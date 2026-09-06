#import "KeychainManager.h"
#import <dlfcn.h>

// ---------- 绕过 LiveContainer Hook：直取原始 SecItem* ----------
// LiveContainer 用 fishhook/Substrate 类手段替换了 Guest App 进程内的
// SecItem* 符号（重定向 access-group / prefix 做软隔离）。
// dlsym 从原始 Security image 取地址，绕过 PLT 级别的 hook，读到宿主全量数据。

typedef OSStatus (*SecCopyMatchingFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*SecAddFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*SecDeleteFn)(CFDictionaryRef);
typedef OSStatus (*SecUpdateFn)(CFDictionaryRef, CFDictionaryRef);

static void *LCOriginalSecurityHandle(void) {
    static void *h = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        h = dlopen("/System/Library/Frameworks/Security.framework/Security",
                   RTLD_GLOBAL | RTLD_NOLOAD);
        if (!h) {
            h = dlopen("/System/Library/Frameworks/Security.framework/Security",
                       RTLD_NOW);
        }
    });
    return h;
}

static SecCopyMatchingFn LCOrigCopyMatching(void) {
    void *h = LCOriginalSecurityHandle();
    return h ? (SecCopyMatchingFn)dlsym(h, "SecItemCopyMatching") : NULL;
}
static SecAddFn LCOrigAdd(void) {
    void *h = LCOriginalSecurityHandle();
    return h ? (SecAddFn)dlsym(h, "SecItemAdd") : NULL;
}
static SecDeleteFn LCOrigDelete(void) {
    void *h = LCOriginalSecurityHandle();
    return h ? (SecDeleteFn)dlsym(h, "SecItemDelete") : NULL;
}

// ---------- JSON-safe 编解码 ----------
//
// Keychain 返回字典里除了 NSString/NSNumber/NSData/NSDate，还可能有：
//   v_Ref = SecCertificateRef / SecKeyRef / SecIdentityRef（__NSCFType）
//   accc  = SecAccessControlRef（__NSCFType）
// 这些都不能进 NSJSONSerialization（会抛 Invalid type in JSON write 并闪退）。
// 策略：能转字节的转 base64；不能序列化的记 dropped 标记，导入时剔除。

static NSString * const kOrigClassKey = @"_orig_class";
static NSString * const kDataMarker = @"__data_base64";
static NSString * const kDateMarker = @"__date_iso";
static NSString * const kCertMarker = @"__cert_der_base64";
static NSString * const kKeyMarker  = @"__key_bytes_base64";
static NSString * const kDropMarker = @"__dropped"; // @{reason, class}

// 导入时剔除标记值的哨兵（指针比较，不会和真实数据冲突）
static NSObject *LCIgnoredValue(void) {
    static NSObject *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[NSObject alloc] init]; });
    return s;
}

static NSString *LCSafeDesc(id v) {
    @try {
        NSString *d = [v description] ?: @"?";
        return d.length > 300 ? [d substringToIndex:300] : d;
    } @catch (NSException *e) {
        return NSStringFromClass([v class]) ?: @"?";
    }
}

static NSDictionary *LCDropped(id v, NSString *reason) {
    return @{kDropMarker: @{
        @"reason": reason ?: @"?",
        @"class": NSStringFromClass([v class]) ?: @"?",
        @"desc": LCSafeDesc(v),
    }};
}

static id LCEncodeValue(id v) {
    if ([v isKindOfClass:[NSString class]] ||
        [v isKindOfClass:[NSNumber class]] ||
        [v isKindOfClass:[NSNull class]]) {
        return v;
    } else if ([v isKindOfClass:[NSData class]]) {
        return @{kDataMarker: [(NSData *)v base64EncodedStringWithOptions:0]};
    } else if ([v isKindOfClass:[NSDate class]]) {
        static NSISO8601DateFormatter *f = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ f = [[NSISO8601DateFormatter alloc] init]; });
        return @{kDateMarker: [f stringFromDate:(NSDate *)v]};
    } else if ([v isKindOfClass:[NSArray class]]) {
        NSMutableArray *a = [NSMutableArray arrayWithCapacity:[(NSArray *)v count]];
        for (id e in (NSArray *)v) [a addObject:LCEncodeValue(e)];
        return a;
    } else if ([v isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *d = [NSMutableDictionary dictionary];
        for (id k in (NSDictionary *)v) {
            if (![k isKindOfClass:[NSString class]]) continue;
            d[k] = LCEncodeValue(((NSDictionary *)v)[k]);
        }
        return d;
    }

    // ---- 到这里只剩 CF Sec 家族对象（v_Ref / accc 等）----
    // CFGetTypeID 只能对真正的 CF 对象调用，先用类名做一次放行检查，
    // 避免对普通 NSObject 越界读取导致闪退；未放行的直接记 dropped。
    NSString *cn = NSStringFromClass([v class]) ?: @"";
    BOOL looksCF = [cn hasPrefix:@"__NSCF"] || [cn hasPrefix:@"__Sec"] ||
                   [cn hasPrefix:@"Sec"];
    if (looksCF && [v isKindOfClass:[NSObject class]]) {
        CFTypeRef ref = (__bridge CFTypeRef)v;
        CFTypeID tid = CFGetTypeID(ref);
        if (tid == SecCertificateGetTypeID()) {
            NSData *der = CFBridgingRelease(
                SecCertificateCopyData((SecCertificateRef)ref));
            if (der) return @{kCertMarker: [der base64EncodedStringWithOptions:0]};
            return LCDropped(v, @"certificate has no DER data");
        }
        if (tid == SecAccessControlGetTypeID()) {
            // ACL 含应用身份白名单，不可序列化；导入时用系统默认保护级别
            return LCDropped(v, @"SecAccessControl cannot be serialized");
        }
        if (tid == SecKeyGetTypeID()) {
            CFErrorRef err = NULL;
            NSData *bytes = CFBridgingRelease(
                SecKeyCopyExternalRepresentation((SecKeyRef)ref, &err));
            if (bytes) return @{kKeyMarker: [bytes base64EncodedStringWithOptions:0]};
            return LCDropped(v, @"non-extractable key (attributes only)");
        }
        if (tid == SecIdentityGetTypeID()) {
            SecCertificateRef cert = NULL;
            NSMutableDictionary *m = [NSMutableDictionary dictionary];
            if (SecIdentityCopyCertificate((SecIdentityRef)ref, &cert) == errSecSuccess && cert) {
                NSData *der = CFBridgingRelease(SecCertificateCopyData(cert));
                if (der) m[@"cert_der_base64"] = [der base64EncodedStringWithOptions:0];
                CFRelease(cert);
            }
            SecKeyRef key = NULL;
            if (SecIdentityCopyPrivateKey((SecIdentityRef)ref, &key) == errSecSuccess && key) {
                CFErrorRef err = NULL;
                NSData *bytes = CFBridgingRelease(SecKeyCopyExternalRepresentation(key, &err));
                if (bytes) m[@"key_bytes_base64"] = [bytes base64EncodedStringWithOptions:0];
                else m[@"key_nonextractable"] = @YES;
                CFRelease(key);
            }
            // identity 是 cert+key 派生视图，导入时自动重建，这里只留档
            return LCDropped(v, @"identity is derived from cert+key; informational only");
        }
    }
    return LCDropped(v, @"unsupported type for JSON");
}

static id LCDecodeValue(id v) {
    if ([v isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)v;
        if (d[kDataMarker] && d.count == 1) {
            return [[NSData alloc] initWithBase64EncodedString:d[kDataMarker] options:0] ?: LCIgnoredValue();
        }
        if (d[kDateMarker] && d.count == 1) {
            static NSISO8601DateFormatter *f = nil;
            static dispatch_once_t once;
            dispatch_once(&once, ^{ f = [[NSISO8601DateFormatter alloc] init]; });
            return [f dateFromString:d[kDateMarker]] ?: [NSDate date];
        }
        if (d[kCertMarker] && d.count == 1) {
            return [[NSData alloc] initWithBase64EncodedString:d[kCertMarker] options:0] ?: LCIgnoredValue();
        }
        if (d[kKeyMarker] && d.count == 1) {
            return [[NSData alloc] initWithBase64EncodedString:d[kKeyMarker] options:0] ?: LCIgnoredValue();
        }
        if (d[kDropMarker]) {
            return LCIgnoredValue(); // 导入时剔除
        }
        NSMutableDictionary *out = [NSMutableDictionary dictionary];
        for (id k in d) {
            if (![k isKindOfClass:[NSString class]]) continue;
            out[k] = LCDecodeValue(d[k]);
        }
        return out;
    } else if ([v isKindOfClass:[NSArray class]]) {
        NSMutableArray *a = [NSMutableArray array];
        for (id e in (NSArray *)v) [a addObject:LCDecodeValue(e)];
        return a;
    }
    return v;
}

// ---------- 单条定位删除 / 写入（浏览编辑与批量恢复共用） ----------

static NSMutableDictionary *LCDelQueryForEncodedEntry(NSDictionary *encodedEntry) {
    NSMutableDictionary *del = [NSMutableDictionary dictionary];
    NSString *secClass = encodedEntry[kOrigClassKey];
    if (![secClass isKindOfClass:[NSString class]]) return del;
    del[(__bridge id)kSecClass] = secClass;
    for (NSString *k in @[
        (__bridge id)kSecAttrAccount,
        (__bridge id)kSecAttrService,
        (__bridge id)kSecAttrServer,
        (__bridge id)kSecAttrAccessGroup,
        (__bridge id)kSecAttrLabel,
        (__bridge id)kSecAttrApplicationTag,
    ]) {
        id raw = encodedEntry[k];
        if (!raw) continue;
        id val = LCDecodeValue(raw);
        if (val == LCIgnoredValue()) continue;
        if ([val isKindOfClass:[NSString class]] ||
            [val isKindOfClass:[NSData class]] ||
            [val isKindOfClass:[NSNumber class]] ||
            [val isKindOfClass:[NSDate class]]) {
            del[k] = val;
        }
    }
    return del;
}

static OSStatus LCAddEncodedEntry(NSDictionary *encodedEntry) {
    NSString *secClass = encodedEntry[kOrigClassKey];
    if (![secClass isKindOfClass:[NSString class]]) return errSecParam;
    if ([secClass isEqual:(__bridge id)kSecClassIdentity]) return errSecParam; // 派生视图不可 Add
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    for (id k in encodedEntry) {
        if ([k isEqual:kOrigClassKey]) continue;
        if (![k isKindOfClass:[NSString class]]) continue;
        id val = LCDecodeValue(encodedEntry[k]);
        if (val == LCIgnoredValue()) continue;
        query[k] = val;
    }
    for (NSString *sk in @[
        (__bridge id)kSecAttrCreationDate,
        (__bridge id)kSecAttrModificationDate,
        (__bridge id)kSecValueRef,
        (__bridge id)kSecValuePersistentRef,
    ]) {
        [query removeObjectForKey:sk];
    }
    if (query[@"v_Data_Base64"]) { // 兼容极早期残留键
        query[(__bridge id)kSecValueData] =
            [[NSData alloc] initWithBase64EncodedString:query[@"v_Data_Base64"] options:0];
        [query removeObjectForKey:@"v_Data_Base64"];
    }
    query[(__bridge id)kSecClass] = secClass;
    if (!query[(__bridge id)kSecValueData] &&
        [secClass isEqual:(__bridge id)kSecClassKey]) {
        return errSecParam; // 无载荷 key（不可导出）无法重建
    }
    SecAddFn origAdd = LCOrigAdd();
    return origAdd ? origAdd((__bridge CFDictionaryRef)query, NULL)
                   : SecItemAdd((__bridge CFDictionaryRef)query, NULL);
}

static BOOL LCDeleteEncodedEntry(NSDictionary *encodedEntry) {
    NSMutableDictionary *del = LCDelQueryForEncodedEntry(encodedEntry);
    if (!del[(__bridge id)kSecClass]) return NO;
    SecDeleteFn origDelete = LCOrigDelete();
    OSStatus st = origDelete ? origDelete((__bridge CFDictionaryRef)del)
                             : SecItemDelete((__bridge CFDictionaryRef)del);
    return st == errSecSuccess || st == errSecItemNotFound;
}

@implementation KeychainManager

+ (NSArray<NSString *> *)classIDs {
    return @[
        (__bridge id)kSecClassGenericPassword,    // genp
        (__bridge id)kSecClassInternetPassword,   // inet
        (__bridge id)kSecClassCertificate,        // cert
        (__bridge id)kSecClassKey,                // keys
        (__bridge id)kSecClassIdentity,           // idnt
    ];
}

+ (NSString *)displayNameForClass:(NSString *)secClass {
    static NSDictionary *m = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        m = @{
            (__bridge id)kSecClassGenericPassword: @"GenericPassword",
            (__bridge id)kSecClassInternetPassword: @"InternetPassword",
            (__bridge id)kSecClassCertificate: @"Certificate",
            (__bridge id)kSecClassKey: @"Key",
            (__bridge id)kSecClassIdentity: @"Identity",
        };
    });
    return m[secClass] ?: secClass;
}

+ (NSArray<NSDictionary *> *)dumpAllItems:(NSError **)outError {
    NSMutableArray<NSDictionary *> *all = [NSMutableArray array];
    SecCopyMatchingFn origCopy = LCOrigCopyMatching();

    for (NSString *secClass in [self classIDs]) {
        NSDictionary *query = @{
            (__bridge id)kSecClass: secClass,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecReturnData: @YES,
        };
        CFTypeRef result = NULL;
        OSStatus st;
        if (origCopy) {
            st = origCopy((__bridge CFDictionaryRef)query, &result);
        } else {
            st = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        }
        if (st == errSecSuccess && result) {
            id obj = (__bridge_transfer id)result;
            NSArray *items = [obj isKindOfClass:[NSArray class]] ? obj : @[obj];
            for (NSDictionary *dict in items) {
                if (![dict isKindOfClass:[NSDictionary class]]) continue;
                NSMutableDictionary *entry = [NSMutableDictionary dictionary];
                for (id k in dict) {
                    if (![k isKindOfClass:[NSString class]]) continue;
                    @try {
                        entry[k] = LCEncodeValue(dict[k]);
                    } @catch (NSException *e) {
                        // 单个字段绝不能拖垮整批导出
                        entry[k] = LCDropped(dict[k],
                            [@"encode exception: " stringByAppendingString:e.reason ?: e.name]);
                    }
                }
                entry[kOrigClassKey] = secClass;
                [all addObject:entry];
            }
        } else if (st != errSecItemNotFound && outError && *outError == nil) {
            // 记录首个非空错误，但继续扫其他 class
            *outError = [NSError errorWithDomain:@"LCKeychainBackup"
                                            code:st
                                        userInfo:@{NSLocalizedDescriptionKey:
                                            [NSString stringWithFormat:@"%@ 查询失败: %d",
                                                [self displayNameForClass:secClass], (int)st]}];
        }
    }
    return all;
}

+ (NSInteger)restoreItems:(NSArray<NSDictionary *> *)items
                    error:(NSError **)outError {
    SecAddFn origAdd = LCOrigAdd();
    SecDeleteFn origDelete = LCOrigDelete();
    NSInteger ok = 0, skippedIdentity = 0, skippedNoData = 0;
    OSStatus lastErr = errSecSuccess;

    // SecItemAdd 不接受的只读 / 系统维护 / 不可序列化字段
    NSString *kRefKey = (__bridge id)kSecValueRef;                 // v_Ref
    NSString *kPersistRefKey = (__bridge id)kSecValuePersistentRef; // v_PersistentRef
    NSArray *stripKeys = @[
        (__bridge id)kSecAttrCreationDate,
        (__bridge id)kSecAttrModificationDate,
        kRefKey,
        kPersistRefKey,
    ];

    for (NSDictionary *raw in items) {
        if (![raw isKindOfClass:[NSDictionary class]]) continue;
        NSString *secClass = raw[kOrigClassKey];
        if (![secClass isKindOfClass:[NSString class]]) continue;

        // identity 是 cert+key 的派生视图，不可直接 Add；
        // cert/key 恢复后它会自动重建，这里跳过
        if ([secClass isEqual:(__bridge id)kSecClassIdentity]) {
            skippedIdentity++;
            continue;
        }

        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        for (id k in raw) {
            if ([k isEqual:kOrigClassKey]) continue;
            if (![k isKindOfClass:[NSString class]]) continue;
            id val = LCDecodeValue(raw[k]);
            if (val != LCIgnoredValue()) query[k] = val;
        }
        for (NSString *sk in stripKeys) [query removeObjectForKey:sk];
        // 兼容极早期版本残留键（若存在）
        if (query[@"v_Data_Base64"]) {
            query[(__bridge id)kSecValueData] =
                [[NSData alloc] initWithBase64EncodedString:query[@"v_Data_Base64"] options:0];
            [query removeObjectForKey:@"v_Data_Base64"];
        }
        query[(__bridge id)kSecClass] = secClass;

        // 无有效载荷（如不可导出的 key 只剩属性）则跳过，避免 errSecParam 刷屏
        if (!query[(__bridge id)kSecValueData]) {
            if ([secClass isEqual:(__bridge id)kSecClassKey]) {
                skippedNoData++;
                continue;
            }
        }

        // 幂等：按“唯一定位键”先删后加
        NSMutableDictionary *delQuery = [NSMutableDictionary dictionaryWithDictionary:@{
            (__bridge id)kSecClass: secClass,
        }];
        for (NSString *k in @[
            (__bridge id)kSecAttrAccount,
            (__bridge id)kSecAttrService,
            (__bridge id)kSecAttrServer,
            (__bridge id)kSecAttrAccessGroup,
            (__bridge id)kSecAttrLabel,
            (__bridge id)kSecAttrApplicationTag,
        ]) {
            if (query[k]) delQuery[k] = query[k];
        }
        if (origDelete) origDelete((__bridge CFDictionaryRef)delQuery);
        else SecItemDelete((__bridge CFDictionaryRef)delQuery);

        OSStatus st;
        if (origAdd) st = origAdd((__bridge CFDictionaryRef)query, NULL);
        else st = SecItemAdd((__bridge CFDictionaryRef)query, NULL);

        if (st == errSecSuccess) {
            ok++;
        } else {
            lastErr = st;
            NSLog(@"[LCKeychainBackup] 写入失败 class=%@ status=%d",
                  [self displayNameForClass:secClass], (int)st);
        }
    }
    if ((skippedIdentity > 0 || skippedNoData > 0)) {
        NSLog(@"[LCKeychainBackup] 跳过 identity %ld 条（派生视图，随 cert/key 重建）, "
              @"无导出数据的 key %ld 条",
              (long)skippedIdentity, (long)skippedNoData);
    }
    if (ok == 0 && (NSInteger)items.count > 0 && outError) {
        *outError = [NSError errorWithDomain:@"LCKeychainBackup"
                                        code:lastErr
                                    userInfo:@{NSLocalizedDescriptionKey:
                                        [NSString stringWithFormat:@"全部写入失败，最后错误: %d", (int)lastErr]}];
    }
    return ok;
}

#pragma mark - 备份容器（plist 为主，兼容旧 JSON）

+ (nullable NSData *)backupPlistWithItems:(NSArray<NSDictionary *> *)items
                                    error:(NSError **)outError {
    NSDictionary *root = @{
        @"format": @"LCKeychainBackup",
        @"version": @2,
        @"exported_at": [NSDate date],
        @"item_count": @(items.count),
        @"items": items ?: @[],
    };
    return [NSPropertyListSerialization dataWithPropertyList:root
                                                      format:NSPropertyListXMLFormat_v1_0
                                                     options:0
                                                       error:outError];
}

+ (nullable NSArray<NSDictionary *> *)itemsFromBackupData:(NSData *)data
                                                    error:(NSError **)outError {
    // 1) 先试 plist（新格式）
    NSError *perr = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data
                                                         options:NSPropertyListImmutable
                                                          format:NULL
                                                           error:&perr];
    if (plist) {
        if ([plist isKindOfClass:[NSDictionary class]]) {
            id items = ((NSDictionary *)plist)[@"items"];
            if ([items isKindOfClass:[NSArray class]]) return items;
        } else if ([plist isKindOfClass:[NSArray class]]) {
            return plist;
        }
    }
    // 2) 再试 JSON（旧格式）
    NSError *jerr = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jerr];
    if ([obj isKindOfClass:[NSArray class]]) return obj;
    if ([obj isKindOfClass:[NSDictionary class]]) {
        id items = ((NSDictionary *)obj)[@"items"];
        if ([items isKindOfClass:[NSArray class]]) return items;
    }
    if (outError) *outError = jerr ?: perr;
    return nil;
}

#pragma mark - 浏览 / 编辑

+ (NSDictionary *)displayDictionaryForEntry:(NSDictionary *)entry {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    for (id k in entry) {
        if (![k isKindOfClass:[NSString class]]) continue;
        if ([k isEqualToString:kOrigClassKey]) {
            if (entry[k]) d[k] = entry[k];
            continue;
        }
        id val = LCDecodeValue(entry[k]);
        if (val == LCIgnoredValue()) {
            NSString *info = @"<unavailable>";
            id raw = entry[k];
            if ([raw isKindOfClass:[NSDictionary class]] && raw[kDropMarker]) {
                NSDictionary *m = raw[kDropMarker];
                info = [NSString stringWithFormat:@"<%@: %@>",
                        m[@"reason"] ?: @"dropped", m[@"class"] ?: @"?"];
            }
            d[k] = info;
        } else {
            d[k] = val;
        }
    }
    return d;
}

+ (BOOL)isKeyEditable:(NSString *)key inEntry:(NSDictionary *)entry {
    static NSSet *readOnly = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        readOnly = [NSSet setWithObjects:
            kOrigClassKey, @"class", @"cdat", @"mdat", @"crtr",
            @"v_Ref", @"v_PersistentRef", @"accc", nil];
    });
    if ([readOnly containsObject:key]) return NO;
    id raw = entry[key];
    if ([raw isKindOfClass:[NSDictionary class]] && raw[kDropMarker]) return NO;
    id disp = [self displayDictionaryForEntry:entry][key];
    return [disp isKindOfClass:[NSString class]] ||
           [disp isKindOfClass:[NSData class]] ||
           [disp isKindOfClass:[NSNumber class]];
}

+ (NSString *)friendlyNameForKey:(NSString *)key {
    static NSDictionary *m = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        m = @{
            @"acct": @"Account", @"svce": @"Service", @"srvr": @"Server",
            @"port": @"Port", @"ptcl": @"Protocol", @"labl": @"Label",
            @"desc": @"Description", @"alis": @"Alias", @"subj": @"Subject",
            @"agrp": @"AccessGroup", @"pdmn": @"Accessible",
            @"v_Data": @"Data", @"v_Ref": @"Reference",
            @"v_PersistentRef": @"PersistentRef", @"accc": @"AccessControl",
            @"cdat": @"Created", @"mdat": @"Modified", @"crtr": @"Creator",
            @"type": @"Type", @"atag": @"ApplicationTag",
            @"class": @"Class", @"path": @"Path",
        };
    });
    NSString *name = m[key];
    return name ? [NSString stringWithFormat:@"%@ (%@)", name, key] : key;
}

+ (NSString *)displayStringForValue:(id)value {
    if ([value isKindOfClass:[NSString class]]) return value;
    if ([value isKindOfClass:[NSData class]]) {
        return [self previewForData:(NSData *)value];
    }
    if ([value isKindOfClass:[NSDate class]]) {
        return [NSDateFormatter localizedStringFromDate:value
                                             dateStyle:NSDateFormatterMediumStyle
                                             timeStyle:NSDateFormatterMediumStyle];
    }
    if ([value isKindOfClass:[NSNumber class]]) return [(NSNumber *)value stringValue];
    if (value == (id)LCIgnoredValue()) return @"<unavailable>";
    return [value description] ?: @"?";
}

+ (NSString *)summaryForEntry:(NSDictionary *)entry {
    NSDictionary *d = [self displayDictionaryForEntry:entry];
    for (NSString *k in @[@"acct", @"labl", @"svce", @"srvr", @"alis"]) {
        id v = d[k];
        if ([v isKindOfClass:[NSString class]] && [(NSString *)v length]) return v;
        if ([v isKindOfClass:[NSData class]]) {
            NSString *s = [[NSString alloc] initWithData:v encoding:NSUTF8StringEncoding];
            if (s.length) return s;
        }
    }
    return [NSString stringWithFormat:@"<%@>",
            [self displayNameForClass:entry[kOrigClassKey] ?: @"?"]];
}

+ (NSString *)subtitleForEntry:(NSDictionary *)entry {
    NSMutableArray *parts = [NSMutableArray array];
    [parts addObject:[self displayNameForClass:entry[kOrigClassKey] ?: @"?"]];
    NSDictionary *d = [self displayDictionaryForEntry:entry];
    NSString *summary = [self summaryForEntry:entry];
    for (NSString *k in @[@"svce", @"srvr", @"agrp"]) {
        id v = d[k];
        if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] &&
            ![(NSString *)v isEqualToString:summary]) {
            [parts addObject:v];
            break;
        }
    }
    id data = d[(__bridge id)kSecValueData];
    if ([data isKindOfClass:[NSData class]]) {
        [parts addObject:[NSString stringWithFormat:@"%luB", (unsigned long)[(NSData *)data length]]];
    }
    return [parts componentsJoinedByString:@" · "];
}

+ (nullable NSDictionary *)saveEntry:(NSDictionary *)orig
               changedDisplayValues:(NSDictionary<NSString *, id> *)changed
                              error:(NSError **)outError {
    NSMutableDictionary *newEntry = [orig mutableCopy];
    for (NSString *k in changed) {
        if ([k isEqualToString:kOrigClassKey]) continue;
        newEntry[k] = LCEncodeValue(changed[k]);
    }
    LCDeleteEncodedEntry(orig); // 定位键可能被改：按原条目删
    OSStatus st = LCAddEncodedEntry(newEntry);
    if (st == errSecSuccess) return newEntry;
    // 回滚：尝试把原条目写回去，避免改坏丢数据
    LCAddEncodedEntry(orig);
    if (outError) {
        *outError = [NSError errorWithDomain:@"LCKeychainBackup" code:st
            userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"写入失败 (%d)，已尝试恢复原条目", (int)st]}];
    }
    return nil;
}

+ (BOOL)deleteEntry:(NSDictionary *)entry error:(NSError **)outError {
    if (LCDeleteEncodedEntry(entry)) return YES;
    if (outError) {
        *outError = [NSError errorWithDomain:@"LCKeychainBackup" code:-1
            userInfo:@{NSLocalizedDescriptionKey: @"删除失败"}];
    }
    return NO;
}

#pragma mark - 数据内容识别

static NSString *LCShorten(NSString *s, NSUInteger maxLen) {
    if (!s) return @"";
    if (s.length <= maxLen) return s;
    return [[s substringToIndex:maxLen] stringByAppendingString:@"…"];
}

+ (nullable id)plistObjectFromData:(NSData *)data error:(NSError **)outError {
    if (!data) return nil;
    return [NSPropertyListSerialization propertyListWithData:data
                                                     options:NSPropertyListImmutable
                                                      format:NULL
                                                       error:outError];
}

+ (LCDataFormat)dataFormat:(NSData *)data {
    if (!data || data.length == 0) return LCDataFormatText;
    // bplist 魔数
    if (data.length >= 6 && memcmp(data.bytes, "bplist", 6) == 0) {
        id obj = [self plistObjectFromData:data error:NULL];
        if ([obj isKindOfClass:[NSDictionary class]]) {
            id arch = ((NSDictionary *)obj)[@"$archiver"];
            if ([arch isKindOfClass:[NSString class]] &&
                [(NSString *)arch containsString:@"NSKeyedArchiver"]) {
                return LCDataFormatKeyedArchive;
            }
            return LCDataFormatPlistBinary;
        }
        return LCDataFormatBinary;
    }
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!s) return LCDataFormatBinary;
    NSCharacterSet *ws = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    NSUInteger i = 0;
    while (i < s.length && [ws characterIsMember:[s characterAtIndex:i]]) i++;
    NSString *rest = i < s.length ? [s substringFromIndex:i] : @"";
    if ([rest hasPrefix:@"<plist"] || [rest hasPrefix:@"<?xml"]) {
        if ([self plistObjectFromData:data error:NULL]) return LCDataFormatPlistXML;
        return LCDataFormatText;
    }
    if ([rest hasPrefix:@"{"] || [rest hasPrefix:@"["]) {
        if ([NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]) {
            return LCDataFormatJSON;
        }
    }
    return LCDataFormatText;
}

+ (NSString *)formatName:(LCDataFormat)fmt {
    switch (fmt) {
        case LCDataFormatJSON: return @"JSON";
        case LCDataFormatPlistBinary: return @"Plist·二进制";
        case LCDataFormatPlistXML: return @"Plist·XML";
        case LCDataFormatKeyedArchive: return @"KeyedArchive";
        case LCDataFormatBinary: return @"二进制";
        case LCDataFormatText: default: return @"文本";
    }
}

+ (NSString *)previewForData:(NSData *)data {
    if (!data || data.length == 0) return @"[空]";
    LCDataFormat fmt = [self dataFormat:data];
    NSString *tag = [self formatName:fmt];
    NSString *body = @"";
    switch (fmt) {
        case LCDataFormatText: {
            NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            body = LCShorten(s ?: @"", 120);
            break;
        }
        case LCDataFormatJSON: {
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
            NSData *compact = obj ? [NSJSONSerialization dataWithJSONObject:obj options:0 error:NULL] : nil;
            NSString *s = compact ? [[NSString alloc] initWithData:compact encoding:NSUTF8StringEncoding] : nil;
            body = LCShorten(s ?: @"", 120);
            break;
        }
        case LCDataFormatPlistBinary:
        case LCDataFormatPlistXML: {
            id obj = [self plistObjectFromData:data error:NULL];
            if ([obj isKindOfClass:[NSDictionary class]]) {
                body = [NSString stringWithFormat:@"{%@}",
                        LCShorten([[(NSDictionary *)obj allKeys] componentsJoinedByString:@", "], 120)];
            } else if ([obj isKindOfClass:[NSArray class]]) {
                body = [NSString stringWithFormat:@"[%lu 项]", (unsigned long)[(NSArray *)obj count]];
            } else {
                body = LCShorten([obj description] ?: @"", 120);
            }
            break;
        }
        case LCDataFormatKeyedArchive: {
            id top = [self plistObjectFromData:data error:NULL];
            NSArray *objects = [top isKindOfClass:[NSDictionary class]] ? top[@"$objects"] : nil;
            body = [NSString stringWithFormat:@"%@ · %lu objects",
                    top[@"$archiver"] ?: @"?",
                    (unsigned long)[objects isKindOfClass:[NSArray class]] ? [(NSArray *)objects count] : 0];
            break;
        }
        case LCDataFormatBinary:
        default:
            body = [NSString stringWithFormat:@"%lu 字节", (unsigned long)data.length];
            break;
    }
    return [NSString stringWithFormat:@"[%@] %@", tag, body];
}

+ (NSString *)editableTextForData:(NSData *)data format:(LCDataFormat)fmt {
    switch (fmt) {
        case LCDataFormatJSON: {
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
            NSData *pretty = obj ? [NSJSONSerialization dataWithJSONObject:obj
                options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL] : nil;
            NSString *s = pretty ? [[NSString alloc] initWithData:pretty encoding:NSUTF8StringEncoding] : nil;
            return s ?: [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
        }
        case LCDataFormatPlistBinary:
        case LCDataFormatPlistXML: {
            id obj = [self plistObjectFromData:data error:NULL];
            NSData *xml = obj ? [NSPropertyListSerialization dataWithPropertyList:obj
                format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL] : nil;
            NSString *s = xml ? [[NSString alloc] initWithData:xml encoding:NSUTF8StringEncoding] : nil;
            return s ?: @"";
        }
        case LCDataFormatBinary:
            return [data base64EncodedStringWithOptions:0];
        case LCDataFormatKeyedArchive:
            return [self decodedDumpForArchiveData:data];
        case LCDataFormatText:
        default:
            return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
    }
}

+ (nullable NSData *)dataFromEditedText:(NSString *)text
                                    format:(LCDataFormat)fmt
                                     error:(NSError **)outError {
    switch (fmt) {
        case LCDataFormatText:
            return [text dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
        case LCDataFormatJSON: {
            NSData *d = [text dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
            if ([NSJSONSerialization JSONObjectWithData:d options:0 error:outError]) return d;
            return nil;
        }
        case LCDataFormatPlistBinary:
        case LCDataFormatPlistXML: {
            NSData *d = [text dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
            NSError *e = nil;
            id obj = [NSPropertyListSerialization propertyListWithData:d
                options:NSPropertyListImmutable format:NULL error:&e];
            if (!obj) {
                if (outError) *outError = e;
                return nil;
            }
            // 保持原序列化格式：二进制的存回二进制，XML 的存回 XML
            return [NSPropertyListSerialization dataWithPropertyList:obj
                format:(fmt == LCDataFormatPlistBinary ? NSPropertyListBinaryFormat_v1_0
                                                       : NSPropertyListXMLFormat_v1_0)
                options:0 error:outError];
        }
        case LCDataFormatBinary: {
            NSData *d = [[NSData alloc] initWithBase64EncodedString:text
                options:NSDataBase64DecodingIgnoreUnknownCharacters];
            if (!d && outError) {
                *outError = [NSError errorWithDomain:@"LCKeychainBackup" code:-1
                    userInfo:@{NSLocalizedDescriptionKey: @"base64 解析失败"}];
            }
            return d;
        }
        case LCDataFormatKeyedArchive: {
            if (outError) {
                *outError = [NSError errorWithDomain:@"LCKeychainBackup" code:-1
                    userInfo:@{NSLocalizedDescriptionKey: @"KeyedArchive 仅支持查看，不可编辑"}];
            }
            return nil;
        }
    }
}

+ (NSString *)decodedDumpForArchiveData:(NSData *)data {
    NSMutableString *out = [NSMutableString string];
    id top = [self plistObjectFromData:data error:NULL];
    if (![top isKindOfClass:[NSDictionary class]]) return @"无法解析（非 plist 容器）";
    NSDictionary *td = (NSDictionary *)top;
    NSArray *objects = [td[@"$objects"] isKindOfClass:[NSArray class]] ? td[@"$objects"] : @[];
    [out appendFormat:@"$archiver: %@\n$objects: %lu\n", td[@"$archiver"] ?: @"?",
            (unsigned long)objects.count];
    [out appendFormat:@"$top: %@\n", td[@"$top"] ?: @"?"];
    // 类名清单
    NSMutableArray *seen = [NSMutableArray array];
    for (id o in objects) {
        if (![o isKindOfClass:[NSDictionary class]]) continue;
        NSString *cn = o[@"$classname"];
        if ([cn isKindOfClass:[NSString class]] && ![seen containsObject:cn]) {
            [seen addObject:cn];
            if (seen.count >= 30) break;
        }
    }
    [out appendFormat:@"类(%lu): %@\n", (unsigned long)seen.count,
            [seen componentsJoinedByString:@", "]];
    // 能解则解（仅常见 Foundation 类）
    @try {
        NSError *ue = nil;
        NSSet *classes = [NSSet setWithObjects:
            [NSDictionary class], [NSArray class], [NSString class],
            [NSNumber class], [NSDate class], [NSData class], [NSSet class], nil];
        id root = [NSKeyedUnarchiver unarchivedObjectOfClasses:classes
                                                       fromData:data error:&ue];
        if (root) {
            [out appendString:@"\n—— 解档成功 ——\n"];
            [out appendString:LCShorten([root description], 3000)];
        } else {
            [out appendString:@"\n（含自定义类，无法完整解档，仅显示结构）"];
        }
    } @catch (NSException *ex) {
        [out appendFormat:@"\n（解档异常 %@，仅显示结构）", ex.name];
    }
    return out;
}

@end
