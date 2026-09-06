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

@implementation KeychainManager

+ (NSArray<NSDictionary *> *)classIDs {
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

@end
