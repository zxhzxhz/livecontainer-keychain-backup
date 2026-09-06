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

static NSString * const kOrigClassKey = @"_orig_class";
static NSString * const kDataMarker = @"__data_base64";
static NSString * const kDateMarker = @"__date_iso";

static id LCEncodeValue(id v) {
    if ([v isKindOfClass:[NSData class]]) {
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
    return v;
}

static id LCDecodeValue(id v) {
    if ([v isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)v;
        if (d[kDataMarker] && d.count == 1) {
            return [[NSData alloc] initWithBase64EncodedString:d[kDataMarker] options:0] ?: [NSData data];
        }
        if (d[kDateMarker] && d.count == 1) {
            static NSISO8601DateFormatter *f = nil;
            static dispatch_once_t once;
            dispatch_once(&once, ^{ f = [[NSISO8601DateFormatter alloc] init]; });
            return [f dateFromString:d[kDateMarker]] ?: [NSDate date];
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
                    entry[k] = LCEncodeValue(dict[k]);
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
    NSInteger ok = 0;
    OSStatus lastErr = errSecSuccess;

    // SecItemAdd 不接受的只读 / 系统维护字段
    NSArray *stripKeys = @[
        (__bridge id)kSecAttrCreationDate,
        (__bridge id)kSecAttrModificationDate,
    ];

    for (NSDictionary *raw in items) {
        if (![raw isKindOfClass:[NSDictionary class]]) continue;
        NSString *secClass = raw[kOrigClassKey];
        if (![secClass isKindOfClass:[NSString class]]) continue;

        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        for (id k in raw) {
            if ([k isEqual:kOrigClassKey]) continue;
            if (![k isKindOfClass:[NSString class]]) continue;
            query[k] = LCDecodeValue(raw[k]);
        }
        for (NSString *sk in stripKeys) [query removeObjectForKey:sk];
        query[(__bridge id)kSecClass] = secClass;

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
    if (ok == 0 && (NSInteger)items.count > 0 && outError) {
        *outError = [NSError errorWithDomain:@"LCKeychainBackup"
                                        code:lastErr
                                    userInfo:@{NSLocalizedDescriptionKey:
                                        [NSString stringWithFormat:@"全部写入失败，最后错误: %d", (int)lastErr]}];
    }
    return ok;
}

@end
