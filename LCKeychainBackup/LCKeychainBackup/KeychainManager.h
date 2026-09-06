#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

/// 穿透 LiveContainer 用户态 Hook，直调原始 Security.framework 的 Keychain 管理器。
/// 导出为 JSON-safe 数组；导入时做 delete+add 幂等恢复。
@interface KeychainManager : NSObject

/// 读出当前签名主体下全量 Keychain 条目（JSON-safe 字典数组）。
/// 每个字典含 @"_orig_class"（genp/inet/cert/keys/idnt），二进制用 {"__data_base64":...}，
/// 日期用 {"__date_iso":...} 包装，保证 NSJSONSerialization 可用。
+ (NSArray<NSDictionary *> *)dumpAllItems:(NSError **)outError;

/// 把 dumpAllItems 产出的数组写回 Keychain。返回实际写入成功的条数。
+ (NSInteger)restoreItems:(NSArray<NSDictionary *> *)items
                    error:(NSError **)outError;

/// 供 UI 展示的类名映射
+ (NSString *)displayNameForClass:(NSString *)secClass;

@end

NS_ASSUME_NONNULL_END
