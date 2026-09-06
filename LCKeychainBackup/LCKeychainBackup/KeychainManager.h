#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

/// 穿透 LiveContainer 用户态 Hook，直调原始 Security.framework 的 Keychain 管理器。
@interface KeychainManager : NSObject

#pragma mark - 导出 / 导入（备份文件内容层）

/// 读出当前签名主体下全量 Keychain 条目（plist-safe 编码字典数组）。
/// 每个字典含 @"_orig_class"（genp/inet/cert/keys/idnt），二进制用 {"__data_base64":...}，
/// 日期用 {"__date_iso":...} 包装，Sec refs 转 DER 或记 __dropped。
+ (NSArray<NSDictionary *> *)dumpAllItems:(NSError **)outError;

/// 把 dumpAllItems 产出的数组写回 Keychain。返回实际写入成功的条数。
+ (NSInteger)restoreItems:(NSArray<NSDictionary *> *)items
                    error:(NSError **)outError;

/// 供 UI 展示的类名映射
+ (NSString *)displayNameForClass:(NSString *)secClass;

#pragma mark - 备份容器（plist 为主，兼容旧 JSON）

/// 打包为 plist（XML）备份文件数据：{version, exported_at, items}
+ (nullable NSData *)backupPlistWithItems:(NSArray<NSDictionary *> *)items
                                    error:(NSError **)outError;

/// 解析备份数据：plist（新）或 JSON（旧）→ 条目数组
+ (nullable NSArray<NSDictionary *> *)itemsFromBackupData:(NSData *)data
                                                    error:(NSError **)outError;

#pragma mark - 浏览 / 编辑（App 内查看修改）

/// 编码条目 → 可展示字典：NSData/NSDate 还原为真实对象，
/// Sec ref / dropped 转为可读描述字符串。@"_orig_class" 原样保留。
+ (NSDictionary *)displayDictionaryForEntry:(NSDictionary *)entry;

/// 某 key 是否可编辑：NSString/NSData 类型且不在只读表，且原始值不是 dropped 标记
+ (BOOL)isKeyEditable:(NSString *)key inEntry:(NSDictionary *)entry;

/// 属性名的友好显示（"acct" → "Account (acct)"），未知 key 显示原文
+ (NSString *)friendlyNameForKey:(NSString *)key;

/// 值的展示字符串：NSData 能转 UTF-8 则原文，否则 base64；NSDate 转本地时间
+ (NSString *)displayStringForValue:(id)value;

/// 列表标题：account / label / service / server 优先
+ (NSString *)summaryForEntry:(NSDictionary *)entry;
/// 列表副标题：Class · service/server · 数据长度
+ (NSString *)subtitleForEntry:(NSDictionary *)entry;

/// 单条更新：按原条目定位删除 + 写入新条目。changed 里是展示层的值
///（NSString/NSData）。成功返回更新后的编码条目，失败返回 nil。
+ (nullable NSDictionary *)saveEntry:(NSDictionary *)orig
               changedDisplayValues:(NSDictionary<NSString *, id> *)changed
                              error:(NSError **)outError;

/// 单条删除
+ (BOOL)deleteEntry:(NSDictionary *)entry error:(NSError **)outError;

@end

NS_ASSUME_NONNULL_END
