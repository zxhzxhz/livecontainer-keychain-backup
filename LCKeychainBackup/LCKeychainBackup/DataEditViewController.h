#import <UIKit/UIKit.h>

/// 全屏大数据编辑器：文本/JSON/plist 按对应格式文本编辑保存；
/// KeyedArchive 等只读内容显示解码转储 + 复制。
@interface DataEditViewController : UIViewController

/// @param title 导航标题（已含格式名）
/// @param hint 顶部提示条，可 nil
/// @param text 初始文本
/// @param readOnly 只读时隐藏保存键，右上角为复制
/// @param onSave 保存回调：返回 YES 则本页自动 pop；NO сопровожда错误弹窗
- (instancetype)initWithTitle:(NSString *)title
                        hint:(nullable NSString *)hint
                        text:(NSString *)text
                    readOnly:(BOOL)readOnly
                      onSave:(nullable BOOL (^)(NSString *text, NSError **err))onSave;

@end
