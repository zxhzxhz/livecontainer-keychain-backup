#import <UIKit/UIKit.h>

/// 单条目属性查看 / 编辑 / 删除。编辑按字段即时写回（delete+add）。
@interface DetailViewController : UIViewController
- (instancetype)initWithEntry:(NSDictionary *)entry;
@end
