#import "DetailViewController.h"
#import "DataEditViewController.h"
#import "KeychainManager.h"

@interface DetailViewController () <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) NSDictionary *entry;   // 编码条目（写回用）
@property (nonatomic, strong) NSDictionary *display; // 展示字典
@property (nonatomic, strong) NSArray<NSString *> *keys; // 有序属性 key
@property (nonatomic, strong) UITableView *table;
@end

@implementation DetailViewController

- (instancetype)initWithEntry:(NSDictionary *)entry {
    if (self = [super init]) {
        _entry = [entry copy];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemTrash
                                                     target:self action:@selector(onDelete)];
    [self rebuild];

    self.table = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStyleInsetGrouped];
    self.table.dataSource = self;
    self.table.delegate = self;
    self.table.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.table];
    [NSLayoutConstraint activateConstraints:@[
        [self.table.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.table.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.table.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.table.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
    ]];
}

- (void)rebuild {
    self.display = [KeychainManager displayDictionaryForEntry:self.entry];
    // 排序：重要字段优先，其余按字母序；_orig_class 放最后
    NSArray *priority = @[@"labl", @"acct", @"svce", @"srvr", @"v_Data",
                          @"desc", @"agrp", @"pdmn", @"port", @"ptcl", @"path"];
    NSMutableArray *rest = [NSMutableArray array];
    for (NSString *k in self.display) {
        if ([k isEqualToString:@"_orig_class"]) continue;
        if (![priority containsObject:k]) [rest addObject:k];
    }
    [rest sortUsingSelector:@selector(compare:)];
    NSMutableArray *ordered = [NSMutableArray array];
    for (NSString *k in priority) {
        if (self.display[k]) [ordered addObject:k];
    }
    [ordered addObjectsFromArray:rest];
    if (self.display[@"_orig_class"]) [ordered addObject:@"_orig_class"];
    self.keys = ordered;
    self.title = [KeychainManager summaryForEntry:self.entry];
}

#pragma mark - Table

- (NSInteger)tableView:(UITableView *)t numberOfRowsInSection:(NSInteger)s {
    return self.keys.count;
}

- (UITableViewCell *)tableView:(UITableView *)t cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *rid = @"kvrow";
    UITableViewCell *cell = [t dequeueReusableCellWithIdentifier:rid];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:rid];
        cell.detailTextLabel.numberOfLines = 0;
    }
    NSString *k = self.keys[ip.row];
    BOOL editable = [KeychainManager isKeyEditable:k inEntry:self.entry];
    cell.textLabel.text = [KeychainManager friendlyNameForKey:k];
    cell.textLabel.font = [UIFont systemFontOfSize:13];
    cell.textLabel.textColor = [UIColor secondaryLabelColor];
    cell.detailTextLabel.text = [KeychainManager displayStringForValue:self.display[k]];
    cell.detailTextLabel.font = [UIFont systemFontOfSize:15];
    cell.accessoryType = editable ? UITableViewCellAccessoryDisclosureIndicator
                                  : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)t didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [t deselectRowAtIndexPath:ip animated:YES];
    NSString *k = self.keys[ip.row];
    id val = self.display[k];
    BOOL editable = [KeychainManager isKeyEditable:k inEntry:self.entry];
    UIAlertController *sheet = [UIAlertController
        alertControllerWithTitle:[KeychainManager friendlyNameForKey:k]
                         message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"复制值" style:UIAlertActionStyleDefault
        handler:^(__unused UIAlertAction *a) {
            UIPasteboard.generalPasteboard.string =
                [KeychainManager displayStringForValue:val];
        }]];
    if (editable) {
        [sheet addAction:[UIAlertAction actionWithTitle:@"编辑" style:UIAlertActionStyleDefault
            handler:^(__unused UIAlertAction *a) { [self editKey:k]; }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (sheet.popoverPresentationController) {
        UITableViewCell *cell = [t cellForRowAtIndexPath:ip];
        sheet.popoverPresentationController.sourceView = cell;
        sheet.popoverPresentationController.sourceRect = cell.bounds;
    }
    [self presentViewController:sheet animated:YES completion:nil];
}

#pragma mark - Edit

// 写回单个字段；成功刷新本页，失败返回错误
- (BOOL)commitValue:(id)newVal forKey:(NSString *)key error:(NSError **)outError {
    NSDictionary *updated = [KeychainManager saveEntry:self.entry
                                 changedDisplayValues:@{key: newVal}
                                                error:outError];
    if (!updated) return NO;
    self.entry = updated;
    [self rebuild];
    [self.table reloadData];
    return YES;
}

- (void)editKey:(NSString *)key {
    id origVal = self.display[key];
    NSString *name = [KeychainManager friendlyNameForKey:key];
    __weak typeof(self) weakSelf = self;

    // 1) 二进制：按内容格式进全屏编辑器
    if ([origVal isKindOfClass:[NSData class]]) {
        NSData *d = (NSData *)origVal;
        LCDataFormat fmt = [KeychainManager dataFormat:d];
        BOOL ro = (fmt == LCDataFormatKeyedArchive);
        NSString *hint = nil;
        switch (fmt) {
            case LCDataFormatPlistBinary:
                hint = @"二进制 plist，已转 XML 显示；保存时自动转回二进制，改错会提示";
                break;
            case LCDataFormatPlistXML:
                hint = @"XML plist，直接改；保存时校验格式";
                break;
            case LCDataFormatJSON:
                hint = @"JSON，直接改；保存时校验格式";
                break;
            case LCDataFormatKeyedArchive:
                hint = @"NSKeyedArchiver 归档，仅支持查看结构（解档需原始类），不可编辑";
                break;
            case LCDataFormatBinary:
                hint = @"不透明二进制，按 base64 编辑";
                break;
            case LCDataFormatText:
            default:
                hint = @"文本，直接改";
                break;
        }
        NSString *title = [NSString stringWithFormat:@"%@ · %@", name,
                           [KeychainManager formatName:fmt]];
        DataEditViewController *e = [[DataEditViewController alloc]
            initWithTitle:title
                     hint:hint
                     text:[KeychainManager editableTextForData:d format:fmt]
                 readOnly:ro
                   onSave:^BOOL(NSString *text, NSError **err) {
                       NSData *nd = [KeychainManager dataFromEditedText:text
                                                                format:fmt error:err];
                       if (!nd) return NO;
                       return [weakSelf commitValue:nd forKey:key error:err];
                   }];
        [self.navigationController pushViewController:e animated:YES];
        return;
    }

    // 2) 数字：数字键盘
    if ([origVal isKindOfClass:[NSNumber class]]) {
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:[NSString stringWithFormat:@"编辑 %@", name]
                             message:@"整数 / 小数 / true / false"
                      preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
            tf.text = [(NSNumber *)origVal stringValue];
            tf.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
        }];
        [alert addAction:[UIAlertAction actionWithTitle:@"取消"
                                                  style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"保存"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(__unused UIAlertAction *a) {
            NSString *t = [alert.textFields.firstObject.text
                stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            NSNumber *num = nil;
            NSString *low = t.lowercaseString;
            if ([low isEqualToString:@"true"] || [low isEqualToString:@"yes"]) num = @YES;
            else if ([low isEqualToString:@"false"] || [low isEqualToString:@"no"]) num = @NO;
            else if ([t rangeOfString:@"."].location != NSNotFound) {
                double v = t.doubleValue;
                num = (v == 0 && ![t isEqualToString:@"0"] && ![t hasPrefix:@"0."])
                    ? nil : @(v);
            } else {
                long long v = t.longLongValue;
                num = (v == 0 && ![t isEqualToString:@"0"]) ? nil : @(v);
            }
            if (!num) {
                [weakSelf toast:@"数字格式不对，未保存"];
                return;
            }
            NSError *err = nil;
            if ([weakSelf commitValue:num forKey:key error:&err]) {
                [weakSelf toast:@"已保存"];
            } else {
                [weakSelf toast:err.localizedDescription ?: @"保存失败"];
            }
        }]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    // 3) 字符串：小框直接改
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:[NSString stringWithFormat:@"编辑 %@", name]
                         message:nil
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.text = [KeychainManager displayStringForValue:origVal];
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault
        handler:^(__unused UIAlertAction *a) {
            NSError *err = nil;
            NSString *t = alert.textFields.firstObject.text ?: @"";
            if ([weakSelf commitValue:t forKey:key error:&err]) {
                [weakSelf toast:@"已保存"];
            } else {
                [weakSelf toast:err.localizedDescription ?: @"保存失败"];
            }
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - Delete

- (void)onDelete {
    UIAlertController *c = [UIAlertController
        alertControllerWithTitle:@"删除该条目？"
                         message:[KeychainManager summaryForEntry:self.entry]
                  preferredStyle:UIAlertControllerStyleAlert];
    [c addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [c addAction:[UIAlertAction actionWithTitle:@"删除" style:UIAlertActionStyleDestructive
        handler:^(__unused UIAlertAction *a) {
            NSError *err = nil;
            if ([KeychainManager deleteEntry:self.entry error:&err]) {
                [self.navigationController popViewControllerAnimated:YES];
            } else {
                [self toast:err.localizedDescription ?: @"删除失败"];
            }
        }]];
    [self presentViewController:c animated:YES completion:nil];
}

- (void)toast:(NSString *)msg {
    UIAlertController *c = [UIAlertController alertControllerWithTitle:nil message:msg
        preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:c animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [c dismissViewControllerAnimated:YES completion:nil];
    });
}

@end
