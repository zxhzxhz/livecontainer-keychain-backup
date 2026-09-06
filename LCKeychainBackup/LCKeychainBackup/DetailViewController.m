#import "DetailViewController.h"
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

- (void)editKey:(NSString *)key {
    id origVal = self.display[key];
    NSString *prefill = [KeychainManager displayStringForValue:origVal];
    BOOL isData = [origVal isKindOfClass:[NSData class]];
    BOOL wasBase64 = isData && [prefill hasPrefix:@"base64:"];

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:[NSString stringWithFormat:@"编辑 %@",
                                  [KeychainManager friendlyNameForKey:key]]
                         message:isData ? (wasBase64 ? @"二进制数据：请粘贴 base64（可带 base64: 前缀）"
                                                     : @"文本数据：直接修改")
                                         : nil
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.text = prefill;
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf = self;
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault
        handler:^(__unused UIAlertAction *a) {
            [weakSelf saveKey:key text:alert.textFields.firstObject.text ?: @""];
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)saveKey:(NSString *)key text:(NSString *)text {
    id newVal;
    id origVal = self.display[key];
    if ([origVal isKindOfClass:[NSData class]]) {
        NSString *s = [text hasPrefix:@"base64:"]
            ? [text substringFromIndex:@"base64:".length] : text;
        // 原来是文本则按文本存，否则按 base64 解析
        NSString *origStr = [KeychainManager displayStringForValue:origVal];
        if (![origStr hasPrefix:@"base64:"]) {
            newVal = [text dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
        } else {
            NSData *d = [[NSData alloc] initWithBase64EncodedString:s options:0];
            if (!d) {
                [self toast:@"base64 解析失败，未保存"];
                return;
            }
            newVal = d;
        }
    } else {
        newVal = text;
    }
    NSError *err = nil;
    NSDictionary *updated = [KeychainManager saveEntry:self.entry
                                 changedDisplayValues:@{key: newVal}
                                                error:&err];
    if (!updated) {
        [self toast:err.localizedDescription ?: @"保存失败"];
        return;
    }
    self.entry = updated;
    [self rebuild];
    [self.table reloadData];
    [self toast:@"已保存"];
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
