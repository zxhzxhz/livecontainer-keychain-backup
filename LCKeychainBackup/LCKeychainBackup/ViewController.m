#import "ViewController.h"
#import "BrowseViewController.h"
#import "KeychainManager.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface ViewController () <UIDocumentPickerDelegate>
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIButton *exportBtn;
@property (nonatomic, strong) UIButton *importBtn;
@property (nonatomic, strong) UIButton *shareBtn;
@property (nonatomic, strong) UIButton *browseBtn;
@property (nonatomic, strong, nullable) NSURL *lastBackupURL;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    [self buildUI];
    [self log:@"LCKeychainBackup 就绪。\n重装须用同一 Apple ID，否则旧数据写不回。"];
}

#pragma mark - UI

- (UIButton *)makeButton:(NSString *)title action:(SEL)sel {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:title forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    b.backgroundColor = [UIColor secondarySystemBackgroundColor];
    b.layer.cornerRadius = 12;
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b.heightAnchor constraintEqualToConstant:52].active = YES;
    return b;
}

- (void)buildUI {
    self.titleLabel = [[UILabel alloc] init];
    self.titleLabel.text = @"LC Keychain 备份";
    self.titleLabel.font = [UIFont boldSystemFontOfSize:24];
    self.titleLabel.textAlignment = NSTextAlignmentCenter;
    self.titleLabel.translatesAutoresizingMaskIntoConstraints = NO;

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.text = @"未备份";
    self.statusLabel.font = [UIFont systemFontOfSize:14];
    self.statusLabel.textColor = [UIColor secondaryLabelColor];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;

    self.exportBtn = [self makeButton:@"1. 导出 Keychain → plist" action:@selector(onExport)];
    self.importBtn = [self makeButton:@"2. 从备份导入恢复" action:@selector(onImport)];
    self.shareBtn  = [self makeButton:@"3. 分享备份文件" action:@selector(onShare)];
    self.browseBtn = [self makeButton:@"4. 浏览 / 编辑 Keychain" action:@selector(onBrowse)];

    self.logView = [[UITextView alloc] init];
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.logView.layer.cornerRadius = 12;
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.titleLabel, self.statusLabel,
        self.exportBtn, self.importBtn, self.shareBtn, self.browseBtn, self.logView,
    ]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:g.topAnchor constant:16],
        [stack.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [stack.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-16],
    ]];
    // 日志区弹性撑满剩余空间
    [self.logView.heightAnchor constraintGreaterThanOrEqualToConstant:180].active = YES;
}

#pragma mark - Log

- (void)log:(NSString *)msg {
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
                      [NSDateFormatter localizedStringFromDate:[NSDate date]
                        dateStyle:NSDateFormatterNoStyle
                        timeStyle:NSDateFormatterMediumStyle], msg];
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:line];
        NSRange end = NSMakeRange(self.logView.text.length, 0);
        [self.logView scrollRangeToVisible:end];
    });
}

#pragma mark - Export

- (void)onExport {
    [self log:@"开始导出全量 Keychain…"];
    self.statusLabel.text = @"导出中…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *err = nil;
        NSArray *items = [KeychainManager dumpAllItems:&err];
        NSError *plistErr = nil;
        NSData *plist = nil;
        @try {
            plist = [KeychainManager backupPlistWithItems:items error:&plistErr];
        } @catch (NSException *ex) {
            plistErr = [NSError errorWithDomain:@"LCKeychainBackup" code:-1
                userInfo:@{NSLocalizedDescriptionKey:
                    [NSString stringWithFormat:@"plist 序列化异常 %@: %@", ex.name, ex.reason]}];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!plist) {
                NSString *m = [NSString stringWithFormat:@"导出失败: %@",
                               plistErr ?: err ?: @"未知错误"];
                self.statusLabel.text = m;
                [self log:m];
                return;
            }
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.dateFormat = @"yyyyMMdd_HHmmss";
            NSString *name = [NSString stringWithFormat:@"keychain_backup_%@.plist",
                              [df stringFromDate:[NSDate date]]];
            NSURL *docs = [[[NSFileManager defaultManager]
                URLsForDirectory:NSDocumentDirectory
                              inDomains:NSUserDomainMask] firstObject];
            NSURL *url = [docs URLByAppendingPathComponent:name];
            NSError *werr = nil;
            [plist writeToURL:url options:NSDataWritingAtomic error:&werr];
            if (werr) {
                self.statusLabel.text = werr.localizedDescription;
                [self log:[@"写入失败: " stringByAppendingString:werr.localizedDescription]];
                return;
            }
            self.lastBackupURL = url;
            NSString *m = [NSString stringWithFormat:@"导出成功：%lu 条 → %@",
                           (unsigned long)items.count, name];
            if (err) m = [m stringByAppendingFormat:@"（部分类查询警告：%@）",
                          err.localizedDescription];
            self.statusLabel.text = m;
            [self log:m];
            [self log:[@"路径: " stringByAppendingString:url.path]];
            if (items.count == 0) {
                [self log:@"⚠️ 结果为空：可能 Hook 未穿透（仅读到隔离区且隔离区为空），或本容器确实无条目。"];
            } else {
                // 按 class 统计
                NSMutableDictionary *c = [NSMutableDictionary dictionary];
                for (NSDictionary *d in items) {
                    NSString *k = [KeychainManager displayNameForClass:d[@"_orig_class"]];
                    c[k] = @([c[k] integerValue] + 1);
                }
                [self log:[@"分类统计: " stringByAppendingString:c.description]];
            }
        });
    });
}

#pragma mark - Import

- (void)onBrowse {
    BrowseViewController *b = [[BrowseViewController alloc] init];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:b];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)onImport {
    // plist（新）+ JSON（旧）都可导入
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc]
            initForOpeningContentTypes:@[UTTypePropertyList, UTTypeJSON]];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
    [self log:@"请选择备份文件 keychain_backup_*（.plist / 旧 .json 均可）"];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;
    [self log:[@"选中文件: " stringByAppendingString:url.lastPathComponent]];
    self.statusLabel.text = @"导入中…";
    BOOL scoped = [url startAccessingSecurityScopedResource];
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (scoped) [url stopAccessingSecurityScopedResource];
    if (!data) {
        [self log:@"读取文件失败"];
        self.statusLabel.text = @"读取文件失败";
        return;
    }
    NSError *perr = nil;
    NSArray *obj = [KeychainManager itemsFromBackupData:data error:&perr];
    if (!obj) {
        NSString *m = [NSString stringWithFormat:@"备份解析失败: %@",
                       perr.localizedDescription ?: @"未知格式"];
        [self log:m];
        self.statusLabel.text = m;
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *rerr = nil;
        NSInteger ok = [KeychainManager restoreItems:(NSArray *)obj error:&rerr];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *m = [NSString stringWithFormat:@"导入完成：成功 %ld / 共 %lu 条",
                           (long)ok, (unsigned long)[(NSArray *)obj count]];
            if (rerr) m = [m stringByAppendingFormat:@"（%@）", rerr.localizedDescription];
            self.statusLabel.text = m;
            [self log:m];
        });
    });
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    [self log:@"已取消选择文件"];
}

#pragma mark - Share

- (void)onShare {
    if (!self.lastBackupURL) {
        // 尝试找 Documents 下最新的备份
        NSURL *docs = [[[NSFileManager defaultManager]
            URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
        NSArray *files = [[NSFileManager defaultManager]
            contentsOfDirectoryAtURL:docs
            includingPropertiesForKeys:@[NSURLContentModificationDateKey]
                               options:0 error:nil];
        NSURL *latest = nil; NSDate *latestDate = nil;
        for (NSURL *f in files) {
            NSString *ext = f.pathExtension.lowercaseString;
            if (![ext isEqualToString:@"plist"] && ![ext isEqualToString:@"json"]) continue;
            if (![f.lastPathComponent hasPrefix:@"keychain_backup_"]) continue;
            NSDate *d = nil;
            [f getResourceValue:&d forKey:NSURLContentModificationDateKey error:nil];
            if (!latest || [d compare:latestDate] == NSOrderedDescending) {
                latest = f; latestDate = d;
            }
        }
        self.lastBackupURL = latest;
    }
    if (!self.lastBackupURL) {
        [self log:@"还没有可分享的备份，请先导出。"];
        return;
    }
    UIActivityViewController *vc = [[UIActivityViewController alloc]
        initWithActivityItems:@[self.lastBackupURL] applicationActivities:nil];
    vc.popoverPresentationController.sourceView = self.shareBtn;
    vc.popoverPresentationController.sourceRect = self.shareBtn.bounds;
    [self presentViewController:vc animated:YES completion:nil];
    [self log:[@"分享: " stringByAppendingString:self.lastBackupURL.lastPathComponent]];
}

@end
