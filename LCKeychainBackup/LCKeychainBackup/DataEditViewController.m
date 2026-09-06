#import "DataEditViewController.h"

@interface DataEditViewController ()
@property (nonatomic, copy) NSString *navTitle;
@property (nonatomic, copy, nullable) NSString *hint;
@property (nonatomic, copy) NSString *initialText;
@property (nonatomic, assign) BOOL readOnly;
@property (nonatomic, copy, nullable) BOOL (^onSave)(NSString *, NSError **);
@property (nonatomic, strong) UITextView *textView;
@end

@implementation DataEditViewController

- (instancetype)initWithTitle:(NSString *)title
                         hint:(NSString *)hint
                         text:(NSString *)text
                     readOnly:(BOOL)readOnly
                       onSave:(BOOL (^)(NSString *, NSError **))onSave {
    if (self = [super init]) {
        _navTitle = [title copy];
        _hint = [hint copy];
        _initialText = [text copy] ?: @"";
        _readOnly = readOnly;
        _onSave = [onSave copy];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = self.navTitle;
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    if (self.readOnly) {
        self.navigationItem.rightBarButtonItem =
            [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAction
                                                         target:self action:@selector(onCopy)];
    } else {
        self.navigationItem.rightBarButtonItem =
            [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemSave
                                                         target:self action:@selector(onSaveTap)];
    }

    UILabel *hintLabel = nil;
    if (self.hint.length) {
        hintLabel = [[UILabel alloc] init];
        hintLabel.text = self.hint;
        hintLabel.font = [UIFont systemFontOfSize:12];
        hintLabel.textColor = [UIColor secondaryLabelColor];
        hintLabel.numberOfLines = 0;
        hintLabel.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:hintLabel];
    }

    self.textView = [[UITextView alloc] init];
    self.textView.text = self.initialText;
    self.textView.editable = !self.readOnly;
    self.textView.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    self.textView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.textView.autocorrectionType = UITextAutocorrectionTypeNo;
    self.textView.spellCheckingType = UITextSpellCheckingTypeNo;
    self.textView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.textView.layer.cornerRadius = 8;
    self.textView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.textView];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    NSMutableArray *c = [NSMutableArray arrayWithObjects:
        [self.textView.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],
        [self.textView.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12],
        [self.textView.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-12],
        nil];
    if (hintLabel) {
        [c addObjectsFromArray:@[
            [hintLabel.topAnchor constraintEqualToAnchor:g.topAnchor constant:8],
            [hintLabel.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
            [hintLabel.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
            [self.textView.topAnchor constraintEqualToAnchor:hintLabel.bottomAnchor constant:8],
        ]];
    } else {
        [c addObject:[self.textView.topAnchor constraintEqualToAnchor:g.topAnchor constant:12]];
    }
    [NSLayoutConstraint activateConstraints:c];
}

- (void)onCopy {
    UIPasteboard.generalPasteboard.string = self.textView.text;
    UIAlertController *c = [UIAlertController alertControllerWithTitle:nil
        message:@"已复制" preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:c animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [c dismissViewControllerAnimated:YES completion:nil];
    });
}

- (void)onSaveTap {
    if (!self.onSave) {
        [self.navigationController popViewControllerAnimated:YES];
        return;
    }
    NSError *err = nil;
    if (self.onSave(self.textView.text ?: @"", &err)) {
        [self.navigationController popViewControllerAnimated:YES];
    } else {
        UIAlertController *c = [UIAlertController
            alertControllerWithTitle:@"保存失败"
                             message:err.localizedDescription ?: @"未知错误"
                      preferredStyle:UIAlertControllerStyleAlert];
        [c addAction:[UIAlertAction actionWithTitle:@"返回修改"
                                              style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:c animated:YES completion:nil];
    }
}

@end
