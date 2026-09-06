#import "BrowseViewController.h"
#import "DetailViewController.h"
#import "KeychainManager.h"

@interface BrowseViewController () <UITableViewDataSource, UITableViewDelegate, UISearchResultsUpdating>
@property (nonatomic, strong) UITableView *table;
@property (nonatomic, strong) UISearchController *searcher;
// 全量编码条目 + 按 class 分组
@property (nonatomic, strong) NSArray<NSDictionary *> *allEntries;
@property (nonatomic, strong) NSArray<NSString *> *sectionClasses;
@property (nonatomic, strong) NSDictionary<NSString *, NSArray<NSDictionary *> *> *sectionRows;
@property (nonatomic, strong) UILabel *emptyLabel;
@end

@implementation BrowseViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Keychain 浏览";
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                     target:self action:@selector(onDone)];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                     target:self action:@selector(reload)];

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

    self.emptyLabel = [[UILabel alloc] init];
    self.emptyLabel.text = @"空：未读到任何条目";
    self.emptyLabel.textColor = [UIColor secondaryLabelColor];
    self.emptyLabel.textAlignment = NSTextAlignmentCenter;
    self.table.backgroundView = self.emptyLabel;

    self.searcher = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.searcher.searchResultsUpdater = self;
    self.searcher.obscuresBackgroundDuringPresentation = NO;
    self.searcher.searchBar.placeholder = @"搜索 account / service / label";
    self.navigationItem.searchController = self.searcher;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.definesPresentationContext = YES;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reload];
}

- (void)onDone { [self dismissViewControllerAnimated:YES completion:nil]; }

- (void)reload {
    NSError *err = nil;
    self.allEntries = [KeychainManager dumpAllItems:&err];
    // 按 class 分组，保持 genp/inet/cert/keys/idnt 顺序
    NSArray *order = [KeychainManager classIDs];
    NSMutableDictionary *groups = [NSMutableDictionary dictionary];
    for (NSDictionary *e in self.allEntries) {
        NSString *c = e[@"_orig_class"] ?: @"?";
        NSMutableArray *a = groups[c] ?: [NSMutableArray array];
        if (!groups[c]) groups[c] = a;
        [a addObject:e];
    }
    NSMutableArray *classes = [NSMutableArray array];
    NSMutableDictionary *rows = [NSMutableDictionary dictionary];
    for (NSString *c in order) {
        if ([(NSArray *)(groups[c] ?: @[]) count]) {
            [classes addObject:c];
            rows[c] = groups[c];
        }
    }
    // 未知 class 兜底
    for (NSString *c in groups) {
        if (!rows[c]) { [classes addObject:c]; rows[c] = groups[c]; }
    }
    self.sectionClasses = classes;
    self.sectionRows = rows;
    self.emptyLabel.hidden = self.allEntries.count > 0;
    [self.table reloadData];
    self.title = [NSString stringWithFormat:@"Keychain (%lu)", (unsigned long)self.allEntries.count];
}

#pragma mark - Search

- (BOOL)isSearching {
    return self.searcher.isActive && self.searcher.searchBar.text.length > 0;
}

- (NSArray<NSDictionary *> *)filteredEntries {
    NSString *q = self.searcher.searchBar.text.lowercaseString;
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *e in self.allEntries) {
        NSString *hay = [NSString stringWithFormat:@"%@ %@",
                         [KeychainManager summaryForEntry:e],
                         [KeychainManager subtitleForEntry:e]].lowercaseString;
        if ([hay containsString:q]) [out addObject:e];
    }
    return out;
}

- (void)updateSearchResultsForSearchController:(UISearchController *)c {
    [self.table reloadData];
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)t {
    return [self isSearching] ? 1 : self.sectionClasses.count;
}

- (NSInteger)tableView:(UITableView *)t numberOfRowsInSection:(NSInteger)s {
    if ([self isSearching]) return [self filteredEntries].count;
    return [(NSArray *)self.sectionRows[self.sectionClasses[s]] count];
}

- (NSString *)tableView:(UITableView *)t titleForHeaderInSection:(NSInteger)s {
    if ([self isSearching]) return @"搜索结果";
    NSString *c = self.sectionClasses[s];
    return [NSString stringWithFormat:@"%@ (%lu)",
            [KeychainManager displayNameForClass:c],
            (unsigned long)[(NSArray *)self.sectionRows[c] count]];
}

- (NSDictionary *)entryAt:(NSIndexPath *)ip {
    if ([self isSearching]) return [self filteredEntries][ip.row];
    return (NSDictionary *)self.sectionRows[self.sectionClasses[ip.section]][ip.row];
}

- (UITableViewCell *)tableView:(UITableView *)t cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *rid = @"kcrow";
    UITableViewCell *cell = [t dequeueReusableCellWithIdentifier:rid];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:rid];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    NSDictionary *e = [self entryAt:ip];
    cell.textLabel.text = [KeychainManager summaryForEntry:e];
    cell.detailTextLabel.text = [KeychainManager subtitleForEntry:e];
    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    return cell;
}

- (void)tableView:(UITableView *)t didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [t deselectRowAtIndexPath:ip animated:YES];
    DetailViewController *d = [[DetailViewController alloc] initWithEntry:[self entryAt:ip]];
    [self.navigationController pushViewController:d animated:YES];
}

@end
