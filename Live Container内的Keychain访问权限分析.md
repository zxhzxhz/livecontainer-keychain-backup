# **Live Container内的Keychain访问权限分析**

*User prompt: 理论上来说，Live Container内的安装的APP可以访问它全部的Keychain对吗*

Response: **理论上和技术实现上，答案是：不能访问系统的全部 Keychain，但可以访问 LiveContainer 宿主及其内部其他 App 的 Keychain。**

iOS 的 Keychain 隔离边界是建立在**进程和签名 Entitlements（授权机制）之上的。LiveContainer 并不是虚拟机或真正的 Hypervisor，它本质是一个应用加载器（App Launcher）**。

具体机制可以分为两个层面：

### **1\. 能否访问 iOS 系统或其他外部 App 的 Keychain？**

**绝对不能。**

> * iOS 系统的 Keychain 数据受 securityd 守护进程和硬件加密（Secure Enclave）严格保护。  
> * 任何应用查询或写入 Keychain 时，系统会校验调用方进程的 Team ID 和 keychain-access-groups 授权项。  
> * 容器内的 App 运行在 LiveContainer 的进程空间内，受到 LiveContainer 自身沙盒及签名签发的证书限制，根本无法跨越权限读取如微信、支付宝或系统自带应用的凭据与密钥。

### **2\. 能否访问 LiveContainer 自身的全部 Keychain 数据？**

**理论上可以（同进程完全穿透），但 LiveContainer 做了运行时的软隔离。**

> * **底层本质：** 所有在 LiveContainer 中运行的 Guest App，在 iOS 内核视角下都属于**同一个宿主进程**，共享相同的签名凭证与 Keychain Access Group。在没有额外 hook 的情况下，任何一个子 App 调用 SecItemCopyMatching 等标准 API，都可以直接读写该签名主体名下的所有 Keychain 条目。  
> * **LiveContainer 的软隔离（Keychain Semi-Separation）：**  
  * LiveContainer 预先申请了多组（通常为 128 个）keychain-access-groups。  
  * 当加载某个 Guest App 时，LiveContainer 会通过 Hook / 动态注入（如 TweakLoader、Substrate）拦截该 App 的 Security 框架调用，强行将其 Keychain 读写请求重定向到为其分配的专属 group 或添加特定 prefix。  
  * **理论限制与漏洞：** 这种隔离纯属**用户态 Hook 级别的软限制**，并不是内核级沙盒。如果容器内运行的代码/逆向工具主动解除 Hook、直接构造底层系统调用，或者两个 App 恰好被分配到了相同的 Keychain Access Group，它是完全能够读出当前 LiveContainer 及其内部其他容器保存的 Keychain 数据的。  
> * **对整个 iOS 系统：** 安全边界依然存在，拿不到外部任何应用的 Keychain。  
> * **对 LiveContainer 内部：** 默认通过 Hook 做了“多容器隔离”，但在攻击者或恶意代码视角下不存在真正的物理安全防线，**理论上同一 LiveContainer 内的所有数据均可被内部 App 互相读取**。

**Sources**

> 1. [NEW LiveContainer iOS 2026 : Run iOS Apps Without Installation](https://www.youtube.com/watch?v=dFMPPWDh7wE)  
> 2. [Container isolation is completely broken · Issue \#1443 \- GitHub](https://github.com/LiveContainer/LiveContainer/issues/1443)  
> 3. [LiveContainer: Run Unlimited iOS Apps Without Installation](https://www.blog.brightcoding.dev/2026/02/04/livecontainer-run-unlimited-ios-apps-without-installation)  
> 4. [Releases · LiveContainer/LiveContainer \- GitHub](https://github.com/LiveContainer/LiveContainer/releases)

---

*User prompt: 我现在livecontainer安装损坏了（nightly版本破坏了内置sidestore签名），只有两天就无法运行，我想制作一个keychain backup工具，安装在livecontainer中，通过内部访问穿透的原理，导出所有项目，重新安装后再导入*

Response: 要在当前已损坏、签名仅剩两天的 LiveContainer 环境下自制工具导出并恢复 Keychain，**理论完全可行，但操作中有两个决定性的技术陷阱必须绕过**。

### **核心风险与前提**

> 1. **证书与 Team ID 变更风险（最致命）**  
   * iOS Keychain 条目是与签名的 **Team ID** 物理绑定的（由 securityd 强制校验）。  
   * 如果重装 LiveContainer 时使用了**不同的 Apple ID**，新重装的 App 将**永远无法**通过系统 API 写入原本属于旧 Team ID 的 Keychain 组。  
   * **前提**：重装时必须使用**完全相同的 Apple 账号/证书**。  
> 2. **避开 LiveContainer 的 Keychain Hook**  
   * LiveContainer 在运行 Guest App 时，默认注入了 Hook 拦截 SecItem\* 系列函数，将其重定向到子应用的独立隔离前缀或 group。  
   * 自制导出工具如果作为普通 Guest App 启动，默认**只能查出当前被分配沙盒的内容**。  
   * **对策**：在导出/导入工具启动时，必须**绕过/解绑 LiveContainer 的 Hook**，直接调用原生系统的 Security.framework。

### **实现方案与代码**

#### **1\. 核心导出/导入逻辑 (Objective-C)**

`#import <Foundation/Foundation.h>`  
`#import <Security/Security.h>`  
`#import <dlfcn.h>`

`// 导出所有支持的 Keychain 类别`  
`static NSArray *kSecClasses = nil;`

`void InitKeychainClasses() {`  
    `kSecClasses = @[`  
        `(__bridge id)kSecClassGenericPassword,`  
        `(__bridge id)kSecClassInternetPassword,`  
        `(__bridge id)kSecClassCertificate,`  
        `(__bridge id)kSecClassKey,`  
        `(__bridge id)kSecClassIdentity`  
    `];`  
`}`

`// 1. 导出 Keychain`  
`NSArray* DumpAllKeychainItems(void) {`  
    `InitKeychainClasses();`  
    `NSMutableArray *allItems = [NSMutableArray array];`

    `for (id secClass in kSecClasses) {`  
        `NSMutableDictionary *query = [NSMutableDictionary dictionaryWithDictionary:@{`  
            `(__bridge id)kSecClass: secClass,`  
            `(__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,`  
            `(__bridge id)kSecReturnAttributes: @YES,`  
            `(__bridge id)kSecReturnData: @YES`  
        `}];`

        `CFTypeRef result = NULL;`  
        `OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);`

        `if (status == errSecSuccess && result != NULL) {`  
            `NSArray *items = (__bridge_transfer NSArray *)result;`  
            `for (NSDictionary *dict in items) {`  
                `NSMutableDictionary *entry = [dict mutableCopy];`  
                `// Base64 编码二进制字段以支持 JSON 序列化`  
                `if (entry[(__bridge id)kSecValueData]) {`  
                    `entry[@"v_Data_Base64"] = [entry[(__bridge id)kSecValueData] base64EncodedStringWithOptions:0];`  
                    `[entry removeObjectForKey:(__bridge id)kSecValueData];`  
                `}`  
                `entry[@"_orig_class"] = secClass;`  
                `[allItems addObject:entry];`  
            `}`  
        `}`  
    `}`  
    `return allItems;`  
`}`

`// 2. 导入 Keychain`  
`BOOL RestoreKeychainItems(NSArray *items) {`  
    `for (NSDictionary *rawEntry in items) {`  
        `NSMutableDictionary *query = [rawEntry mutableCopy];`  
        `id secClass = query[@"_orig_class"];`  
        `[query removeObjectForKey:@"_orig_class"];`

        `// 还原 Data`  
        `if (query[@"v_Data_Base64"]) {`  
            `NSData *data = [[NSData alloc] initWithBase64EncodedString:query[@"v_Data_Base64"] options:0];`  
            `query[(__bridge id)kSecValueData] = data;`  
            `[query removeObjectForKey:@"v_Data_Base64"];`  
        `}`

        `// 移除只读/系统维护元数据（否则 SecItemAdd 会报错 errSecParam -50）`  
        `[query removeObjectForKey:(__bridge id)kSecAttrCreationDate];`  
        `[query removeObjectForKey:(__bridge id)kSecAttrModificationDate];`

        `query[(__bridge id)kSecClass] = secClass;`

        `// 幂等写入：先删后加`  
        `NSMutableDictionary *delQuery = [NSMutableDictionary dictionaryWithDictionary:@{`  
            `(__bridge id)kSecClass: secClass`  
        `}];`  
        `if (query[(__bridge id)kSecAttrAccount]) delQuery[(__bridge id)kSecAttrAccount] = query[(__bridge id)kSecAttrAccount];`  
        `if (query[(__bridge id)kSecAttrService]) delQuery[(__bridge id)kSecAttrService] = query[(__bridge id)kSecAttrService];`  
        `if (query[(__bridge id)kSecAttrAccessGroup]) delQuery[(__bridge id)kSecAttrAccessGroup] = query[(__bridge id)kSecAttrAccessGroup];`

        `SecItemDelete((__bridge CFDictionaryRef)delQuery);`  
        `OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);`  
        `if (status != errSecSuccess) {`  
            `NSLog(@"[KeychainBackup] 写入失败: %d", (int)status);`  
        `}`  
    `}`  
    `return YES;`  
`}`

### **绕过 LiveContainer 的 Hook 限制**

LiveContainer 通常通过动态库（LCShared / fishhook / Substrate）替换了符号地址。为确保读出**未经过滤的宿主原始数据**，建议在打包该备份 App 时进行原生符号还原：

`// 直接通过 dlopen 原始库取得未被中途串改的系统函数指针调用`  
`typedef OSStatus (*SecItemCopyMatchingFunc)(CFDictionaryRef query, CFTypeRef *result);`

`SecItemCopyMatchingFunc GetOriginalSecItemCopyMatching() {`  
    `void *handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_GLOBAL | RTLD_NOLOAD);`  
    `if (!handle) handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);`  
    `return (SecItemCopyMatchingFunc)dlsym(handle, "SecItemCopyMatching");`  
`}`

### **操作流程**

> 1. **编译备份 App**：  
   * 将上述逻辑封装进一个极简的 iOS App（包含两个按钮：“Export to JSON” 和 “Import from JSON”）。  
   * 点击导出后，将生成的 keychain\_backup.json 保存到应用沙盒的 Documents 目录，并通过系统的 UIActivityViewController（分享面板）将其发送到“文件”App 或隔空投送（AirDrop）出来。  
> 2. **装入现存 LiveContainer**：  
   * 在 LiveContainer 仍有 2 天证书有效期的状态下，将此备份 App 作为 Guest App 安装并运行。  
   * 点击导出，确认导出的 JSON 文件非空并保存在手机本地。  
> 3. **修复与重装**：  
   * 使用**相同的 Apple 账号**重新打包签名发布一个可用的 LiveContainer 稳定版本。  
   * 安装新的 LiveContainer。  
> 4. **导入数据**：  
   * 在新 LiveContainer 中安装备份 App。  
   * 读入刚才的 keychain\_backup.json，执行恢复逻辑。

---

