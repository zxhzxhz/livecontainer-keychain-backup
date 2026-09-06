# LCKeychainBackup — LiveContainer 内 Keychain 备份 / 恢复工具（第一阶段：极简版）

在 LiveContainer 即将过期（nightly 签名损坏、仅剩 ~2 天）的紧急情况下，
用一个安装在 LiveContainer **内部**的 Guest App 穿透其用户态 Keychain Hook，
把宿主进程名下所有 Keychain 条目导出为 JSON，重装后再导入。

> 原理见 `Live Container内的Keychain访问权限分析.md`：
> 同一 LiveContainer 内的 Guest App 与宿主是**同一进程 / 同一签名主体**，
> Keychain 隔离只是用户态 Hook（重定向 access-group / prefix）的软隔离，
> 通过 `dlopen + dlsym` 取原始 `SecItem*` 函数即可读到未过滤的全量数据。
> 不能读取 LiveContainer 之外的系统 / 其他 App 的 Keychain。

## ⚠️ 决定成败的前提（必读）

1. **重装必须用同一个 Apple ID / 同一证书（同一 Team ID）。**
   Keychain 条目与 Team ID 物理绑定，换号重装后旧数据永远写不回去。
2. **先导出、确认 JSON 非空并拷贝出手机，再重装。**
   建议 AirDrop / 文件 App / 分享面板多存几份。

## 功能

### Phase 1（已完成）：备份 / 恢复

- 基础 UI：状态 + 日志 + 按钮
- **导出**：遍历 5 类 `kSecClass`（genp/inet/cert/keys/idnt），
  `SecItemCopyMatching` 全量查询 → `Documents/keychain_backup_<时间戳>.plist`
- **导入**：从文件选择备份（.plist 新格式 / .json 旧格式兼容）→
  `SecItemDelete + SecItemAdd` 幂等恢复
- **分享**：把最近一次备份通过 `UIActivityViewController` 发到文件 App / AirDrop

### Phase 2（当前）：浏览 / 编辑 + plist 格式

- 备份文件改为 **plist（XML）**：`NSDate` / `NSData` 原生支持；
  根结构 `{format, version: 2, exported_at, item_count, items}`，旧 JSON 照样能导
- **浏览**：按 GenericPassword / InternetPassword / Certificate / Key / Identity
  分组列表，标题为 account/label，副标题为 class · service · 数据长度，带搜索
- **详情**：全部属性 key-value 展示，点一行可复制值
- **编辑**：字符串直接改；`v_Data` 文本按文本存、二进制按 base64 存；
  写回走“按原条目删 + 写新”（定位键被改也不怕），失败自动回滚原条目
- **删除**：单条删除（二次确认）
- 只读保护：`_orig_class/class/cdat/mdat/crtr/v_Ref/持久化引用/accc`
  及不可序列化字段不可编；identity 整类不可直接 Add（它是 cert+key 派生视图）

## 安装到 LiveContainer

1. 从 GitHub Actions 产物下载 `LCKeychainBackup-unsigned.ipa`（no-sign）。
2. 用 LiveContainer 的“从 URL / 文件安装”装入（或经 TrollStore / SideStore 自签后装入）。
3. 在旧 LiveContainer 里打开 → 点 **导出** → **分享**存好 JSON。
4. 用**同一 Apple ID** 重装 LiveContainer 稳定版 → 装回本 App → **导入** JSON。

## 本地编译 / CI

- 本地需 Xcode；iPhone 真机 SDK。
- CI（`.github/workflows/build-unsigned-ipa.yml`）在 `macos-latest` 上：
  `xcodebuild CODE_SIGNING_ALLOWED=NO` 编出 `.app` → 打包 `Payload/*.app` 为 unsigned ipa → 上传 Artifact。

## 目录

```
LCKeychainBackup/                  # Xcode 工程 + 源码
.github/workflows/                 # Action：编译 no-sign ipa
Live Container内的Keychain访问权限分析.md
```

## 免责

仅用于备份你自己的数据。Hook 穿透 equally 适用于同一容器内其他 App 的条目，
请勿读取、传播他人凭据。
