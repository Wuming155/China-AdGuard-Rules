# 🛡️ China AdGuard Rules

本项目自动抓取、去重并整合多个优质过滤规则源。通过 GitHub Actions 每天自动更新。

### 📊 规则统计
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| **Hosts 屏蔽规则** | 计算中... | [点击下载](./dist/hosts_rules.txt) |
| **AdGuard 过滤规则** | 计算中... | [点击下载](./dist/adguard_rules.txt) |
| **白名单放行规则** | 计算中... | [点击下载](./dist/whitelist.txt) |

**⏰ 最后更新时间**: 正在同步...
### 🔗 来源说明
1. **SM-Ad-FuckU-hosts**: 针对移动端广告、运营商劫持的优化。
2. **AWAvenue-Ads-Rule**: 强大的类 Adblock 规则库。
3. **自定义维护**: 包含手动搜集的黑名单与白名单。

### 🛠️ 如何使用
- **AdGuard Home**: 将下载链接（Raw）添加至“过滤器”->“DNS 拦截列表”。
- **浏览器插件**: 在 AdGuard 或 uBlock Origin 中作为自定义规则导入。
- **Hosts**: 复制 `hosts_rules.txt` 内容粘贴进系统文件。

---
*本项目由 GitHub Actions 自动构建，请勿手动修改本文件。*
