# China-AdGuard-Rules

中国地区实用的AdGuard过滤规则，包含广告拦截、隐私保护、恶意软件拦截等功能。

## 规则统计

| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| AdGuard 语法 | 163737 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/adguard_rules.txt) |
| Hosts 屏蔽 | 6088 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/hosts_rules.txt) |
| 白名单放行 | 7611 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/whitelist.txt) |

⏰ 最后更新: 2026-01-17 22:11:10

## 源文件说明

### 1. SM-Ad-FuckU-hosts

* **地址**: `https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts`
* **介绍**: 该项目主要针对**什么值得买 (SMZDM)** 及相关购物平台的广告和冗余信息进行拦截。它采用了 Hosts 格式，侧重于从底层屏蔽与广告推送相关的域名。
* **适用场景**: 经常使用“什么值得买”但讨厌其开屏广告、弹窗及推广内容的系统环境。

### 2. AdRules (AdBlock 格式)

* **地址**: `https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt`
* **介绍**: 这是目前国内非常流行的开源规则库之一。它集成了多个上游规则，并针对中国互联网环境（如视频网站、门户网站）进行了大量优化。
* **特点**: 更新频率极高，覆盖范围广，包含视频贴片广告屏蔽、网页元素过滤和反广告屏蔽检测。

### 3. AWAvenue Ads Rule

* **地址**: `https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt`
* **介绍**: 由 AWAvenue 维护的综合性广告过滤规则，旨在提供“全平台、全设备”的拦截体验。
* **特点**: 对移动端 APP 的开屏广告、横幅广告有较好的拦截效果，同时兼顾了网页端的干净清爽。

### 4. DD-AD

* **地址**: `https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt`
* **介绍**: 这是一份相对小众但维护勤快、针对性强的过滤规则。
* **特点**: 主要针对国内主流 APP 的广告请求进行精简和屏蔽，旨在减少系统资源消耗的同时提升访问速度。

### 5. jiekouAD (大梦主广告规则)

* **地址**: `https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt`
* **介绍**: 这是一个专门针对**影视采集站、解析接口**以及在线视频播放器内置广告的规则列表。
* **特点**: 如果你经常使用第三方影视网站或解析插件，这个规则能有效屏蔽视频开头的“菠菜”（赌博）广告、跑马灯弹窗和虚假播放按钮。

### 6. HG (HG1 规则)

* **地址**: `https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt`
* **介绍**: 这属于个人维护的一份去广告补丁规则。
* **特点**: 包含了一些特定的移动端劫持跳转屏蔽和部分常见 APP 的广告接口屏蔽，通常作为大规则库的补充使用。

### 7. 666 Rules (qq5460168)

* **地址**: `https://raw.githubusercontent.com/qq5460168/666/master/rules.txt`
* **介绍**: 该规则库以“666”命名，是一个历史较久的个人维护项目。
* **特点**: 重点在于拦截各类网页上的牛皮癣广告、自动跳转广告以及部分短视频平台的后台上报连接。

#### 自定义白名单
**地址**: `https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/refs/heads/main/custom-rules/custom_whitelist.txt`
* **介绍**: 日常使用中手动的放行一些域名，减小误杀。