import os
import re
from datetime import datetime

def update_readme(stats):
    if not os.path.exists('README.md'): return
    
    with open('README.md', 'r', encoding='utf-8') as f:
        content = f.read()

    # 准备新的统计表格
    date_full = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    new_table = f"""
📊 **规则统计**

| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| AdGuard 过滤规则 | {stats.get('adguard_rules', 0)} | [点击下载](https://raw.githubusercontent.com/你的用户名/仓库名/main/dist/adguard_rules.txt) |
| Hosts 屏蔽规则 | {stats.get('hosts_rules', 0)} | [点击下载](https://raw.githubusercontent.com/你的用户名/仓库名/main/dist/hosts_rules.txt) |
| 白名单放行规则 | {stats.get('whitelist', 0)} | [点击下载](https://raw.githubusercontent.com/你的用户名/仓库名/main/dist/whitelist.txt) |

⏰ **最后更新时间**: {date_full}
"""

    # 使用正则替换标记之间的内容，防止重复堆叠
    pattern = r".*?"
    replacement = f"{new_table}"
    
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)