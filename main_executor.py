import requests
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置：文件名对应的显示名称
TITLE_MAP = {
    'hosts_rules.txt': 'Hosts 屏蔽规则',
    'adguard_rules.txt': 'AdGuard 过滤规则',
    'whitelist.txt': '白名单放行规则'
}

def get_file_header(filename, count):
    date_str = datetime.now().strftime('%Y年%m月%d日')
    display_name = TITLE_MAP.get(filename, filename.replace('.txt', ''))
    return f"# 更新日期：{date_str}\n# 规则数：{count}\n! Title: {display_name}\n! ------------------------------------\n\n"

def fetch_url(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        if r.status_code == 200:
            return r.text.splitlines()
    except:
        pass
    return []

def update_live_readme(file_stats):
    """
    file_stats: 格式为 {'文件名.txt': 数量, ...}
    根据实际生成的文件数量，动态构建表格
    """
    readme_path = 'README.md'
    if not os.path.exists(readme_path): return

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 构建表格行
    table_rows = ""
    for filename, count in sorted(file_stats.items()):
        display_name = TITLE_MAP.get(filename, filename.replace('.txt', ''))
        table_rows += f"| **{display_name}** | {count} | [点击下载](./dist/{filename}) |\n"

    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    new_stats = f"""### 📊 规则统计
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
{table_rows}
**⏰ 最后更新时间**: {date_str}
"""

    pattern = re.compile(r'.*?', re.DOTALL)
    if pattern.search(content):
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(pattern.sub(new_stats, content))
        print("README 统计已根据实际文件数量自动更新。")

def run():
    # 使用字典，支持动态增加分类
    collections = {
        'hosts_rules.txt': set(),
        'adguard_rules.txt': set(),
        'whitelist.txt': set()
    }

    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\]]+', f.read())

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_url, urls)

    for lines in results:
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!') or (line.startswith('#') and not line.startswith('##')):
                continue
            
            # 1. 白名单判定
            if line.startswith('@@'):
                collections['whitelist.txt'].add(line)
            # 2. Hosts 判定
            elif line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                parts = line.split()
                if len(parts) >= 2:
                    collections['hosts_rules.txt'].add(f"0.0.0.0 {parts[1]}")
            # 3. 其他所有规则（CSS, 通配符等）
            else:
                collections['adguard_rules.txt'].add(line)

    # 过滤掉空的分类，只处理有内容的文件
    active_collections = {k: v for k, v in collections.items() if v}
    
    os.makedirs('dist', exist_ok=True)
    file_stats = {}

    for filename, rules in active_collections.items():
        count = len(rules)
        file_stats[filename] = count
        with open(f'dist/{filename}', 'w', encoding='utf-8') as f:
            f.write(get_file_header(filename, count))
            f.write("\n".join(sorted(list(rules))))

    # 动态统计：生成了几个文件，README 就列出几个
    update_live_readme(file_stats)

if __name__ == "__main__":
    run()
