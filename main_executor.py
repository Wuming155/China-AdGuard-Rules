import requests
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        if r.status_code == 200: return r.text.splitlines()
    except: pass
    return []

def update_readme(file_stats):
    readme_path = 'README.md'
    if not os.path.exists(readme_path): return

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. 构造新的表格块
    table_rows = ""
    for filename in sorted(file_stats.keys()):
        count = file_stats[filename]
        display_name = TITLE_MAP.get(filename, filename.replace('.txt', ''))
        table_rows += f"| **{display_name}** | {count} | [点击下载](./dist/{filename}) |\n"

    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    start_marker = ""
    end_marker = ""

    # 2. 核心逻辑：直接物理分割字符串
    if start_marker in content and end_marker in content:
        # 保留标记之前的部分
        before = content.split(start_marker)[0]
        # 保留标记之后的部分
        after = content.split(end_marker)[-1]
        
        # 重新拼接：前段 + 开始标记 + 新表格 + 结束标记 + 后段
        new_stats = (
            f"\n### 📊 规则统计\n"
            f"| 规则类型 | 规则数量 | 下载链接 |\n"
            f"| :--- | :--- | :--- |\n"
            f"{table_rows}\n"
            f"**⏰ 最后更新时间**: {date_str}\n"
        )
        
        updated_content = before + start_marker + new_stats + end_marker + after
        
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(updated_content.strip() + "\n")
        print("README 统计已精准替换。")
    else:
        # 如果找不到标记，为了防止乱加，直接报错不处理
        print("！！！错误：README 中找不到标记位，停止更新以防重复！！！")
def run():
    collections = {'hosts_rules.txt': set(), 'adguard_rules.txt': set(), 'whitelist.txt': set()}
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
            if line.startswith('@@'):
                collections['whitelist.txt'].add(line)
            elif line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                parts = line.split()
                if len(parts) >= 2: collections['hosts_rules.txt'].add(f"0.0.0.0 {parts[1]}")
            else:
                collections['adguard_rules.txt'].add(line)

    os.makedirs('dist', exist_ok=True)
    file_stats = {}
    for filename, rules in collections.items():
        if rules:
            file_stats[filename] = len(rules)
            with open(f'dist/{filename}', 'w', encoding='utf-8') as f:
                f.write(get_file_header(filename, len(rules)))
                f.write("\n".join(sorted(list(rules))))

    update_readme(file_stats)

if __name__ == "__main__":
    run()
