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
    return f"# 更新日期：{date_str}\n# 规则数：{count}\n! Title: {display_name}\n\n"

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

    # 1. 构造新表格
    table_rows = "| 规则类型 | 规则数量 | 下载链接 |\n| :--- | :--- | :--- |\n"
    for filename in sorted(file_stats.keys()):
        count = file_stats[filename]
        display_name = TITLE_MAP.get(filename, filename.replace('.txt', ''))
        table_rows += f"| **{display_name}** | {count} | [点击下载](./dist/{filename}) |\n"

    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 构建最终要显示的统计块
    new_block = (
        f"{table_rows}\n"
        f"**⏰ 最后更新时间**: {date_str}\n"
        f"REPLACE_ME" 
    )

    # 2. 逻辑：寻找 REPLACE_ME 并替换，同时在末尾再带一个 REPLACE_ME 方便下次替换
    if "REPLACE_ME" in content:
        # 只替换第一个发现的 REPLACE_ME
        updated_content = content.replace("REPLACE_ME", new_block, 1)
        # 如果因为误操作产生了多个 REPLACE_ME，清理掉多余的
        parts = updated_content.split("REPLACE_ME")
        final_content = parts[0] + "REPLACE_ME" + parts[-1]
        
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(final_content.strip() + "\n")
        print("README 已成功更新数字。")
    else:
        print("错误：README.md 中找不到 REPLACE_ME 标记")

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
            with open(os.path.join('dist', filename), 'w', encoding='utf-8') as f:
                f.write(get_file_header(filename, len(rules)))
                f.write("\n".join(sorted(list(rules))))
    update_readme(file_stats)

if __name__ == "__main__":
    run()
