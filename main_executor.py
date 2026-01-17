import requests
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def fetch_url(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        if r.status_code == 200:
            return r.text.splitlines()
    except:
        pass
    return []

def update_live_readme(hosts_num, other_num):
    readme_path = 'README.md'
    if not os.path.exists(readme_path):
        return

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 构建动态内容块
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    new_stats = f"""### 📊 规则统计
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| **Hosts 拦截** | {hosts_num} | [点击下载](./dist/hosts_rules.txt) |
| **AdGuard 过滤** | {other_num} | [点击下载](./dist/adguard_rules.txt) |

**⏰ 最后更新时间**: {date_str}
"""

    # 使用正则替换两个标记位之间的所有内容
    pattern = re.compile(r'.*?', re.DOTALL)
    updated_content = pattern.sub(new_stats, content)

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    print("README.md 统计数据已更新")

def run():
    host_set = set()
    other_set = set()

    if not os.path.exists('sources.txt'):
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\]]+', f.read())

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_url, urls)

    for lines in results:
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!') or line.startswith('# '):
                continue
            
            if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                parts = line.split()
                if len(parts) >= 2:
                    host_set.add(f"0.0.0.0 {parts[1]}")
            else:
                other_set.add(line)

    # 保存文件
    os.makedirs('dist', exist_ok=True)
    with open('dist/hosts_rules.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(list(host_set))))
    with open('dist/adguard_rules.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(list(other_set))))

    # 动态更新 README.md
    update_live_readme(len(host_set), len(other_set))

if __name__ == "__main__":
    run()
