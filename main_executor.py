import requests
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib3

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_file_header(name, count):
    """找回您丢失的标题信息"""
    # 严格按照你要求的日期格式
    date_str = datetime.now().strftime('%Y年%m月%d日')
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则',
        'adguard_rules': 'AdGuard 过滤规则'
    }
    return f"# 更新日期：{date_str}\n# 规则数：{count}\n! Title: {title_map.get(name, '去广告规则')}\n! ------------------------------------\n\n"

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
    """动态更新 README 中的统计数据"""
    readme_path = 'README.md'
    if not os.path.exists(readme_path):
        return

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # 匹配标记位进行替换
    new_stats = f"""### 📊 规则统计
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| **Hosts 屏蔽** | {hosts_num} | [点击下载](./dist/hosts_rules.txt) |
| **AdGuard 过滤** | {other_num} | [点击下载](./dist/adguard_rules.txt) |

**⏰ 最后更新时间**: {date_str}
"""

    pattern = re.compile(r'.*?', re.DOTALL)
    if pattern.search(content):
        updated_content = pattern.sub(new_stats, content)
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(updated_content)

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
            # 排除注释和空行，但保留像 ### 这样的规则
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
    
    # 1. 保存 Hosts 规则（包含标题）
    with open('dist/hosts_rules.txt', 'w', encoding='utf-8') as f:
        f.write(get_file_header('hosts_rules', len(host_set)))
        f.write("\n".join(sorted(list(host_set))))

    # 2. 保存 AdGuard 规则（包含标题）
    with open('dist/adguard_rules.txt', 'w', encoding='utf-8') as f:
        f.write(get_file_header('adguard_rules', len(other_set)))
        f.write("\n".join(sorted(list(other_set))))

    # 3. 更新 README
    update_live_readme(len(host_set), len(other_set))

    print(f"处理完成：Hosts({len(host_set)}条), 其他({len(other_set)}条)")

if __name__ == "__main__":
    run()
