import requests
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
from pathlib import Path

# 配置信息
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY', 'Wuming155/China-AdGuard-Rules')
MAX_WORKERS = 10
TIMEOUT = 15

class RuleResolver:
    """分类解析器：确保 AdGuard 语法规则和 Hosts 域名规则各归各位"""
    def __init__(self):
        self.host_pattern = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\.\_]+)')
        self.domain_pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$')

    def resolve(self, line):
        line = line.strip()
        if not line or (line.startswith('!') and not line.startswith('!!')) or \
           (line.startswith('#') and not (line.startswith('##') or line.startswith('#%#'))):
            return None, None
        
        if line.startswith('@@'):
            return 'whitelist', line
            
        if any(x in line for x in ['||', '*', '^', '$', '##', '#%#']):
            if not re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)', line):
                return 'adguard_rules', line

        host_match = self.host_pattern.match(line)
        if host_match:
            domain = host_match.group(1).strip().lower()
            if domain not in ['localhost', 'localhost.localdomain']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        if self.domain_pattern.match(line):
            return 'hosts_rules', f"0.0.0.0 {line.lower()}"

        return None, None

def get_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def fetch_url(url, session):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        resp = session.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.text.splitlines()
    except Exception:
        pass
    return []

def update_readme(stats):
    """精准定位并更新 README 中的统计表"""
    readme_path = Path('README.md')
    if not readme_path.exists():
        return
        
    content = readme_path.read_text(encoding='utf-8')
    raw_base = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/dist"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    table_content = f"""
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| AdGuard 语法 | {stats.get('adguard_rules', 0)} | [点击下载]({raw_base}/adguard_rules.txt) |
| Hosts 屏蔽 | {stats.get('hosts_rules', 0)} | [点击下载]({raw_base}/hosts_rules.txt) |
| 白名单放行 | {stats.get('whitelist', 0)} | [点击下载]({raw_base}/whitelist.txt) |

⏰ 最后更新: {now}
"""
    # 替换规则统计部分
    pattern = r"(## 规则统计[\s\S]*?)(?=## |$)"
    if re.search(pattern, content):
        new_content = re.sub(pattern, f"## 规则统计\n{table_content}\n", content)
    else:
        new_content = content + f"\n\n## 规则统计\n{table_content}"

    readme_path.write_text(new_content, encoding='utf-8')

def main():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}
    
    # --- 新增：读取本地 custom-rules 文件夹下的文件 ---
    custom_rules_path = Path('custom-rules')
    if custom_rules_path.exists():
        print(f"正在扫描本地文件夹: {custom_rules_path}")
        for txt_file in custom_rules_path.glob('*.txt'):
            print(f"处理本地文件: {txt_file.name}")
            with open(txt_file, 'r', encoding='utf-8') as f:
                for line in f:
                    rtype, rule = resolver.resolve(line)
                    if rtype:
                        collections[rtype].add(rule)

    # 1. 读取远程源链接
    if os.path.exists('sources.txt'):
        with open('sources.txt', 'r', encoding='utf-8') as f:
            urls = [l.strip() for l in f if l.strip().startswith('http')]
            
        # 2. 并发下载与解析远程规则
        session = get_session()
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(fetch_url, url, session): url for url in urls}
            for future in as_completed(futures):
                lines = future.result()
                for line in lines:
                    rtype, rule = resolver.resolve(line)
                    if rtype:
                        collections[rtype].add(rule)

    # 3. 写入结果文件
    os.makedirs('dist', exist_ok=True)
    stats = {}
    update_time = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    for name in ['hosts_rules', 'adguard_rules', 'whitelist']:
        sorted_list = sorted(list(collections[name]))
        stats[name] = len(sorted_list)
        with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
            f.write(f"! Last Update: {update_time}\n")
            f.write(f"! Total Rules: {len(sorted_list)}\n\n")
            f.write("\n".join(sorted_list))
    
    # 4. 更新 README
    update_readme(stats)
    print("任务全部完成！")

if __name__ == "__main__":
    main()