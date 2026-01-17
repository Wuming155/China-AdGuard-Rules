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
    readme_path = Path('README.md')
    if not readme_path.exists():
        return
    content = readme_path.read_text(encoding='utf-8')
    raw_base = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/dist"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 构建新表格内容
    table_content = f"""
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| AdGuard 语法 | {stats.get('adguard_rules', 0)} | [点击下载]({raw_base}/adguard_rules.txt) |
| Hosts 屏蔽 | {stats.get('hosts_rules', 0)} | [点击下载]({raw_base}/hosts_rules.txt) |
| 白名单放行 | {stats.get('whitelist', 0)} | [点击下载]({raw_base}/whitelist.txt) |

⏰ 最后更新: {now}
"""
    # 采用更稳健的匹配：匹配 ## 规则统计 标题后的内容，直到下一个二级标题
    pattern = r"(## 规则统计\n)([\s\S]*?)(?=\n## )"
    if re.search(pattern, content):
        new_content = re.sub(pattern, r"\1" + table_content, content)
    else:
        # 如果没找到二级标题，尝试匹配到结尾
        pattern_end = r"(## 规则统计\n)([\s\S]*)"
        new_content = re.sub(pattern_end, r"\1" + table_content, content)

    readme_path.write_text(new_content, encoding='utf-8')

def main():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}
    
    # 1. 优先读取本地 custom-rules
    custom_dir = Path('custom-rules')
    if custom_dir.exists():
        print(f"正在扫描本地目录: {custom_dir.absolute()}")
        for file_path in custom_dir.glob('*.txt'):
            print(f"正在读取本地文件: {file_path.name}")
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    rtype, rule = resolver.resolve(line)
                    if rtype:
                        collections[rtype].add(rule)

    # 2. 读取远程源
    sources_path = Path('sources.txt')
    if sources_path.exists():
        with open(sources_path, 'r', encoding='utf-8') as f:
            urls = [l.strip() for l in f if l.strip().startswith('http')]
            if urls:
                session = get_session()
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    futures = {executor.submit(fetch_url, url, session): url for url in urls}
                    for future in as_completed(futures):
                        lines = future.result()
                        for line in lines:
                            rtype, rule = resolver.resolve(line)
                            if rtype:
                                collections[rtype].add(rule)

    # 3. 写入 dist
    dist_dir = Path('dist')
    dist_dir.mkdir(exist_ok=True)
    stats = {}
    update_time = datetime.now().strftime('%Y-%m-%d %H:%M')
    for name in ['hosts_rules', 'adguard_rules', 'whitelist']:
        sorted_list = sorted(list(collections[name]))
        stats[name] = len(sorted_list)
        (dist_dir / f"{name}.txt").write_text(
            f"! Last Update: {update_time}\n! Total Rules: {len(sorted_list)}\n\n" + "\n".join(sorted_list),
            encoding='utf-8'
        )
    
    # 4. 更新 README
    update_readme(stats)
    print(f"处理完成！总计: AdGuard({stats['adguard_rules']}), Hosts({stats['hosts_rules']}), Whitelist({stats['whitelist']})")

if __name__ == "__main__":
    main()