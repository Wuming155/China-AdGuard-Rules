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

class RuleResolver:
    def __init__(self):
        self.host_pattern = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\.\_]+)')
        self.domain_pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$')

    def resolve(self, line):
        line = line.strip()
        if not line or (line.startswith('!') and not line.startswith('!!')) or \
           (line.startswith('#') and not (line.startswith('##') or line.startswith('#%#'))):
            return None, None
        if line.startswith('@@'): return 'whitelist', line
        if any(x in line for x in ['||', '*', '^', '$', '##', '#%#']):
            if not re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)', line): return 'adguard_rules', line
        host_match = self.host_pattern.match(line)
        if host_match:
            domain = host_match.group(1).strip().lower()
            if domain not in ['localhost', 'localhost.localdomain']: return 'hosts_rules', f"0.0.0.0 {domain}"
        if self.domain_pattern.match(line): return 'hosts_rules', f"0.0.0.0 {line.lower()}"
        return None, None

def get_file_stats(folder_path):
    """扫描文件夹并统计每个文件的规则数"""
    stats_list = []
    path = Path(folder_path)
    if path.exists():
        for f in path.glob('*.txt'):
            count = 0
            with open(f, 'r', encoding='utf-8') as file:
                for line in file:
                    # 简单统计非空、非注释行
                    if line.strip() and not line.startswith(('!', '#')):
                        count += 1
            stats_list.append({'name': f.name, 'count': count, 'folder': folder_path})
    return stats_list

def update_readme(all_file_stats):
    readme_path = Path('README.md')
    if not readme_path.exists(): return
    content = readme_path.read_text(encoding='utf-8')

    raw_base = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 构建动态表格
    table_header = "| 规则文件 | 规则数量 | 所在目录 | 下载链接 |\n| :--- | :--- | :--- | :--- |\n"
    table_rows = ""
    for item in all_file_stats:
        safe_name = item['name'].replace(" ", "%20").replace("&", "%26")
        download_url = f"[点击下载]({raw_base}/{item['folder']}/{safe_name})"
        table_rows += f"| {item['name']} | {item['count']} | {item['folder']} | {download_url} |\n"
    
    table_content = f"{table_header}{table_rows}\n⏰ 最后更新: {now}\n"
    
    # 精准替换 ## 规则统计 下的内容
    pattern = r"(## 规则统计[\s\S]*?)(?=## |$)"
    new_content = re.sub(pattern, f"## 规则统计\n\n{table_content}\n", content)
    readme_path.write_text(new_content, encoding='utf-8')

def main():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}
    
    # 1. 先读 custom-rules 进总库
    c_path = Path('custom-rules')
    if c_path.exists():
        for f in c_path.glob('*.txt'):
            with open(f, 'r', encoding='utf-8') as file:
                for line in file:
                    rtype, rule = resolver.resolve(line)
                    if rtype: collections[rtype].add(rule)

    # 2. 读远程 sources.txt 进总库
    if os.path.exists('sources.txt'):
        with open('sources.txt', 'r', encoding='utf-8') as f:
            urls = [l.strip() for l in f if l.strip().startswith('http')]
        session = requests.Session()
        for url in urls:
            try:
                lines = session.get(url, timeout=10).text.splitlines()
                for line in lines:
                    rtype, rule = resolver.resolve(line)
                    if rtype: collections[rtype].add(rule)
            except: pass

    # 3. 写入 dist 文件夹
    dist_dir = Path('dist')
    dist_dir.mkdir(exist_ok=True)
    for name, rules in collections.items():
        sorted_rules = sorted(list(rules))
        (dist_dir / f"{name}.txt").write_text(f"! Total: {len(sorted_rules)}\n\n" + "\n".join(sorted_rules), encoding='utf-8')

    # 4. 【核心需求】扫描两个文件夹并更新表格
    all_stats = get_file_stats('custom-rules') + get_file_stats('dist')
    update_readme(all_stats)
    print("规则统计已自动同步至 README 表格！")

if __name__ == "__main__":
    main()