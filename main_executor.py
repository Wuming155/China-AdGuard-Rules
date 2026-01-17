import requests
import re
import os
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
from pathlib import Path

# 配置信息
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY', 'Wuming155/China-AdGuard-Rules')

class RuleResolver:
    def __init__(self):
        # 匹配以 0.0.0.0 或 127.0.0.1 开头的行，提取空格后的第一个非空格字符串
        self.host_pattern = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)')
        # 匹配合法域名的基础正则
        self.domain_pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$')

    def is_ip(self, value):
        """判断字符串是否为 IP 地址（IPv4 或 IPv6）"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def resolve(self, line):
        line = line.strip()
        # 1. 排除空行、注释行（但保留 AdGuard 特殊规则前缀）
        if not line or (line.startswith('!') and not line.startswith('!!')) or \
           (line.startswith('#') and not (line.startswith('##') or line.startswith('#%#'))):
            return None, None
        
        # 2. 处理白名单
        if line.startswith('@@'): 
            return 'whitelist', line
            
        # 3. 处理 AdGuard 特色语法 (包含 ||, *, ^ 等符号)
        if any(x in line for x in ['||', '*', '^', '$', '##', '#%#']):
            # 排除掉那些只是简单 hosts 格式但包含特殊字符的行
            if not re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)', line): 
                return 'adguard_rules', line

        # 4. 处理 Hosts 格式规则 (0.0.0.0 domain.com)
        host_match = self.host_pattern.match(line)
        if host_match:
            target = host_match.group(1).strip().lower()
            # 核心过滤：目标不能是 localhost 且 不能是 IP 地址
            if target not in ['localhost', 'localhost.localdomain'] and not self.is_ip(target):
                return 'hosts_rules', f"0.0.0.0 {target}"
            return None, None

        # 5. 处理纯域名格式行
        if self.domain_pattern.match(line):
            domain = line.lower()
            # 核心过滤：确保该域名字符串本身不是一个 IP 地址
            if not self.is_ip(domain):
                return 'hosts_rules', f"0.0.0.0 {domain}"
        
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
                    if line.strip() and not line.startswith(('!', '#')):
                        count += 1
            stats_list.append({'name': f.name, 'count': count, 'folder': folder_path})
    return stats_list

def update_readme(all_file_stats):
    """更新 README.md 中的统计表格"""
    readme_path = Path('README.md')
    if not readme_path.exists(): return
    content = readme_path.read_text(encoding='utf-8')

    raw_base = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    table_header = "| 规则文件 | 规则数量 | 下载链接 |\n| :--- | :--- | :--- |\n"
    table_rows = ""
    for item in all_file_stats:
        safe_name = item['name'].replace(" ", "%20").replace("&", "%26")
        download_url = f"[点击下载]({raw_base}/{item['folder']}/{safe_name})"
        table_rows += f"| {item['name']} | {item['count']} | {download_url} |\n"
    
    table_content = f"{table_header}{table_rows}\n⏰ 最后更新: {now}\n"
    
    pattern = r"(## 规则统计[\s\S]*?)(?=## |$)"
    new_content = re.sub(pattern, f"## 规则统计\n\n{table_content}\n", content)
    readme_path.write_text(new_content, encoding='utf-8')

def main():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}
    
    # 1. 读取本地自定义规则
    c_path = Path('custom-rules')
    if c_path.exists():
        for f in c_path.glob('*.txt'):
            with open(f, 'r', encoding='utf-8') as file:
                for line in file:
                    rtype, rule = resolver.resolve(line)
                    if rtype: collections[rtype].add(rule)

    # 2. 读取远程订阅源
    if os.path.exists('sources.txt'):
        with open('sources.txt', 'r', encoding='utf-8') as f:
            urls = [l.strip() for l in f if l.strip().startswith('http')]
        
        session = requests.Session()
        # 设置简单的重试机制
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        for url in urls:
            try:
                response = session.get(url, timeout=15)
                if response.status_code == 200:
                    lines = response.text.splitlines()
                    for line in lines:
                        rtype, rule = resolver.resolve(line)
                        if rtype: collections[rtype].add(rule)
            except Exception as e:
                print(f"Error fetching {url}: {e}")

    # 3. 写入 dist 文件夹
    dist_dir = Path('dist')
    dist_dir.mkdir(exist_ok=True)
    update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    for name, rules in collections.items():
        sorted_rules = sorted(list(rules))
        header = [
            f"! Title: {name.replace('_', ' ').title()}",
            f"! Homepage: https://github.com/{GITHUB_REPO}",
            f"! Total Rules: {len(sorted_rules)}",
            f"! Last Update: {update_time}",
            "!\n"
        ]
        file_content = "\n".join(header) + "\n".join(sorted_rules)
        (dist_dir / f"{name}.txt").write_text(file_content, encoding='utf-8')

    # 4. 扫描并更新 README 统计
    all_stats = get_file_stats('custom-rules') + get_file_stats('dist')
    update_readme(all_stats)
    print("所有无效 IP 规则已过滤，统计已同步至 README！")

if __name__ == "__main__":
    main()