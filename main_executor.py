import requests
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

# 配置
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY', 'Wuming155/China-AdGuard-Rules')
MAX_WORKERS = 10  # 并发线程数
TIMEOUT = 15      # 超时时间（秒）

class RuleResolver:
    """分类解析器：确保 AdGuard 语法规则和 Hosts 域名规则各归各位"""
    def __init__(self):
        # 预编译正则以提高性能
        self.host_pattern = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\.\_]+)')
        self.domain_pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$')

    def resolve(self, line):
        line = line.strip()
        
        # 排除空行及普通注释
        if not line or (line.startswith('!') and not line.startswith('!!')) or \
           (line.startswith('#') and not (line.startswith('##') or line.startswith('#%#'))):
            return None, None
        
        # 1. 处理白名单
        if line.startswith('@@'):
            return 'whitelist', line
            
        # 2. 处理 AdGuard 语法类
        if any(x in line for x in ['||', '*', '^', '$', '##', '#%#']):
            if not re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)', line):
                return 'adguard_rules', line

        # 3. 处理 Hosts 格式
        host_match = self.host_pattern.match(line)
        if host_match:
            domain = host_match.group(1).strip().lower()
            if domain not in ['localhost', 'localhost.localdomain']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 4. 纯域名格式补全
        if self.domain_pattern.match(line):
            return 'hosts_rules', f"0.0.0.0 {line.lower()}"

        return None, None

def get_session():
    """创建带有重试机制的请求会话"""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def fetch_url(url, session):
    """抓取单个 URL 内容"""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        resp = session.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.text.splitlines()
        print(f"[!] 跳过 (状态码 {resp.status_code}): {url}")
    except Exception as e:
        print(f"[X] 抓取失败 {url}: {str(e)}")
    return []

def update_readme(stats):
    """覆盖式更新 README 中的统计表"""
    if not os.path.exists('README.md'):
        return
        
    with open('README.md', 'r', encoding='utf-8') as f:
        content = f.read()

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
    # 查找 ## 规则统计 标记
    pattern = r"(## 规则统计[\s\S]*?)(?=## |$)"
    header_mark = "## 规则统计"
    
    if re.search(pattern, content):
        new_content = re.sub(pattern, f"{header_mark}\n{table_content}\n", content)
    else:
        # 如果没找到标记，则追加到末尾
        new_content = content + f"\n\n{header_mark}\n{table_content}"

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)

def run():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}
    
    if not os.path.exists('sources.txt'):
        print("错误: 缺少 sources.txt")
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip().startswith('http')]

    print(f"开始同步，共 {len(urls)} 个源...")
    
    session = get_session()
    
    # 使用线程池并发抓取
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(fetch_url, url, session): url for url in urls}
        
        for future in as_completed(future_to_url):
            lines = future.result()
            for line in lines:
                rtype, rule = resolver.resolve(line)
                if rtype:
                    collections[rtype].add(rule)

    # 生成文件
    os.makedirs('dist', exist_ok=True)
    stats = {}
    header_date = datetime.now().strftime('%Y年%m月%d日 %H:%M')
    title_map = {'hosts_rules': 'Hosts 屏蔽', 'adguard_rules': 'AdGuard 语法', 'whitelist': '白名单'}
    
    for name in ['hosts_rules', 'adguard_rules', 'whitelist']:
        sorted_rules = sorted(list(collections[name]))
        stats[name] = len(sorted_rules)
        
        file_path = f'dist/{name}.txt'
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"! Title: {title_map[name]}\n")
            f.write(f"! Updated: {header_date}\n")
            f.write(f"! Count: {len(sorted_rules)}\n")
            f.write(f"! Repo: https://github.com/{GITHUB_REPO}\n\n")
            f.write("\n".join(sorted_rules))
        print(f"已生成: {file_path} (共 {len(sorted_rules)} 条)")
    
    update_readme(stats)
    print("README 统计更新完成")

if __name__ == "__main__":
    run()