import requests
import re
import os
from datetime import datetime

# 自动获取当前运行的仓库路径
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY', 'Wuming155/China-AdGuard-Rules')

class RuleResolver:
    """深度解析：确保 AdGuard 语法规则和 Hosts 域名规则互不干扰"""
    def resolve(self, line):
        line = line.strip()
        if not line or (line.startswith('!') and not line.startswith('!!')) or (line.startswith('#') and not (line.startswith('##') or line.startswith('#%#'))):
            return None, None
        
        # 1. 处理白名单
        if line.startswith('@@'):
            return 'whitelist', line
            
        # 2. 处理语法类 (||, *, ^, $, ##)
        if any(x in line for x in ['||', '*', '^', '$', '##', '#%#']):
            if not re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)', line):
                return 'adguard_rules', line

        # 3. 处理 Hosts/域名类 (提取纯域名)
        host_re = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\.\_]+)', line)
        if host_re:
            domain = host_re.group(1).strip()
            if domain not in ['localhost', 'localhost.localdomain']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 4. 纯域名补全格式
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            return 'hosts_rules', f"0.0.0.0 {line}"

        return None, None

def update_readme(stats):
    """精准定位 并替换统计表"""
    if not os.path.exists('README.md'): return
    with open('README.md', 'r', encoding='utf-8') as f:
        content = f.read()

    raw_base = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/dist"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    table = f"""
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| AdGuard 语法 | {stats.get('adguard_rules', 0)} | [点击下载]({raw_base}/adguard_rules.txt) |
| Hosts 屏蔽 | {stats.get('hosts_rules', 0)} | [点击下载]({raw_base}/hosts_rules.txt) |
| 白名单放行 | {stats.get('whitelist', 0)} | [点击下载]({raw_base}/whitelist.txt) |

⏰ 最后更新: {now}
"""
    # 替换 和 之间的内容
    pattern = r".*?"
    replacement = f"\n{table}\n"
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)

def run():
    resolver = RuleResolver()
    col = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}
    
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip().startswith('http')]

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    rtype, rule = resolver.resolve(line)
                    if rtype: col[rtype].add(rule)
        except: continue

    os.makedirs('dist', exist_ok=True)
    stats = {}
    header_date = datetime.now().strftime('%Y年%m月%d日')
    
    for name in ['hosts_rules', 'adguard_rules', 'whitelist']:
        sorted_list = sorted(list(col[name]))
        stats[name] = len(sorted_list)
        with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
            f.write(f"#更新日期：{header_date}\n#条数：{len(sorted_list)}\n\n")
            f.write("\n".join(sorted_list))
    
    update_readme(stats)

if __name__ == "__main__":
    run()
