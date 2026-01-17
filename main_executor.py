import requests
import re
import os
from datetime import datetime
import urllib3
from concurrent.futures import ThreadPoolExecutor

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RuleResolver:
    def __init__(self):
        # 参考 resolver.py 的 Adblock 选项特征，用于精准识别过滤规则
        self.ad_features = {
            'script', 'image', 'stylesheet', 'domain', 'third-party', 
            'xmlhttprequest', 'popup', 'subdocument'
        }

    def resolve(self, line):
        line = line.strip()
        
        # 1. 严格过滤注释和干扰项 (保留规则行中的 #)
        if not line or (line.startswith('!') and not line.startswith('!!')):
            return None, None
        if line.startswith('# ') or line == '#':
            return None, None

        # 2. 白名单：@@ 开头
        if line.startswith('@@'):
            return 'whitelist', line

        # 3. AdGuard/CSS 化妆规则 (全面兼容您提到的 ###, ##.sth, [style^=] 等)
        # 即使 DNS 无法解析，CSS 隐藏规则依然在浏览器端生效，绝对不能过滤
        if '##' in line or line.startswith('###') or '#%#' in line or '#$#' in line or '#@#' in line:
            return 'adguard_rules', line
        
        # 4. 网络拦截规则：||example.com^ 等
        if line.startswith('||') or line.startswith('|') or ('^' in line and '$' in line):
            return 'adguard_rules', line

        # 5. Hosts 屏蔽规则 (拦截型：0.0.0.0 / 127.0.0.1)
        # 剔除 github 加速等映射 IP，只保留 0/127 拦截格式
        host_re = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\._]+)', line)
        if host_re:
            domain = host_re.group(2).strip()
            if domain not in ['localhost', 'localhost.localdomain', 'ip6-localhost']:
                # 哪怕这个域名现在解析不通，只要它是拦截格式，就保留
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 6. 纯域名行判定
        # 只要符合域名格式且不是 CSS 选择器，就直接视为 Hosts 拦截规则
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            if not any(c in line for c in ['#', '[', '>', '*', ' ', ':']):
                return 'hosts_rules', f"0.0.0.0 {line}"

        return None, None

def get_file_header(name, count):
    date_str = datetime.now().strftime('%Y年%m月%d日')
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则 (包含已失效域名)',
        'adguard_rules': 'AdGuard 过滤规则 (CSS/网络拦截)',
        'whitelist': '白名单放行规则'
    }
    return f"# 更新日期：{date_str}\n# 规则总数：{count}\n! Title: {title_map.get(name, '规则库')}\n! Description: none\n! ------------------------------------\n\n"

def fetch_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    try:
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        if r.status_code == 200:
            r.encoding = 'utf-8'
            return r.text.splitlines()
    except Exception as e:
        print(f"Fetch Error: {url} -> {e}")
    return []

def run():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}

    if not os.path.exists('sources.txt'):
        print("Error: sources.txt not found")
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\]]+', f.read())

    # 参考 adblock.py 的并发思想，提高 Actions 执行效率
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(fetch_url, urls)

    for lines in results:
        for line in lines:
            rtype, rule = resolver.resolve(line)
            if rtype:
                collections[rtype].add(rule)

    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules:
            sorted_rules = sorted(list(rules))
            with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
                f.write(get_file_header(name, len(sorted_rules)))
                f.write("\n".join(sorted_rules))
            print(f"Generated: {name}.txt ({len(sorted_rules)} lines)")

if __name__ == "__main__":
    run()
