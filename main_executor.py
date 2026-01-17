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
        # 常见 Adblock 选项，参考 resolver.py 的思想
        self.adblock_options = {'script', 'image', 'stylesheet', 'domain', 'third-party', 'xmlhttprequest'}

    def resolve(self, line):
        line = line.strip()
        
        # 1. 过滤无效行与基础注释
        # 注意：排除类似 ## 或 ### 开头的规则行（它们不是注释）
        if not line or (line.startswith('!') and not line.startswith('!!')):
            return None, None
        if line.startswith('# ') or line == '#':
            return None, None

        # 2. 白名单规则判定
        if line.startswith('@@'):
            return 'whitelist', line

        # 3. AdGuard 化妆规则与 CSS 屏蔽 (重点支持您的需求)
        # 捕获：###id, ##.class, domain##.selector, ##a[href*="..."], ##.sth > .col-red
        if '##' in line or line.startswith('###') or '#%#' in line or '#$#' in line or '#@#' in line:
            return 'adguard_rules', line
        
        # 4. AdGuard 网络拦截规则
        # 捕获：||example.com^, |http://example.com/ad.js|
        if line.startswith('||') or line.startswith('|') or ('^' in line and '$' in line):
            return 'adguard_rules', line

        # 5. Hosts 屏蔽规则 (严格限定拦截模式)
        # 逻辑：只接受 0.0.0.0 或 127.0.0.1，剔除 GitHub 加速等映射规则
        host_re = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\._]+)', line)
        if host_re:
            domain = host_re.group(2).strip()
            # 排除本地回环
            if domain not in ['localhost', 'localhost.localdomain', 'ip6-localhost']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 6. 纯域名行判定
        # 逻辑：如果是纯域名且没有 CSS 特征，自动归类为拦截 Hosts
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            # 排除掉包含 CSS 符号的行，防止误杀
            if not any(c in line for c in ['#', '[', '>', '*', ' ', ':']):
                return 'hosts_rules', f"0.0.0.0 {line}"

        return None, None

def get_file_header(name, count):
    date_str = datetime.now().strftime('%Y年%m月%d日')
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则',
        'adguard_rules': 'AdGuard 过滤规则',
        'whitelist': '白名单放行规则'
    }
    return f"# 更新日期：{date_str}\n# 规则数：{count}\n! Title: {title_map.get(name, '规则库')}\n! ------------------------------------\n\n"

def fetch_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*'
    }
    try:
        # 增加了 verify=False 解决部分源证书问题
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        if r.status_code == 200:
            r.encoding = 'utf-8'
            return r.text.splitlines()
    except Exception as e:
        print(f"无法获取 {url}: {e}")
    return []

def run():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}

    if not os.path.exists('sources.txt'):
        print("未找到 sources.txt")
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\]]+', f.read())

    # 使用线程池并发下载，提高 GitHub Action 执行效率
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_url, urls)

    for lines in results:
        for line in lines:
            rtype, rule = resolver.resolve(line)
            if rtype:
                collections[rtype].add(rule)

    # 写入结果
    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules:
            sorted_rules = sorted(list(rules))
            save_path = f'dist/{name}.txt'
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(get_file_header(name, len(sorted_rules)))
                f.write("\n".join(sorted_rules))
            print(f"成功生成: {save_path}, 条数: {len(sorted_rules)}")

if __name__ == "__main__":
    run()
