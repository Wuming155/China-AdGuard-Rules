import requests
import re
import os
from datetime import datetime
import urllib3
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RuleResolver:
    def __init__(self):
        # 扩展特征库，参考 resolver.py 逻辑
        self.adblock_features = {
            '##', '###', '#%#', '#$#', '#@#', '||', '@@', '^', '$', '[', '>', '*'
        }

    def resolve(self, line):
        line = line.strip()
        
        # 1. 彻底排除：空行和纯注释
        # 特别注意：! 开头是注释，但 !! 可能在某些规则中有意义，不过通常作为注释处理
        if not line or (line.startswith('!') and not line.startswith('!!')):
            return None, None
        # 只有 # 后面紧跟空格才视为注释，避免误杀 ### 规则
        if line.startswith('# ') or line == '#':
            return None, None

        # 2. 判定白名单：@@ 开头
        if line.startswith('@@'):
            return 'whitelist', line

        # 3. 判定 AdGuard / CSS 过滤规则 (核心修复点)
        # 只要包含 ##, ### 或特殊的 AdGuard 语法特征，统一归为 adguard_rules
        if any(feat in line for feat in ['##', '###', '#%#', '#$#', '#@#']):
            return 'adguard_rules', line
        
        # 判定网络规则：以 || 开头，或者包含通配符和位置符
        if line.startswith('||') or line.startswith('|') or ('^' in line) or ('$' in line and ',' in line):
            return 'adguard_rules', line

        # 4. 判定拦截型 Hosts
        # 严格执行：仅限 0.0.0.0 和 127.0.0.1
        host_match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\._]+)', line)
        if host_match:
            domain = host_match.group(2).strip()
            if domain not in ['localhost', 'localhost.localdomain', 'ip6-localhost']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 5. 纯域名行判定 (作为 Hosts 补充)
        # 排除所有带选择器特征符号的行，剩下的纯域名视为拦截
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            if not any(c in line for c in ['#', '[', '>', '*', ' ', ':', '/', '@']):
                return 'hosts_rules', f"0.0.0.0 {line}"
        
        # 6. 兜底判定 (非常重要)：
        # 如果一行规则包含 "." (域名特征) 且包含 CSS 常用符号（如 .class 或 #id），
        # 但没被上面捕捉到，也归入 adguard_rules
        if '.' in line and ('#' in line or '[' in line or '>' in line):
            return 'adguard_rules', line

        return None, None

def get_file_header(name, count):
    date_str = datetime.now().strftime('%Y年%m月%d日')
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则 (Strict)',
        'adguard_rules': 'AdGuard 过滤规则 (Advanced)',
        'whitelist': '白名单放行规则'
    }
    return f"# 更新日期：{date_str}\n# 规则总数：{count}\n! Title: {title_map.get(name)}\n! ------------------------------------\n\n"

def fetch_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    }
    try:
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        if r.status_code == 200:
            r.encoding = 'utf-8'
            return r.text.splitlines()
        print(f"跳过失效源 ({r.status_code}): {url}")
    except Exception as e:
        print(f"连接失败: {url} -> {e}")
    return []

def run():
    resolver = RuleResolver()
    # 使用 dict 结构确保分类
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}

    if not os.path.exists('sources.txt'):
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        # 正则提取所有 URL，兼容 sources.txt 里的各种标注
        urls = re.findall(r'https?://[^\s\]]+', f.read())

    # 线程池并发执行
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_url, urls)

    for lines in results:
        for line in lines:
            rtype, rule = resolver.resolve(line)
            if rtype:
                collections[rtype].add(rule)

    os.makedirs('dist', exist_ok=True)
    for name in ['hosts_rules', 'adguard_rules', 'whitelist']:
        rules = collections[name]
        # 即使 rules 为空，也建议生成一个带头部的空文件，防止后续脚本读取报错
        sorted_rules = sorted(list(rules))
        with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
            f.write(get_file_header(name, len(sorted_rules)))
            if sorted_rules:
                f.write("\n".join(sorted_rules))
        print(f"保存成功: {name}.txt, 条数: {len(sorted_rules)}")

if __name__ == "__main__":
    run()
