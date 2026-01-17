import requests
import re
import os
from datetime import datetime

class RuleResolver:
    """参考 217heidai 的 Resolver 逻辑，对规则进行深度解析"""
    def __init__(self):
        # 常见 Adblock 选项，用于辅助判定 AdGuard 规则
        self.options = {'script', 'image', 'stylesheet', 'ad', 'subdocument', 'xmlhttprequest', 'domain'}

    def resolve(self, line):
        line = line.strip()
        if not line or (line.startswith('!') and not line.startswith('!!')) or (line.startswith('#') and not line.startswith('##')):
            return None, None

        # 1. 判定白名单
        if line.startswith('@@'):
            return 'whitelist', line

        # 2. 判定 AdGuard/Adblock 语法规则
        # 逻辑：包含 || 且有 ^ 或 $；或者包含通配符 *；或者包含元素隐藏 ##
        if (line.startswith('||') and ('^' in line or '$' in line)) or \
           ('*' in line) or ('##' in line) or ('#%#' in line):
            return 'adguard_rules', line

        # 3. 判定 Hosts 规则
        # 逻辑：匹配 0.0.0.0 或 127.0.0.1 开头的行，并提取纯域名部分，剔除尾部注释
        host_re = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\.\_]+)', line)
        if host_re:
            domain = host_re.group(1).strip()
            if domain not in ['localhost', 'localhost.localdomain']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 4. 判定纯域名行，自动补齐为 Hosts 格式
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            return 'hosts_rules', f"0.0.0.0 {line}"

        return None, None

def get_file_header(name, count):
    # 严格按照你要求的日期格式
    date_str = datetime.now().strftime('%Y年%m月%d日')
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则',
        'adguard_rules': 'AdGuard 过滤规则',
        'whitelist': '白名单放行规则'
    }
    return f"#更新日期：{date_str}\n#规则数：{count}\n! Title: {title_map.get(name, '去广告规则')}\n! ------------------------------------\n\n"

def run():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}

    if not os.path.exists('sources.txt'):
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip().startswith('http')]

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code != 200: continue
            
            for line in r.text.splitlines():
                rtype, rule = resolver.resolve(line)
                if rtype:
                    collections[rtype].add(rule)
        except:
            continue

    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules:
            sorted_rules = sorted(list(rules))
            with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
                f.write(get_file_header(name, len(sorted_rules)))
                f.write("\n".join(sorted_rules))

if __name__ == "__main__":
    run()
