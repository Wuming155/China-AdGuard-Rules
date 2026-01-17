import requests
import re
import os
from datetime import datetime
from readme_generator import update_readme

class RuleResolver:
    def resolve(self, line):
        line = line.strip()
        if not line or (line.startswith('!') and not line.startswith('!!')) or (line.startswith('#') and not (line.startswith('##') or line.startswith('#%#'))):
            return None, None
        if line.startswith('@@'):
            return 'whitelist', line
        # 严格分类：语法规则必须包含 ||, *, ^, $, ## 等
        if any(x in line for x in ['||', '*', '^', '$', '##', '#%#']):
            if not re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)', line):
                return 'adguard_rules', line
        # Hosts 提取：只留 0.0.0.0 和 域名，剔除后缀注释
        host_re = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\.\_]+)', line)
        if host_re:
            domain = host_re.group(1).strip()
            if domain not in ['localhost', 'localhost.localdomain']:
                return 'hosts_rules', f"0.0.0.0 {domain}"
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            return 'hosts_rules', f"0.0.0.0 {line}"
        return None, None

def run():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip().startswith('http')]

    for url in urls:
        try:
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    rtype, rule = resolver.resolve(line)
                    if rtype: collections[rtype].add(rule)
        except: continue

    stats = {}
    os.makedirs('dist', exist_ok=True)
    date_str = datetime.now().strftime('%Y年%m月%d日')
    for name, rules in collections.items():
        sorted_rules = sorted(list(rules))
        stats[name] = len(sorted_rules)
        with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
            title = {'hosts_rules':'Hosts 屏蔽规则','adguard_rules':'AdGuard 过滤规则','whitelist':'白名单放行规则'}[name]
            f.write(f"#更新日期：{date_str}\n#规则数：{len(sorted_rules)}\n! Title: {title}\n\n")
            f.write("\n".join(sorted_rules))
    
    # 调用专门的更新函数
    update_readme(stats)

if __name__ == "__main__":
    run()