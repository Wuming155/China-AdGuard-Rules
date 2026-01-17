import requests
import re
import os
from datetime import datetime

def get_file_header(name, count):
    date_str = datetime.now().strftime('%y%m%d')
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则',
        'adblock_rules': 'Adblock 静态规则',
        'adguard_rules': 'AdGuard 高级规则',
        'whitelist': '白名单规则'
    }
    display_title = title_map.get(name, '去广告规则')
    return f"#更新日期：{date_str}\n#规则数：{count}\n! Title: {display_title}\n! ------------------------------------\n\n"

def run():
    # 严格分类容器
    collections = {
        'hosts_rules': set(),
        'adblock_rules': set(),
        'adguard_rules': set(),
        'whitelist': set()
    }

    if not os.path.exists('sources.txt'):
        print("Error: sources.txt not found")
        return
        
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.strip().startswith('http')]

    for url in urls:
        print(f"正在处理源: {url}")
        try:
            r = requests.get(url, timeout=15)
            for line in r.text.splitlines():
                line = line.strip()
                
                # 排除空行和纯注释
                if not line or line.startswith('!') or (line.startswith('#') and not line.startswith('##')):
                    continue

                # --- 1. 绝对优先：白名单 ---
                if line.startswith('@@'):
                    collections['whitelist'].add(line)
                    continue

                # --- 2. 绝对隔离：AdGuard 高级规则 ---
                # 只要含有这些特殊符号，就判定为高级规则，不进入 Adblock
                if '##' in line or '#%#' in line or '#$#' in line or '$' in line:
                    collections['adguard_rules'].add(line)
                    continue

                # --- 3. 绝对隔离：标准 Adblock 规则 ---
                # 此时已排除了带 $ 的高级规则，只保留纯粹的 ||domain^
                if line.startswith('||'):
                    collections['adblock_rules'].add(line)
                    continue

                # --- 4. 绝对隔离：Hosts 规则 ---
                # 匹配 127/0.0.0.0 格式，统一转为 0.0.0.0
                host_match = re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+([a-zA-Z0-9\-\.\_]+)', line)
                if host_match:
                    domain = host_match.group(1)
                    if domain not in ['localhost', 'localhost.localdomain']:
                        collections['hosts_rules'].add(f"0.0.0.0 {domain}")
                    continue
                
                # 5. 如果是纯域名行，也归入 Hosts
                if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
                    collections['hosts_rules'].add(f"0.0.0.0 {line}")

        except Exception as e:
            print(f"无法读取 {url}: {e}")

    # 导出文件
    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules:
            sorted_rules = sorted(list(rules))
            with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
                f.write(get_file_header(name, len(sorted_rules)))
                f.write("\n".join(sorted_rules))

if __name__ == "__main__":
    run()
