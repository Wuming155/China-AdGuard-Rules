import requests
import re
import os
from datetime import datetime

def get_file_header(name, count):
    date_str = datetime.now().strftime('%y%m%d')
    # 重新定义三类标题
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则',
        'adguard_rules': 'AdGuard 过滤规则',
        'whitelist': '白名单放行规则'
    }
    display_title = title_map.get(name, '去广告规则')
    return f"#更新日期：{date_str}\n#规则数：{count}\n! Title: {display_title}\n\n"

def run():
    # 严格分为三类
    collections = {
        'hosts_rules': set(),    # 纯域名类 (0.0.0.0)
        'whitelist': set(),      # 白名单类 (@@)
        'adguard_rules': set()   # 语法类 (||, ##, $, 等)
    }

    if not os.path.exists('sources.txt'):
        print("错误: 找不到 sources.txt")
        return
        
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.strip().startswith('http')]

    for url in urls:
        print(f"正在处理: {url}")
        try:
            r = requests.get(url, timeout=15)
            for line in r.text.splitlines():
                line = line.strip()
                
                # 过滤掉空行和纯注释
                if not line or line.startswith('!') or (line.startswith('#') and not line.startswith('##')):
                    continue

                # 1. 分类逻辑：白名单
                if line.startswith('@@'):
                    collections['whitelist'].add(line)
                    continue

                # 2. 分类逻辑：AdGuard/语法类 (包含你举例的 || 开头的规则)
                # 只要是 || 开头，或者含有 ##, #%#, $ 符号的，全进这一类
                if line.startswith('||') or '##' in line or '#%#' in line or '$' in line:
                    collections['adguard_rules'].add(line)
                    continue

                # 3. 分类逻辑：Hosts 域名类
                host_match = re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+([a-zA-Z0-9\-\.\_]+)', line)
                if host_match:
                    domain = host_match.group(1)
                    if domain not in ['localhost', 'localhost.localdomain']:
                        collections['hosts_rules'].add(f"0.0.0.0 {domain}")
                    continue
                
                # 如果是纯域名行，也归入 Hosts
                if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
                    collections['hosts_rules'].add(f"0.0.0.0 {line}")

        except Exception as e:
            print(f"请求失败: {url} -> {e}")

    # 导出文件
    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules: # 只有当该类别有规则时才生成文件
            sorted_rules = sorted(list(rules))
            with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
                f.write(get_file_header(name, len(sorted_rules)))
                f.write("\n".join(sorted_rules))

if __name__ == "__main__":
    run()
