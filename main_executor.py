import requests
import re
import os
from datetime import datetime

def get_file_header(name, count):
    # 按照你的要求设置日期格式：2026年01月17日
    date_str = datetime.now().strftime('%Y年%m月%d日')
    
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则',
        'adguard_rules': 'AdGuard 过滤规则',
        'whitelist': '白名单放行规则'
    }
    display_title = title_map.get(name, '去广告规则')
    
    return f"#更新日期：{date_str}\n#规则数：{count}\n! Title: {display_title}\n! ------------------------------------\n\n"

def run():
    collections = {
        'hosts_rules': set(),    
        'whitelist': set(),      
        'adguard_rules': set()   
    }

    if not os.path.exists('sources.txt'):
        print("错误: 找不到 sources.txt")
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip().startswith('http')]

    for url in urls:
        print(f"正在处理同步: {url}")
        try:
            # 增加 User-Agent 伪装浏览器，防止部分源拒绝抓取
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code != 200:
                print(f"跳过源 (状态码 {r.status_code}): {url}")
                continue

            for line in r.text.splitlines():
                line = line.strip()
                
                # 1. 过滤掉纯注释行（不含规则的行）
                if not line or (line.startswith('!') and not line.startswith('!!')) or (line.startswith('#') and not line.startswith('##')):
                    continue

                # 2. 分类：白名单
                if line.startswith('@@'):
                    collections['whitelist'].add(line)
                    continue

                # 3. 分类：AdGuard/语法类 (针对你提供的 *-ad.sm.cn* 等复杂规则)
                # 只要包含特殊匹配符，就归为这一类
                special_chars = ['||', '*', '^', '$', '##', '#%#', '#$#', '[', ']']
                if any(char in line for char in special_chars):
                    collections['adguard_rules'].add(line)
                    continue

                # 4. 分类：Hosts 域名类 (转化 127/0 为 0.0.0.0)
                host_match = re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+([a-zA-Z0-9\-\.\_]+)', line)
                if host_match:
                    domain = host_match.group(1)
                    if domain not in ['localhost', 'localhost.localdomain']:
                        collections['hosts_rules'].add(f"0.0.0.0 {domain}")
                    continue
                
                # 5. 纯域名行
                if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
                    collections['hosts_rules'].add(f"0.0.0.0 {line}")

        except Exception as e:
            print(f"读取源失败: {url} -> {e}")

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
