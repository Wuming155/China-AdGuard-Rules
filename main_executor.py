import requests
import re
import os
from datetime import datetime
import time

def get_file_header(name, count):
    # 按照要求设置日期格式：2026年01月17日
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

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    for url in urls:
        print(f"正在尝试同步: {url}")
        success = False
        for i in range(3): # 失败重试3次
            try:
                r = requests.get(url, headers=headers, timeout=30)
                if r.status_code == 200:
                    content = r.text
                    lines = content.splitlines()
                    print(f"成功获取 {len(lines)} 行数据")
                    
                    for line in lines:
                        line = line.strip()
                        # 1. 基础过滤：跳过空行
                        if not line: continue
                        
                        # 2. 识别白名单
                        if line.startswith('@@'):
                            collections['whitelist'].add(line)
                            continue
                            
                        # 3. 识别注释行：如果以 ! 或 # 开头，且不是高级规则，则跳过
                        if (line.startswith('!') or line.startswith('#')) and not (line.startswith('##') or line.startswith('#%#')):
                            continue

                        # 4. 识别 AdGuard/Adblock 语法 (核心逻辑)
                        # 只要包含以下特征，一律进入 adguard_rules
                        if any(x in line for x in ['||', '*', '^', '$', '##', '#%#', ':', '/']):
                            collections['adguard_rules'].add(line)
                        
                        # 5. 识别 Hosts 格式
                        elif re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+', line):
                            domain_part = re.split(r'\s+', line)
                            if len(domain_part) > 1:
                                domain = domain_part[1]
                                if domain not in ['localhost', 'localhost.localdomain']:
                                    collections['hosts_rules'].add(f"0.0.0.0 {domain}")
                        
                        # 6. 纯域名格式
                        elif re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
                            collections['hosts_rules'].add(f"0.0.0.0 {line}")
                    
                    success = True
                    break
            except Exception as e:
                print(f"第 {i+1} 次尝试失败: {e}")
                time.sleep(2)
        
        if not success:
            print(f"!!! 无法同步该源: {url}")

    # 导出文件
    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules:
            sorted_rules = sorted(list(rules))
            with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
                f.write(get_file_header(name, len(sorted_rules)))
                f.write("\n".join(sorted_rules))
            print(f"文件已生成: {name}.txt, 规则数: {len(rules)}")

if __name__ == "__main__":
    run()
