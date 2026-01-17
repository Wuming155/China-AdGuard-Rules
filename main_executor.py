import requests
import re
import os

def run():
    # 准备分类容器
    collections = {
        'hosts_rules': set(),    # 仅保留标准 0.0.0.0 屏蔽规则
        'adblock_rules': set(),  # 标准语法
        'adguard_rules': set(),  # 高级修饰符
        'whitelist': set()       # 白名单
    }

    if not os.path.exists('sources.txt'):
        print("Error: sources.txt 不存在")
        return
        
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.strip().startswith('http')]

    for url in urls:
        print(f"正在抓取: {url}")
        try:
            r = requests.get(url, timeout=15)
            for line in r.text.splitlines():
                line = line.strip()
                
                # 跳过空行
                if not line:
                    continue

                # --- 1. 处理白名单 (优先级最高) ---
                if line.startswith('@@'):
                    collections['whitelist'].add(line)
                    continue

                # --- 2. 处理 Hosts 规则 (严格过滤模式) ---
                # 只匹配以 127.0.0.1 或 0.0.0.0 开头的行
                # 排除注释行，且不保留原始 IP，统一转为 0.0.0.0
                host_match = re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+([a-zA-Z0-9\-\.\_]+)', line)
                if host_match:
                    domain = host_match.group(1)
                    # 排除掉 localhost 等本地环回地址，只保留广告域名
                    if domain not in ['localhost', 'localhost.localdomain', 'broadcasthost']:
                        collections['hosts_rules'].add(f"0.0.0.0 {domain}")
                    continue

                # --- 3. 处理 AdGuard/Adblock (跳过所有以 # 或 ! 开头的注释) ---
                if line.startswith('!') or line.startswith('#'):
                    continue

                if '##' in line or '#%#' in line or '$' in line:
                    collections['adguard_rules'].add(line)
                elif line.startswith('||'):
                    collections['adblock_rules'].add(line)
        except Exception as e:
            print(f"访问失败 {url}: {e}")

    # 3. 导出到 dist 文件夹
    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules:
            with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
                # 写入简单的文件头
                f.write(f"! Name: My Classified {name}\n")
                f.write(f"! Total lines: {len(rules)}\n")
                f.write("! ------------------------------------\n\n")
                # 排序写入，保证文件整洁
                f.write("\n".join(sorted(list(rules))))

if __name__ == "__main__":
    run()
