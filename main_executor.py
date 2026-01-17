import requests
import re
import os
from datetime import datetime

def run():
    # 准备容器
    # 为了保证你的需求，我们把所有拦截类规则合并，白名单单独放
    combined_intercept = set()
    whitelist = set()

    if not os.path.exists('sources.txt'):
        print("错误: 找不到 sources.txt")
        return
        
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.strip().startswith('http')]

    for url in urls:
        print(f"正在同步: {url}")
        try:
            r = requests.get(url, timeout=15)
            for line in r.text.splitlines():
                line = line.strip()
                
                # 1. 处理白名单
                if line.startswith('@@'):
                    whitelist.add(line)
                    continue

                # 2. 核心逻辑：保留注释以外的所有拦截规则
                # 匹配 Hosts 格式 (0.0.0.0 或 127.0.0.1)
                host_match = re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+([a-zA-Z0-9\-\.\_]+)', line)
                if host_match:
                    domain = host_match.group(1)
                    if domain not in ['localhost', 'localhost.localdomain']:
                        combined_intercept.add(f"0.0.0.0 {domain}")
                    continue

                # 3. 核心逻辑：保留 || 开头的 Adblock 规则 (如你提到的 kakamobi.cn)
                if line.startswith('||'):
                    combined_intercept.add(line)
                    continue
                
                # 4. 其他有效规则 (非注释、非空行)
                if line and not (line.startswith('!') or line.startswith('#')):
                    combined_intercept.add(line)
                    
        except Exception as e:
            print(f"失败: {url}, 错误: {e}")

    # --- 写入文件逻辑 ---
    os.makedirs('dist', exist_ok=True)
    
    # 生成日期格式：260117 (YYMMDD)
    date_str = datetime.now().strftime('%y%m%d')
    
    # 写入拦截规则总表
    if combined_intercept:
        with open('dist/rules.txt', 'w', encoding='utf-8') as f:
            # 写入你要求的 Header
            f.write(f"#更新日期：{date_str}\n")
            f.write(f"#规则数：{len(combined_intercept)}\n")
            f.write(f"! Title: 去广告规则\n")
            f.write("! ------------------------------------\n\n")
            f.write("\n".join(sorted(list(combined_intercept))))

    # 写入白名单 (如果有)
    if whitelist:
        with open('dist/whitelist.txt', 'w', encoding='utf-8') as f:
            f.write(f"#更新日期：{date_str}\n")
            f.write(f"#规则数：{len(whitelist)}\n")
            f.write(f"! Title: 白名单规则\n\n")
            f.write("\n".join(sorted(list(whitelist))))

if __name__ == "__main__":
    run()
