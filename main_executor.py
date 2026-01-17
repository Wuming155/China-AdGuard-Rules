import requests
import re
import os
from datetime import datetime
import urllib3
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_comment(line):
    """简单判定注释：! 开头的，或者 # 后面带空格的"""
    if line.startswith('!'):
        return True
    if line.startswith('# ') or line == '#':
        return True
    return False

def fetch_url(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        if r.status_code == 200:
            r.encoding = 'utf-8'
            return r.text.splitlines()
    except:
        pass
    return []

def run():
    # 仅分两类：host规则和其他规则
    host_set = set()
    other_set = set()

    if not os.path.exists('sources.txt'):
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\]]+', f.read())

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_url, urls)

    for lines in results:
        for line in lines:
            line = line.strip()
            # 排除空行和注释
            if not line or is_comment(line):
                continue
            
            # 判定是否为 Host 拦截规则 (仅限 0.0.0.0 或 127.0.0.1 开头)
            if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                # 统一转为 0.0.0.0 格式并去重
                parts = line.split()
                if len(parts) >= 2:
                    host_set.add(f"0.0.0.0 {parts[1]}")
            else:
                # 剩下的不管什么规则，全部塞进 other_set
                other_set.add(line)

    # 保存文件
    os.makedirs('dist', exist_ok=True)
    date_str = datetime.now().strftime('%Y年%m月%d日')

    # 1. 保存 Hosts 规则
    with open('dist/hosts_rules.txt', 'w', encoding='utf-8') as f:
        f.write(f"# 更新日期：{date_str}\n# 规则数：{len(host_set)}\n\n")
        f.write("\n".join(sorted(list(host_set))))

    # 2. 保存剩下的全部规则
    with open('dist/adguard_rules.txt', 'w', encoding='utf-8') as f:
        f.write(f"# 更新日期：{date_str}\n# 规则数：{len(other_set)}\n\n")
        f.write("\n".join(sorted(list(other_set))))

    print(f"处理完成：Hosts({len(host_set)}条), 其他规则({len(other_set)}条)")

if __name__ == "__main__":
    run()
