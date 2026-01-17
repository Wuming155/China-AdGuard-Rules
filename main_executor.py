import requests
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib3

# 禁用不安全请求的警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 配置区 ---
SOURCES_FILE = 'sources.txt'
README_FILE = 'README.md'
DIST_DIR = 'dist'

# 文件名与 README 中显示名称的对应关系
TITLE_MAP = {
    'hosts_rules.txt': 'Hosts 屏蔽规则',
    'adguard_rules.txt': 'AdGuard 过滤规则',
    'whitelist.txt': '白名单放行规则'
}

def get_file_header(filename, count):
    """为生成的规则文件添加头部信息"""
    date_str = datetime.now().strftime('%Y年%m月%d日')
    display_name = TITLE_MAP.get(filename, filename.replace('.txt', ''))
    return f"# 更新日期：{date_str}\n# 规则数：{count}\n! Title: {display_name}\n! ------------------------------------\n\n"

def fetch_url(url):
    """抓取 URL 内容"""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        if r.status_code == 200:
            return r.text.splitlines()
    except Exception as e:
        print(f"抓取失败 {url}: {e}")
    return []

def update_readme(file_stats):
    """彻底修复重复追加问题的更新函数"""
    readme_path = 'README.md'
    if not os.path.exists(readme_path): 
        print("错误：找不到 README.md")
        return

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. 构造新的表格内容
    table_rows = ""
    for filename in sorted(file_stats.keys()):
        count = file_stats[filename]
        display_name = TITLE_MAP.get(filename, filename.replace('.txt', ''))
        table_rows += f"| **{display_name}** | {count} | [点击下载](./dist/{filename}) |\n"

    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 注意：这里的标记位必须保持这一行的纯净
    new_block = f"\n### 📊 规则统计\n| 规则类型 | 规则数量 | 下载链接 |\n| :--- | :--- | :--- |\n{table_rows}\n**⏰ 最后更新时间**: {date_str}\n"

    # 2. 使用正则匹配。核心逻辑：匹配从 到 的所有内容
    # 修复：防止因为换行符不同导致的匹配失败
    pattern = re.compile(r'.*?', re.DOTALL)

    if pattern.search(content):
        # 如果找到了标记位，直接精准替换
        updated_content = pattern.sub(new_block, content)
        print("发现标记位，执行精准替换。")
    else:
        # 如果找不到标记位，说明你的 README 里标记写错了或没了
        # 为了防止继续无限追加，我们报错并提示你手动检查
        print("！！！致命错误：在 README.md 中没找到匹配的标记位 ！！！")
        print("请检查 README.md 是否包含完整的 和 ")
        return

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(updated_content)

def run():
    # 规则分类容器
    collections = {
        'hosts_rules.txt': set(),
        'adguard_rules.txt': set(),
        'whitelist.txt': set()
    }

    if not os.path.exists(SOURCES_FILE):
        print(f"错误: 找不到 {SOURCES_FILE}")
        return
        
    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\]]+', f.read())

    print(f"开始抓取 {len(urls)} 个源...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_url, urls)

    for lines in results:
        for line in lines:
            line = line.strip()
            # 排除空行和简单的注释（! 或 #空格），但保留 ### 规则
            if not line or line.startswith('!') or line.startswith('# '):
                continue
            
            # 1. 判定白名单
            if line.startswith('@@'):
                collections['whitelist.txt'].add(line)
            # 2. 判定 Hosts 格式
            elif line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                parts = line.split()
                if len(parts) >= 2:
                    # 统一转成 0.0.0.0 并提取域名
                    domain = parts[1]
                    collections['hosts_rules.txt'].add(f"0.0.0.0 {domain}")
            # 3. 剩下的全放进 AdGuard 规则
            else:
                collections['adguard_rules.txt'].add(line)

    # 处理保存逻辑
    os.makedirs(DIST_DIR, exist_ok=True)
    file_stats = {}

    for filename, rules in collections.items():
        if rules:  # 只有当该分类有规则时才创建文件
            count = len(rules)
            file_stats[filename] = count
            file_path = os.path.join(DIST_DIR, filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(get_file_header(filename, count))
                f.write("\n".join(sorted(list(rules))))
            print(f"已生成: {filename} (共 {count} 条)")

    # 更新 README 统计
    update_readme(file_stats)

if __name__ == "__main__":
    run()
