import requests
import re
import os
from datetime import datetime

# 自动获取当前运行的仓库路径，用于在 README 中生成正确的 raw 链接
# 本地测试时会显示 User/Repo，在 Actions 运行时会自动变成你的 名字/仓库名
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY', 'Wuming155/China-AdGuard-Rules')

class RuleResolver:
    """分类解析器：确保 AdGuard 语法规则和 Hosts 域名规则各归各位"""
    def resolve(self, line):
        line = line.strip()
        # 排除空行、单行注释（! 或 # 开头且不含特殊修饰符的）
        if not line or (line.startswith('!') and not line.startswith('!!')) or (line.startswith('#') and not (line.startswith('##') or line.startswith('#%#'))):
            return None, None
        
        # 1. 处理白名单 (@@ 开头)
        if line.startswith('@@'):
            return 'whitelist', line
            
        # 2. 处理 AdGuard 语法类 (包含 ||, *, ^, $, ## 等特征)
        # 注意：排除掉包含 0.0.0.0 的行，防止 Hosts 误入
        if any(x in line for x in ['||', '*', '^', '$', '##', '#%#']):
            if not re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)', line):
                return 'adguard_rules', line

        # 3. 处理 Hosts/域名类 (提取纯域名并去掉后缀注释)
        host_re = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\.\_]+)', line)
        if host_re:
            domain = host_re.group(1).strip()
            if domain not in ['localhost', 'localhost.localdomain']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 4. 纯域名补全格式 (如 example.com 直接转为 0.0.0.0 example.com)
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            return 'hosts_rules', f"0.0.0.0 {line}"

        return None, None

def update_readme(stats):
    """
    精准定位 README 中的标记并进行【覆盖式替换】
    这是解决 README 重复堆叠的核心代码
    """
    if not os.path.exists('README.md'):
        print("未找到 README.md，跳过更新统计表")
        return
        
    with open('README.md', 'r', encoding='utf-8') as f:
        content = f.read()

    raw_base = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/dist"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 构造新的统计表格内容
    table_content = f"""
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| AdGuard 语法 | {stats.get('adguard_rules', 0)} | [点击下载]({raw_base}/adguard_rules.txt) |
| Hosts 屏蔽 | {stats.get('hosts_rules', 0)} | [点击下载]({raw_base}/hosts_rules.txt) |
| 白名单放行 | {stats.get('whitelist', 0)} | [点击下载]({raw_base}/whitelist.txt) |

⏰ 最后更新: {now}
"""
    # 使用正则表达式匹配 "## 规则统计" 标题及其内容，直到下一个标题
    pattern = r"(## 规则统计[\s\S]*?)(?=## |$)"
    replacement = f"## 规则统计\n{table_content}\n"
    
    # 替换规则统计部分
    new_content = re.sub(pattern, replacement, content)

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("README 统计表更新成功")

def run():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}
    
    # 读取源链接
    if not os.path.exists('sources.txt'):
        print("缺少 sources.txt 文件")
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip().startswith('http')]

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    for url in urls:
        print(f"正在同步: {url}")
        try:
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    rtype, rule = resolver.resolve(line)
                    if rtype:
                        collections[rtype].add(rule)
        except Exception as e:
            print(f"抓取失败 {url}: {e}")

    # 生成分类文件
    os.makedirs('dist', exist_ok=True)
    stats = {}
    header_date = datetime.now().strftime('%Y年%m月%d日')
    
    for name in ['hosts_rules', 'adguard_rules', 'whitelist']:
        sorted_list = sorted(list(collections[name]))
        stats[name] = len(sorted_list)
        with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
            # 写入文件头
            title_map = {'hosts_rules': 'Hosts 屏蔽', 'adguard_rules': 'AdGuard 语法', 'whitelist': '白名单'}
            f.write(f"# 更新日期：{header_date}\n# 条数：{len(sorted_list)}\n! Title: {title_map[name]}\n\n")
            f.write("\n".join(sorted_list))
    
    # 更新 README 统计
    update_readme(stats)

if __name__ == "__main__":
    run()
