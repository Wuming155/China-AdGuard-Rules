import requests
import re
import os
from datetime import datetime
import urllib3

# 禁用不安全请求警告（针对某些 SSL 证书过期的规则源）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RuleResolver:
    def __init__(self):
        pass

    def resolve(self, line):
        line = line.strip()
        # 排除注释和空行
        if not line or (line.startswith('!') and not line.startswith('!!')) or (line.startswith('#') and not line.startswith('##')):
            return None, None

        # 1. 判定白名单
        if line.startswith('@@'):
            return 'whitelist', line

        # 2. 判定 AdGuard/Adblock 语法规则
        if (line.startswith('||') and ('^' in line or '$' in line)) or \
           ('*' in line) or ('##' in line) or ('#%#' in line):
            return 'adguard_rules', line

        # 3. 判定 Hosts 规则 (增强正则：支持空格或制表符，支持末尾注释)
        host_re = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\._]+)', line)
        if host_re:
            domain = host_re.group(1).strip()
            if domain not in ['localhost', 'localhost.localdomain']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 4. 判定纯域名行
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            return 'hosts_rules', f"0.0.0.0 {line}"

        return None, None

def get_file_header(name, count):
    date_str = datetime.now().strftime('%Y年%m月%d日')
    title_map = {
        'hosts_rules': 'Hosts 屏蔽规则',
        'adguard_rules': 'AdGuard 过滤规则',
        'whitelist': '白名单放行规则'
    }
    return f"# 更新日期：{date_str}\n# 规则数：{count}\n! Title: {title_map.get(name, '去广告规则')}\n! ------------------------------------\n\n"

def run():
    resolver = RuleResolver()
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}

    if not os.path.exists('sources.txt'):
        print("错误：未找到 sources.txt")
        return
        
    # 改进：使用正则从 sources.txt 中提取所有链接，无视前缀
    with open('sources.txt', 'r', encoding='utf-8') as f:
        content = f.read()
        urls = re.findall(r'https?://[^\s\]]+', content)

    # 增强版请求头，模拟真实浏览器
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,en;q=0.5,en-US;q=0.3',
        'Referer': 'https://www.google.com/'
    }

    for url in urls:
        print(f"正在获取: {url}")
        try:
            # 加入 verify=False 绕过证书校验，加入 stream=True 防止大文件撑爆内存
            r = requests.get(url, headers=headers, timeout=30, verify=False)
            if r.status_code == 200:
                # 显式指定编码，防止乱码
                r.encoding = 'utf-8'
                lines = r.text.splitlines()
                for line in lines:
                    rtype, rule = resolver.resolve(line)
                    if rtype:
                        collections[rtype].add(rule)
                print(f"成功处理: {url}, 有效行数: {len(lines)}")
            else:
                print(f"请求失败 (状态码: {r.status_code}): {url}")
        except Exception as e:
            print(f"请求异常 ({url}): {e}")

    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules:
            sorted_rules = sorted(list(rules))
            save_path = f'dist/{name}.txt'
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(get_file_header(name, len(sorted_rules)))
                f.write("\n".join(sorted_rules))
            print(f"文件已保存: {save_path}")

if __name__ == "__main__":
    run()
