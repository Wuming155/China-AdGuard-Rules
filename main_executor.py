import requests
import re
import os
from datetime import datetime
import urllib3

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RuleResolver:
    def resolve(self, line):
        line = line.strip()
        
        # 1. 排除基础注释（! 开头或单纯的 # 注释）
        if not line or (line.startswith('!') and not line.startswith('!!')) or line.startswith('# '):
            return None, None

        # 2. 白名单判定
        if line.startswith('@@'):
            return 'whitelist', line

        # 3. AdGuard 化妆规则与网络规则 (全面覆盖您提到的各类“浴霸”规则)
        # 包含：域名##选择器、###ID选择器、#%#脚本注入、#$#样式注入
        if '##' in line or line.startswith('###') or '#%#' in line or '#$#' in line or '#@#' in line:
            return 'adguard_rules', line
        
        # 包含：||拦截前缀、^/$/通配符等网络规则
        if line.startswith('||') or (line.startswith('|') and line.endswith('|')) or ('^' in line and '$' in line):
            return 'adguard_rules', line

        # 4. Hosts 屏蔽规则 (严格限定拦截模式)
        # 仅匹配以 0.0.0.0 或 127.0.0.1 开头的行，忽略加速/映射规则
        host_re = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\._]+)', line)
        if host_re:
            domain = host_re.group(2).strip()
            # 排除本地回环地址
            if domain not in ['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback']:
                return 'hosts_rules', f"0.0.0.0 {domain}"

        # 5. 纯域名行判定 (自动视为拦截)
        # 排除掉包含 CSS 特征（#、.、[、>）的行，防止误判化妆规则
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
            if not any(char in line for char in ['#', '[', '>', ' ', '*', ':']):
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
    # 使用 set 自动去重
    collections = {'hosts_rules': set(), 'whitelist': set(), 'adguard_rules': set()}

    if not os.path.exists('sources.txt'):
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        # 提取链接：兼容 [source] 标注等杂质
        urls = re.findall(r'https?://[^\s\]]+', f.read())

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    }

    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=30, verify=False)
            if r.status_code == 200:
                r.encoding = 'utf-8'
                for line in r.text.splitlines():
                    rtype, rule = resolver.resolve(line)
                    if rtype:
                        collections[rtype].add(rule)
        except:
            continue

    os.makedirs('dist', exist_ok=True)
    for name, rules in collections.items():
        if rules:
            sorted_rules = sorted(list(rules))
            with open(f'dist/{name}.txt', 'w', encoding='utf-8') as f:
                f.write(get_file_header(name, len(sorted_rules)))
                f.write("\n".join(sorted_rules))

if __name__ == "__main__":
    run()
