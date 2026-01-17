import re

def test_regex():
    # 模拟 README.md 内容
    content = '''# China-AdGuard-Rules

中国地区实用的AdGuard过滤规则，包含广告拦截、隐私保护、恶意软件拦截等功能。

## 规则统计

| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| AdGuard 语法 | 163737 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/adguard_rules.txt) |
| Hosts 屏蔽 | 6100 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/hosts_rules.txt) |
| 白名单放行 | 7610 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/whitelist.txt) |

⏰ 最后更新: 2026-01-17 13:32:03

## 使用说明

1. 下载所需的规则文件
2. 在AdGuard客户端中添加自定义规则
3. 定期更新以保持最佳效果

## 贡献

欢迎提交Issue和Pull Request来改进规则库！'''
    
    # 模拟表格内容
    table_content = '''
| 规则类型 | 规则数量 | 下载链接 |
| :--- | :--- | :--- |
| AdGuard 语法 | 1000 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/adguard_rules.txt) |
| Hosts 屏蔽 | 200 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/hosts_rules.txt) |
| 白名单放行 | 50 | [点击下载](https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/whitelist.txt) |

⏰ 最后更新: 2026-01-17 14:00:00'''
    
    # 测试正则表达式
    pattern = r"(## 规则统计[\s\S]*?)(?=## |$)"
    replacement = f"## 规则统计\n{table_content}\n"
    
    print("原始内容：")
    print(content)
    print("\n" + "="*50 + "\n")
    
    new_content = re.sub(pattern, replacement, content)
    
    print("替换后的内容：")
    print(new_content)
    
    # 检查是否有重复的表格
    table_count = new_content.count("| 规则类型 | 规则数量 | 下载链接 |")
    print(f"\n表格数量：{table_count}")
    
    if table_count == 1:
        print("测试通过：正则表达式正确替换表格，没有重复！")
    else:
        print(f"测试失败：有 {table_count} 个表格，应该只有 1 个！")

if __name__ == "__main__":
    test_regex()