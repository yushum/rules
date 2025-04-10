import os
import requests

# 定义源文件 URL
SOURCE_URLS = {
    "direct": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/refs/heads/master/sr_direct_list.module",
    "proxy": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/refs/heads/master/sr_proxy_list.module",
    "reject": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/refs/heads/master/sr_reject_list.module"
}

# 定义输出目录
OUTPUT_DIRS = {
    "shadowrocket": "shadowrocket",
    "mihomo": "mihomo"
}

# 定义自定义文件路径
CUSTOM_FILES = {
    "direct_append": "custom/direct_append.list",
    "proxy_append": "custom/proxy_append.list",
    "reject_append": "custom/reject_append.list",
    "direct_excludes": "custom/direct_excludes.list",
    "proxy_excludes": "custom/proxy_excludes.list",
    "reject_excludes": "custom/reject_excludes.list"
}

# IP 类型规则，需要添加 ,no-resolve
IP_TYPES = {"IP-ASN", "IP-CIDR", "IP-CIDR6"}

def fetch_rules(url):
    """从 URL 获取规则内容"""
    response = requests.get(url)
    response.raise_for_status()
    return response.text.splitlines()

def read_file(file_path):
    """读取本地文件，如果不存在返回空列表"""
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    return []

def process_rules(lines):
    """处理规则，去除注释和策略，添加 no-resolve"""
    rules = []
    in_rule_section = False

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('#'):
            if in_rule_section:
                break  # 遇到新的注释块，规则部分结束
            continue
        if line == '[Rule]':
            in_rule_section = True
            continue
        if in_rule_section:
            # 分割规则和策略
            parts = line.split(',')
            if len(parts) < 2:
                continue
            rule_type = parts[0].strip()
            domain = parts[1].strip()
            # 检查是否为 IP 类型规则
            if rule_type in IP_TYPES:
                rules.append(f"{rule_type},{domain},no-resolve")
            else:
                rules.append(f"{rule_type},{domain}")
    return rules

def convert_to_mihomo(rules):
    """将 Shadowrocket 规则转换为 mihomo 格式"""
    mihomo_rules = []
    for rule in rules:
        if rule.startswith("URL-REGEX"):
            mihomo_rule = rule.replace("URL-REGEX", "DOMAIN_REGEX", 1)
            mihomo_rules.append(mihomo_rule)
        else:
            mihomo_rules.append(rule)
    return mihomo_rules

def apply_customizations(rules, append_list, exclude_list):
    """应用追加和排除规则"""
    rules_set = set(rules)
    append_set = set(append_list)
    exclude_set = set(exclude_list)
    
    # 添加 append 规则
    rules_set.update(append_set)
    # 移除 exclude 规则
    rules_set.difference_update(exclude_set)
    
    return sorted(list(rules_set))

def main():
    # 确保输出目录存在
    for dir_path in OUTPUT_DIRS.values():
        os.makedirs(dir_path, exist_ok=True)

    # 处理每个类型的规则
    for rule_type in ["direct", "proxy", "reject"]:
        # 获取源规则
        source_lines = fetch_rules(SOURCE_URLS[rule_type])
        rules = process_rules(source_lines)

        # 读取自定义文件
        append_list = read_file(CUSTOM_FILES[f"{rule_type}_append"])
        exclude_list = read_file(CUSTOM_FILES[f"{rule_type}_excludes"])

        # 应用自定义规则
        final_rules = apply_customizations(rules, append_list, exclude_list)

        # 生成 Shadowrocket 规则集
        shadowrocket_path = os.path.join(OUTPUT_DIRS["shadowrocket"], f"{rule_type}.list")
        with open(shadowrocket_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(final_rules) + "\n")

        # 生成 mihomo 规则集
        mihomo_rules = convert_to_mihomo(final_rules)
        mihomo_path = os.path.join(OUTPUT_DIRS["mihomo"], f"{rule_type}.list")
        with open(mihomo_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(mihomo_rules) + "\n")

if __name__ == "__main__":
    main()
