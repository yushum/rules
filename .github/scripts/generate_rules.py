import os
import re
import requests
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

# 定义规则优先级
RULE_PRIORITY = {"URL-REGEX": 3, "DOMAIN-SUFFIX": 2, "DOMAIN": 1}

# 下载文件内容
def download_file(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return []

# 处理规则去重并按优先级排序
def deduplicate_rules(rules):
    rule_dict = OrderedDict()
    for rule in rules:
        if not rule.strip() or rule.startswith('#'):
            continue
        parts = rule.split(',')
        if len(parts) < 2:
            continue
        rule_type, value = parts[0], parts[1]
        priority = RULE_PRIORITY.get(rule_type, 0)
        rule_dict[value] = (rule, priority)
    
    # 按优先级排序并保留最高优先级的规则
    sorted_rules = [rule for _, (rule, _) in sorted(rule_dict.items(), key=lambda x: x[1], reverse=True)]
    return sorted_rules

# 添加 no-resolve 到 IP-CIDR/IP-ASN 规则
def add_no_resolve(rule):
    if re.match(r"^(IP-CIDR|IP-ASN),", rule) and "no-resolve" not in rule:
        return f"{rule},no-resolve"
    return rule

# 处理单个类型的规则
def process_rule_type(rule_type, base_url, custom_url_file, custom_list_file, output_dir):
    # 下载基础规则并清理
    base_lines = download_file(base_url)
    rule_start = base_lines.index("[Rule]") if "[Rule]" in base_lines else 0
    rules = [line.rsplit(f",{rule_type.upper()}", 1)[0] for line in base_lines[rule_start + 1:] if line.strip()]

    # 处理 custom/*-url.list 中的规则
    custom_urls = []
    if os.path.exists(custom_url_file):
        with open(custom_url_file, 'r', encoding='utf-8') as f:
            custom_urls = [line.strip() for line in f if line.strip()]
    with ThreadPoolExecutor() as executor:
        custom_rules = sum(executor.map(download_file, custom_urls), [])
    rules.extend(custom_rules)

    # 去重
    rules = deduplicate_rules(rules)

    # 添加 custom/*.list 中的规则
    if os.path.exists(custom_list_file):
        with open(custom_list_file, 'r', encoding='utf-8') as f:
            rules.extend(line.strip() for line in f if line.strip())

    # 添加 no-resolve
    rules = [add_no_resolve(rule) for rule in rules]

    # 保存到 shadowrocket
    os.makedirs(output_dir, exist_ok=True)
    with open(f"{output_dir}/{rule_type}.list", 'w', encoding='utf-8') as f:
        f.write("\n".join(rules) + "\n")

    # 转换为 mihomo 格式
    mihomo_rules = [line.replace("URL-REGEX", "DOMAIN-REGEX") for line in rules]
    with open(f"mihomo/{rule_type}.list", 'w', encoding='utf-8') as f:
        f.write("\n".join(mihomo_rules) + "\n")

def main():
    base_urls = {
        "direct": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_direct_list.module",
        "proxy": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_proxy_list.module",
        "reject": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_reject_list.module"
    }
    for rule_type in ["direct", "proxy", "reject"]:
        process_rule_type(
            rule_type,
            base_urls[rule_type],
            f"custom/{rule_type}-url.list",
            f"custom/{rule_type}.list",
            "shadowrocket"
        )

if __name__ == "__main__":
    main()