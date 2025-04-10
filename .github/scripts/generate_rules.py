import os
import re
import requests
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

# 定义规则优先级（仅作为初始参考，实际去重基于覆盖范围）
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

# 检查规则是否被另一条规则覆盖
def is_covered(rule, other_rule):
    rule_type, rule_value = rule.split(',', 1)[0], rule.split(',', 1)[1]
    other_type, other_value = other_rule.split(',', 1)[0], other_rule.split(',', 1)[1]
    
    # URL-REGEX 覆盖 DOMAIN-SUFFIX 和 DOMAIN
    if other_type == "URL-REGEX":
        try:
            if rule_type == "DOMAIN-SUFFIX" and re.match(other_value, f"x.{rule_value}"):
                return True
            if rule_type == "DOMAIN" and re.match(other_value, rule_value):
                return True
        except re.error:
            return False
    
    # DOMAIN-SUFFIX 覆盖 DOMAIN
    if other_type == "DOMAIN-SUFFIX" and rule_type == "DOMAIN":
        if rule_value.endswith(f".{other_value}"):
            return True
    
    return False

# 处理规则去重，按覆盖范围保留更广的规则
def deduplicate_rules(rules):
    rule_dict = OrderedDict()
    for rule in rules:
        if not rule.strip() or rule.startswith('#'):
            continue
        rule_type, value = rule.split(',', 1)[0], rule.split(',', 1)[1]
        rule_dict[value] = rule
    
    # 去重：检查每条规则是否被其他规则覆盖
    final_rules = []
    rule_list = list(rule_dict.values())
    for i, rule in enumerate(rule_list):
        covered = False
        for j, other_rule in enumerate(rule_list):
            if i != j and is_covered(rule, other_rule):
                covered = True
                break
        if not covered:
            final_rules.append(rule)
    
    return final_rules

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

    # 去重，按覆盖范围保留
    rules = deduplicate_rules(rules)

    # 添加 custom/*.list 中的规则（不去重）
    if os.path.exists(custom_list_file):
        with open(custom_list_file, 'r', encoding='utf-8') as f:
            rules.extend(line.strip() for line in f if line.strip())

    # 添加 no-resolve
    rules = [add_no_resolve(rule) for rule in rules]

    # 按字母顺序排序
    rules.sort()

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
