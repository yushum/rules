import os
import re
import requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False
        self.rule = None

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, domain, rule):
        node = self.root
        parts = domain.split('.')[::-1]
        for part in parts:
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
        node.is_end = True
        node.rule = rule

    def is_covered(self, domain):
        node = self.root
        parts = domain.split('.')[::-1]
        for part in parts:
            if part not in node.children:
                return False
            node = node.children[part]
            if node.is_end:
                print(f"DEBUG: {domain} covered by {node.rule}")
                return True
        return node.is_end

def deduplicate_rules(rules):
    by_type = defaultdict(list)
    for rule in rules:
        if not rule.strip() or rule.startswith('#'):
            continue
        rule_type, value = rule.split(',', 1)[0], rule.split(',', 1)[1]
        by_type[rule_type].append((value, rule))

    final_rules = set()
    trie = Trie()
    regexes = []

    # 处理 DOMAIN-SUFFIX
    if "DOMAIN-SUFFIX" in by_type:
        for value, rule in by_type["DOMAIN-SUFFIX"]:
            trie.insert(value, rule)
            final_rules.add(rule)

    # 处理 DOMAIN
    if "DOMAIN" in by_type:
        for value, rule in by_type["DOMAIN"]:
            if not trie.is_covered(value):
                final_rules.add(rule)
            else:
                print(f"DEBUG: Skipping {rule} as it's covered by a DOMAIN-SUFFIX")

    # 处理 URL-REGEX
    if "URL-REGEX" in by_type:
        regexes = [(value, rule, re.compile(value)) for value, rule in by_type["URL-REGEX"]]
        for value, rule, _ in regexes:
            final_rules.add(rule)

    # 过滤被 URL-REGEX 覆盖的规则
    if regexes:
        filtered_rules = set()
        for rule in final_rules:
            rule_type, value = rule.split(',', 1)[0], rule.split(',', 1)[1]
            covered = False
            if rule_type in ["DOMAIN", "DOMAIN-SUFFIX"]:
                for _, regex_rule, regex in regexes:
                    test_value = value if rule_type == "DOMAIN" else f"x.{value}"
                    if regex.match(test_value):
                        covered = True
                        print(f"DEBUG: {rule} covered by {regex_rule}")
                        break
            if not covered:
                filtered_rules.add(rule)
        final_rules = filtered_rules

    # 添加其他类型
    for rule_type in by_type:
        if rule_type not in ["DOMAIN", "DOMAIN-SUFFIX", "URL-REGEX"]:
            final_rules.update(rule for _, rule in by_type[rule_type])

    print(f"DEBUG: Final rules count: {len(final_rules)}")
    return list(final_rules)

# 其余函数保持不变
def download_file(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        print(f"DEBUG: Successfully downloaded {url}")
        return response.text.splitlines()
    except Exception as e:
        print(f"DEBUG: Failed to download {url}: {e}")
        return []

def add_no_resolve(rule):
    if re.match(r"^(IP-CIDR|IP-ASN),", rule) and "no-resolve" not in rule:
        return f"{rule},no-resolve"
    return rule

def process_rule_type(rule_type, base_url, custom_url_file, custom_list_file, output_dir):
    base_lines = download_file(base_url)
    rule_start = base_lines.index("[Rule]") if "[Rule]" in base_lines else 0
    rules = [line.rsplit(f",{rule_type.upper()}", 1)[0] for line in base_lines[rule_start + 1:] if line.strip()]

    custom_urls = []
    if os.path.exists(custom_url_file):
        with open(custom_url_file, 'r', encoding='utf-8') as f:
            custom_urls = [line.strip() for line in f if line.strip()]
    with ThreadPoolExecutor() as executor:
        custom_rules = sum(executor.map(download_file, custom_urls), [])
    rules.extend(custom_rules)

    rules = deduplicate_rules(rules)

    if os.path.exists(custom_list_file):
        with open(custom_list_file, 'r', encoding='utf-8') as f:
            rules.extend(line.strip() for line in f if line.strip())

    rules = [add_no_resolve(rule) for rule in rules]
    rules.sort()

    os.makedirs(output_dir, exist_ok=True)
    with open(f"{output_dir}/{rule_type}.list", 'w', encoding='utf-8') as f:
        f.write("\n".join(rules) + "\n")

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
