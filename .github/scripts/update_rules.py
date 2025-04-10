import os
import re
import requests
from collections import defaultdict

# Constants
BASE_URL = "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master"
SOURCES = {
    "direct": f"{BASE_URL}/sr_direct_list.module",
    "proxy": f"{BASE_URL}/sr_proxy_list.module",
    "reject": f"{BASE_URL}/sr_reject_list.module",
}
TYPES = ["direct", "proxy", "reject"]
CACHE_DIR = ".github/cache"

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)

def fetch_url(url):
    cache_file = os.path.join(CACHE_DIR, url.replace('/', '_').replace(':', '_'))
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
        with open(cache_file, 'w', encoding='utf-8') as f:
            f.write(content)
        return content
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as f:
                return f.read()
        return ""

def parse_rules(text):
    rules = defaultdict(list)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '[Rule]' in line:
            continue
        rule = line.split(',', 1)[0]  # Remove policy (e.g., ,DIRECT)
        if rule.startswith(('DOMAIN', 'DOMAIN-SUFFIX', 'URL-REGEX', 'IP-CIDR', 'IP-ASN')):
            rules[rule.split(',', 1)[0]].append(rule)
    return rules

def deduplicate_rules(rules):
    # Sort by precedence: URL-REGEX > DOMAIN-SUFFIX > DOMAIN
    precedence = {'URL-REGEX': 3, 'DOMAIN-SUFFIX': 2, 'DOMAIN': 1}
    domain_rules = set()
    suffix_rules = set()
    regex_rules = set()
    other_rules = []

    for rule_type, rule_list in rules.items():
        if rule_type == 'DOMAIN':
            for rule in rule_list:
                domain = rule.split(',', 1)[1]
                domain_rules.add((rule, domain))
        elif rule_type == 'DOMAIN-SUFFIX':
            for rule in rule_list:
                suffix = rule.split(',', 1)[1]
                suffix_rules.add((rule, suffix))
        elif rule_type == 'URL-REGEX':
            for rule in rule_list:
                regex = rule.split(',', 1)[1]
                regex_rules.add((rule, regex))
        else:
            other_rules.extend(rule_list)

    # Deduplicate DOMAIN against DOMAIN-SUFFIX
    filtered_domains = set()
    for rule, domain in domain_rules:
        if not any(domain.endswith(suffix) for _, suffix in suffix_rules):
            filtered_domains.add(rule)

    # Deduplicate DOMAIN and DOMAIN-SUFFIX against URL-REGEX (simplified check)
    final_domains = set()
    final_suffixes = set()
    for rule in filtered_domains:
        domain = rule.split(',', 1)[1]
        if not any(re.search(regex, domain) for _, regex in regex_rules):
            final_domains.add(rule)
    for rule, suffix in suffix_rules:
        if not any(re.search(regex, suffix) for _, regex in regex_rules):
            final_suffixes.add(rule)

    # Combine and sort
    all_rules = list(final_domains) + list(final_suffixes) + [r[0] for r in regex_rules] + other_rules
    return sorted(all_rules, key=lambda x: x.split(',', 1)[1] if ',' in x else x)

def append_no_resolve(rule):
    if rule.startswith(('IP-CIDR', 'IP-ASN')) and ',no-resolve' not in rule:
        return f"{rule},no-resolve"
    return rule

def convert_to_mihomo(rule):
    if rule.startswith('URL-REGEX'):
        regex = rule.split(',', 1)[1]
        # Simplify: assume URL-REGEX is domain-like; adjust as needed
        domain_regex = regex.replace('^https?://', '').replace('.*', '')
        return f"DOMAIN-REGEX,{domain_regex}"
    return rule

def process_type(rule_type):
    # Step 1: Fetch and clean base rules
    base_content = fetch_url(SOURCES[rule_type])
    base_rules = parse_rules(base_content)

    # Step 2: Fetch and parse URL rules
    url_file = f"custom/{rule_type}-url.list"
    url_rules = defaultdict(list)
    if os.path.exists(url_file):
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            content = fetch_url(url)
            for rule_type, rules in parse_rules(content).items():
                url_rules[rule_type].extend(rules)

    # Step 3: Load custom rules
    custom_file = f"custom/{rule_type}.list"
    custom_rules = defaultdict(list)
    if os.path.exists(custom_file):
        with open(custom_file, 'r', encoding='utf-8') as f:
            content = f.read()
            custom_rules = parse_rules(content)

    # Step 4: Merge and deduplicate (custom > url > base)
    merged_rules = defaultdict(list)
    for rule_type in base_rules:
        merged_rules[rule_type] = base_rules[rule_type] + url_rules[rule_type] + custom_rules[rule_type]
    deduped_rules = deduplicate_rules(merged_rules)

    # Step 5: Add no-resolve and write Shadowrocket file
    final_rules = [append_no_resolve(rule) for rule in deduped_rules]
    os.makedirs('shadowrocket', exist_ok=True)
    with open(f"shadowrocket/{rule_type}.list", 'w', encoding='utf-8') as f:
        f.write("# Generated by GitHub Actions\n")
        f.write('\n'.join(final_rules) + '\n')

    # Step 6: Convert to mihomo and write
    mihomo_rules = [convert_to_mihomo(rule) for rule in final_rules]
    os.makedirs('mihomo', exist_ok=True)
    with open(f"mihomo/{rule_type}.list", 'w', encoding='utf-8') as f:
        f.write("# Generated by GitHub Actions\n")
        f.write('\n'.join(mihomo_rules) + '\n')

def main():
    for rule_type in TYPES:
        process_type(rule_type)

if name == "__main__":
    main()
