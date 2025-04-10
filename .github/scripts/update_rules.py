import os
import requests

# Utility function to fetch and clean rules
def fetch_and_clean(url, remove_suffix):
    response = requests.get(url)
    rules = response.text.splitlines()
    cleaned_rules = [rule.replace(remove_suffix, '') for rule in rules if '[Rule]' not in rule]
    return cleaned_rules

# Utility function to merge and deduplicate lists
def merge_and_deduplicate(custom_list, url_list, rule_type):
    # Load custom rules
    custom_rules = []
    if os.path.exists(custom_list):
        with open(custom_list, 'r') as f:
            custom_rules = f.read().splitlines()

    # Load URL-based rules and deduplicate
    merged_rules = set(custom_rules)
    if os.path.exists(url_list):
        with open(url_list, 'r') as f:
            urls = f.read().splitlines()
            for url in urls:
                rules = fetch_and_clean(url, f',{rule_type}')
                merged_rules.update(rules)
    
    # Sorting rules based on the priority
    sorted_rules = sorted(merged_rules, key=lambda x: (
        x.startswith('URL-REGEX'), x.startswith('DOMAIN-SUFFIX'), x.startswith('DOMAIN')), reverse=True)
    
    return sorted_rules

# Generate final list files
def generate_rule_files():
    directories = {
        'direct': 'direct-url.list',
        'proxy': 'proxy-url.list',
        'reject': 'reject-url.list'
    }
    
    for rule_type, url_list in directories.items():
        custom_list = f'custom/{rule_type}.list'
        final_rules = merge_and_deduplicate(custom_list, f'custom/{url_list}', rule_type.upper())
        
        # Add IP-CIDR rules with no-resolve
        final_rules = [rule + ',no-resolve' if 'IP-CIDR' in rule else rule for rule in final_rules]
        
        # Save to final output
        with open(f'shadowrocket/{rule_type}.list', 'w') as f:
            f.write('\n'.join(final_rules))
        
        # Convert to Mihomo rules (DOMAIN-REGEX)
        mihomo_rules = [rule.replace('URL-REGEX', 'DOMAIN-REGEX') for rule in final_rules]
        with open(f'mihomo/{rule_type}.list', 'w') as f:
            f.write('\n'.join(mihomo_rules))

if __name__ == "__main__":
    generate_rule_files()
