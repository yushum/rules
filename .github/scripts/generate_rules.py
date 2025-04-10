#!/usr/bin/env python3

import os
import re
import requests
import logging
import sys
from pathlib import Path
from collections import defaultdict
from typing import List, Tuple, Optional, Dict, Set

# --- Configuration ---
# Make paths relative to the script's location for portability
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent.parent # Assuming script is in .github/scripts/
CUSTOM_DIR = REPO_ROOT / "custom"
OUTPUT_SR_DIR = REPO_ROOT / "shadowrocket"
OUTPUT_MH_DIR = REPO_ROOT / "mihomo"

BASE_URLS: Dict[str, str] = {
    "direct": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_direct_list.module",
    "proxy": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_proxy_list.module",
    "reject": "https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_reject_list.module",
}

# Rule type priorities for deduplication (higher number = higher priority)
# DOMAIN-REGEX is treated same as URL-REGEX for Mihomo compatibility during processing
RULE_PRIORITY: Dict[str, int] = {
    "URL-REGEX": 3,
    "DOMAIN-REGEX": 3,
    "DOMAIN-SUFFIX": 2,
    "DOMAIN": 1,
    "IP-CIDR": 0,
    "IP-CIDR6": 0,
    "GEOIP": 0,
    # Add other common types if necessary
}

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout # Log to stdout for GitHub Actions
)

# --- Helper Functions ---

def fetch_url_content(url: str, retries: int = 3, timeout: int = 60) -> Optional[str]:
    """Fetches content from a URL with retries and timeout."""
    session = requests.Session() # Use session for potential keep-alive
    for attempt in range(retries):
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            # Detect encoding, fallback to utf-8
            response.encoding = response.apparent_encoding or 'utf-8'
            logging.info(f"Successfully fetched {url}")
            return response.text
        except requests.exceptions.Timeout:
            logging.warning(f"Timeout fetching {url} (Attempt {attempt + 1}/{retries})")
        except requests.exceptions.RequestException as e:
            logging.warning(f"Error fetching {url} (Attempt {attempt + 1}/{retries}): {e}")
        except Exception as e:
            logging.error(f"Non-request error fetching {url} (Attempt {attempt + 1}/{retries}): {e}")

        if attempt < retries - 1:
             time.sleep(2 ** attempt) # Exponential backoff

    logging.error(f"Failed to fetch {url} after {retries} attempts.")
    return None

def parse_rule(line: str) -> Optional[Tuple[str, str]]:
    """Parses a rule line into (type, value), ignoring comments/empty lines."""
    line = line.strip()
    # More robust comment/empty line check
    if not line or line.startswith(('#', ';', '//', '!')):
        return None

    parts = [p.strip() for p in line.split(',', 1)]

    if len(parts) == 2:
        rule_type = parts[0].upper()
        value = parts[1]
        # Basic validation: value should not be empty
        if rule_type and value:
            return rule_type, value
    elif len(parts) == 1:
        # Try to infer type for simple lists (e.g., domain lists, IP lists)
        value = parts[0]
        if not value: return None # Ignore empty single parts

        # Simple IP address check (v4 and v6)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$', value):
            return "IP-CIDR", value
        if ':' in value and '/' in value: # Very basic IPv6 CIDR check
             return "IP-CIDR6", value
        if '.' in value: # Assume domain if it contains a dot
             return "DOMAIN", value
        # Add other inferences if needed

    logging.debug(f"Could not parse rule: {line}")
    return None # Ignore lines that don't parse correctly

def process_gmoogway_module(content: Optional[str]) -> List[str]:
    """Removes header and policy tag from GMOOgway module content."""
    if not content:
        return []

    lines = content.splitlines()
    rules: List[str] = []
    in_rule_section = False
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith(('#', ';', '//')):
            continue
        if stripped_line == '[Rule]':
            in_rule_section = True
            continue
        if not in_rule_section:
            continue

        # Remove trailing policy like ,DIRECT ,PROXY ,REJECT etc.
        rule_part = re.sub(r'\s*,\s*(DIRECT|PROXY|REJECT|no-resolve)\s*$', '', stripped_line, flags=re.IGNORECASE).strip()
        # Ensure the remaining part isn't empty after removing policy
        if rule_part:
            rules.append(rule_part)
    return rules

def read_custom_list(filepath: Path) -> List[str]:
    """Reads rules from a custom .list file if it exists."""
    rules: List[str] = []
    if not filepath.is_file():
        logging.info(f"Custom list not found (optional): {filepath}")
        return rules

    logging.info(f"Reading custom list: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(('#', ';', '//')):
                    rules.append(line)
    except Exception as e:
        logging.error(f"Error reading {filepath}: {e}")
    return rules

def fetch_external_rules(url_list_path: Path) -> List[str]:
    """Fetches rules from URLs listed in a file."""
    external_rules: List[str] = []
    if not url_list_path.is_file():
        logging.info(f"URL list not found (optional): {url_list_path}")
        return external_rules

    logging.info(f"Reading URL list: {url_list_path}")
    try:
        with open(url_list_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith(('#', ';', '//'))]
    except Exception as e:
        logging.error(f"Error reading {url_list_path}: {e}")
        return external_rules # Return empty list on error reading the URL list

    import time # Needed for sleep
    for url in urls:
        logging.info(f"Fetching external rules from: {url}")
        content = fetch_url_content(url)
        if content:
            count = 0
            for line in content.splitlines():
                line = line.strip()
                # Basic filtering of common headers/comments/metadata
                if line and not line.startswith(('#', ';', '//', '[', '!', '{', '}')):
                     # Check if the line itself looks like a rule
                     if ',' in line or '.' in line or ':' in line:
                         external_rules.append(line)
                         count += 1
                     else:
                        logging.debug(f"Skipping potential metadata line from {url}: {line}")

            logging.info(f" Added {count} rules from {url}")
        else:
            logging.warning(f"Skipping failed URL: {url}") # Don't stop the whole process

    return external_rules

def deduplicate_rules(rules: List[str]) -> List[str]:
    """
    Deduplicates rules based on priority and domain relationships.
    Priority: URL-REGEX/DOMAIN-REGEX > DOMAIN-SUFFIX > DOMAIN.
    Handles cases where DOMAIN-SUFFIX should remove covered DOMAIN rules.
    """
    logging.info(f"Starting enhanced deduplication for {len(rules)} rules...")

    # Type alias for rule data stored during deduplication
    RuleData = Tuple[int, str] # (priority, full_rule_string)

    # Pass 1: Basic deduplication based on exact value and priority
    # Stores { normalized_value: (priority, original_rule_string) }
    unique_rules_by_value: Dict[str, RuleData] = {}
    processed_count = 0
    skipped_malformed = 0

    for rule_str in rules:
        processed_count += 1
        parsed = parse_rule(rule_str)
        if not parsed:
            skipped_malformed += 1
            continue
        rule_type, value = parsed

        priority = RULE_PRIORITY.get(rule_type, 0)
        # Normalize domain names for consistent matching
        normalized_value = value.lower() if "DOMAIN" in rule_type else value

        current_priority, _ = unique_rules_by_value.get(normalized_value, (-1, None))

        if priority > current_priority:
            unique_rules_by_value[normalized_value] = (priority, rule_str)
        elif priority == current_priority and rule_type == "DOMAIN-SUFFIX" and "DOMAIN," + value == rule_str :
            # Edge case: If DOMAIN and DOMAIN-SUFFIX for same value exist, explicitly prefer DOMAIN-SUFFIX
             unique_rules_by_value[normalized_value] = (priority, f"DOMAIN-SUFFIX,{value}")

    logging.info(f"Pass 1 (Exact match deduplication) finished. Kept: {len(unique_rules_by_value)}, Processed: {processed_count}, Malformed/Comment: {skipped_malformed}")

    # Pass 2: Handle DOMAIN vs DOMAIN-SUFFIX relationship
    # We work directly on the results of Pass 1
    final_rules: Dict[str, RuleData] = {} # { normalized_value: (priority, rule_string) }
    # Store lowercase domain suffixes for quick lookup: {suffix_value: priority}
    domain_suffix_priorities: Dict[str, int] = {
        val.lower(): prio for val, (prio, rule_str) in unique_rules_by_value.items()
        if parse_rule(rule_str) and parse_rule(rule_str)[0] == "DOMAIN-SUFFIX" # type: ignore
    }

    # Iterate through the rules kept after Pass 1
    for normalized_value, (priority, rule_string) in unique_rules_by_value.items():
        parsed = parse_rule(rule_string)
        if not parsed: continue # Should not happen if Pass 1 worked
        rule_type, current_value = parsed

        keep_rule = True
        if rule_type == "DOMAIN":
            # Check if this DOMAIN is covered by a known DOMAIN-SUFFIX
            domain_lower = current_value.lower()
            parts = domain_lower.split('.')
            # Check suffixes from most specific to least specific (e.g., b.a.com -> a.com)
            for i in range(len(parts) - 1):
                parent_suffix = '.'.join(parts[i+1:])
                if parent_suffix in domain_suffix_priorities:
                    suffix_priority = domain_suffix_priorities[parent_suffix]
                    # If the covering suffix has >= priority, discard this specific DOMAIN rule
                    if suffix_priority >= priority:
                        logging.debug(f"Discarding '{rule_string}' (Prio {priority}) due to covering suffix '{parent_suffix}' (Prio {suffix_priority})")
                        keep_rule = False
                        break # Found the most relevant covering suffix

        if keep_rule:
            final_rules[normalized_value] = (priority, rule_string)

    # Extract the final rule strings
    deduped_list = sorted([rule_data[1] for rule_data in final_rules.values()])
    logging.info(f"Pass 2 (Domain relationship) finished. Final unique rules: {len(deduped_list)}")
    return deduped_list


def convert_to_mihomo(rules: List[str]) -> List[str]:
    """Converts Shadowrocket URL-REGEX rules to Mihomo DOMAIN-REGEX."""
    mihomo_rules: List[str] = []
    for rule in rules:
        if rule.startswith("URL-REGEX,"):
            mihomo_rules.append("DOMAIN-REGEX," + rule[len("URL-REGEX,"):])
        else:
            mihomo_rules.append(rule)
    return mihomo_rules

# --- Main Execution ---

def main():
    logging.info("Starting rule generation process...")
    # Ensure output directories exist
    OUTPUT_SR_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_MH_DIR.mkdir(parents=True, exist_ok=True)

    overall_success = True

    for rule_type_key in ["direct", "proxy", "reject"]:
        logging.info(f"--- Processing type: {rule_type_key} ---")

        # 1. Fetch and process base module
        base_url = BASE_URLS[rule_type_key]
        base_content = fetch_url_content(base_url)
        if base_content is None:
            logging.error(f"Failed to fetch base module for {rule_type_key}. Skipping this type.")
            overall_success = False
            continue # Skip to next rule type if base fails
        processed_base_rules = process_gmoogway_module(base_content)
        logging.info(f"Processed {len(processed_base_rules)} base rules for {rule_type_key}.")

        # 2. Fetch external rules from URL list
        external_url_list_path = CUSTOM_DIR / f"{rule_type_key}-url.list"
        external_rules = fetch_external_rules(external_url_list_path)
        logging.info(f"Fetched {len(external_rules)} external rules for {rule_type_key}.")

        # 3. Combine base and external rules for deduplication
        combined_rules_for_dedup = processed_base_rules + external_rules

        # 4. Deduplicate the combined set
        deduplicated_rules = deduplicate_rules(combined_rules_for_dedup)
        logging.info(f"Deduplicated rules count for {rule_type_key}: {len(deduplicated_rules)}")

        # 5. Read custom .list rules (append without deduplication)
        custom_list_path = CUSTOM_DIR / f"{rule_type_key}.list"
        custom_list_rules = read_custom_list(custom_list_path)
        logging.info(f"Read {len(custom_list_rules)} custom list rules for {rule_type_key}.")

        # 6. Final list = Deduplicated (Base + External) + Custom List
        # Ensure no duplicates between deduplicated and custom lists if they happen to overlap
        # Convert custom list rules to a set for quick checking
        deduplicated_set = set(deduplicated_rules)
        final_sr_rules = deduplicated_rules + [
            rule for rule in custom_list_rules if rule not in deduplicated_set
        ]
        logging.info(f"Final Shadowrocket rule count for {rule_type_key}: {len(final_sr_rules)}")


        # 7. Write Shadowrocket list
        sr_output_path = OUTPUT_SR_DIR / f"{rule_type_key}.list"
        try:
            with open(sr_output_path, 'w', encoding='utf-8') as f:
                # Write rules separated by newline, add trailing newline
                f.write('\n'.join(final_sr_rules) + '\n')
            logging.info(f"Successfully wrote Shadowrocket rules to {sr_output_path}")
        except Exception as e:
            logging.error(f"Error writing to {sr_output_path}: {e}")
            overall_success = False

        # 8. Convert to Mihomo format
        final_mihomo_rules = convert_to_mihomo(final_sr_rules)
        logging.info(f"Converted rules to Mihomo format for {rule_type_key}.")

        # 9. Write Mihomo list
        mh_output_path = OUTPUT_MH_DIR / f"{rule_type_key}.list"
        try:
            with open(mh_output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(final_mihomo_rules) + '\n')
            logging.info(f"Successfully wrote Mihomo rules to {mh_output_path}")
        except Exception as e:
            logging.error(f"Error writing to {mh_output_path}: {e}")
            overall_success = False

    if not overall_success:
        logging.error("Rule generation process finished with errors.")
        sys.exit(1) # Exit with error code if any step failed
    else:
        logging.info("Rule generation process finished successfully.")
        sys.exit(0)


if __name__ == "__main__":
    import time # Import time here for fetch_url_content backoff
    main()
