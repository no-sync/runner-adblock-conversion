from pathlib import Path
import urllib.request
import re
import json
import shutil
import subprocess
from datetime import datetime

BLACKLIST_URLS = Path("sources/blacklist_urls.txt")
WHITELIST_URLS = Path("sources/whitelist_urls.txt")

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "hosts.txt"
ADBLOCK_OUTPUT_FILE = OUTPUT_DIR / "adblock.yaml"

SINGBOX_JSON_OUTPUT_FILE = OUTPUT_DIR / "adblock.json"
SINGBOX_SRS_OUTPUT_FILE = OUTPUT_DIR / "adblock.srs"

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE
)


def read_url_list(file_path):
    urls = []

    if not file_path.exists():
        return urls

    for line in file_path.read_text(
        encoding="utf-8",
        errors="ignore"
    ).splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        urls.append(line)

    return urls


def extract_domain(line):
    line = line.strip().lower()

    if not line:
        return None

    if line.startswith("#"):
        return None

    if "#" in line:
        line = line.split("#", 1)[0].strip()

    if not line:
        return None

    parts = line.split()

    # Supports:
    #
    # example.com
    # 0.0.0.0 example.com
    # 127.0.0.1 example.com
    #
    candidate = parts[-1]

    if candidate.startswith("*."):
        candidate = candidate[2:]

    candidate = candidate.rstrip(".")

    if DOMAIN_RE.match(candidate):
        return candidate

    return None


def download_domains(urls):
    domains = set()

    for url in urls:
        print(f"Downloading: {url}")

        try:
            with urllib.request.urlopen(
                url,
                timeout=120
            ) as response:

                text = response.read().decode(
                    "utf-8",
                    errors="ignore"
                )

        except Exception as e:
            print(f"Failed: {url}")
            print(e)
            continue

        for line in text.splitlines():
            domain = extract_domain(line)

            if domain:
                domains.add(domain)

    return domains


def is_whitelisted(domain, whitelist):
    """
    If whitelist contains:

        google.com

    remove:

        google.com
        www.google.com
        mail.google.com
        foo.bar.google.com
    """

    current = domain

    while True:
        if current in whitelist:
            return True

        if "." not in current:
            return False

        current = current.split(".", 1)[1]


def remove_redundant_subdomains(domains):
    """
    If both exist:

        example.com
        www.example.com
        ads.www.example.com

    keep only:

        example.com
    """

    domains = set(domains)
    result = set()

    for domain in sorted(domains, key=lambda d: d.count(".")):
        current = domain
        redundant = False

        while "." in current:
            current = current.split(".", 1)[1]

            if current in domains:
                redundant = True
                break

        if not redundant:
            result.add(domain)

    return result


def write_hosts_file(domains):
    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        for domain in sorted(domains):
            f.write(f"{domain}\n")


def write_adblock_file(domains, whitelist_count):
    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    total_rules = len(domains)
    domain_rules = 0
    domain_suffix_rules = total_rules

    with open(
        ADBLOCK_OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write("# Title: AdBlock_Rule_For_Clash\n")
        f.write("# Description: clash adblock rules\n")
        f.write("# LICENSE1: GPL-3.0\n")
        f.write("# LICENSE2: CC-BY-NC-SA 4.0\n")
        f.write(f"# Generated Time: {generated_time}\n")
        f.write(f"# Total Rules: {total_rules}\n")
        f.write(f"# DOMAIN : {domain_rules}\n")
        f.write(f"# DOMAIN-SUFFIX : {domain_suffix_rules}\n")
        f.write(f"# Whitelist : {whitelist_count}\n")
        f.write("\n")
        f.write("payload:\n")
        f.write("\n")

        for domain in sorted(domains):
            f.write(f"  - DOMAIN-SUFFIX,{domain}\n")


def write_singbox_json_file(domains):
    rules = [
        {
            "domain_suffix": [
                f".{domain}"
                for domain in sorted(domains)
            ]
        }
    ]

    ruleset = {
        "version": 5,
        "rules": rules
    }

    with open(
        SINGBOX_JSON_OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            ruleset,
            f,
            indent=2,
            ensure_ascii=False
        )

        f.write("\n")


def compile_singbox_ruleset():
    singbox_binary = shutil.which("sing-box")

    if singbox_binary is None:
        raise RuntimeError(
            "sing-box binary was not found in PATH. "
            "Install sing-box before running build.py."
        )

    print()
    print("Compiling Sing-box rule-set...")

    try:
        subprocess.run(
            [
                singbox_binary,
                "rule-set",
                "compile",
                "--output",
                str(SINGBOX_SRS_OUTPUT_FILE),
                str(SINGBOX_JSON_OUTPUT_FILE)
            ],
            check=True
        )

    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"sing-box rule-set compilation failed with exit code {e.returncode}."
        )

    print("Sing-box SRS output :", SINGBOX_SRS_OUTPUT_FILE)


blacklist_urls = read_url_list(BLACKLIST_URLS)
whitelist_urls = read_url_list(WHITELIST_URLS)

print(f"Blacklist sources: {len(blacklist_urls)}")
print(f"Whitelist sources: {len(whitelist_urls)}")

blacklist = download_domains(blacklist_urls)
whitelist = download_domains(whitelist_urls)

final_blacklist = {
    domain
    for domain in blacklist
    if not is_whitelisted(domain, whitelist)
}

before_cleanup = len(final_blacklist)

final_blacklist = remove_redundant_subdomains(final_blacklist)

removed_subdomains = before_cleanup - len(final_blacklist)

write_hosts_file(final_blacklist)

write_adblock_file(
    final_blacklist,
    len(whitelist)
)

write_singbox_json_file(
    final_blacklist
)

compile_singbox_ruleset()

print()
print("Blacklist loaded      :", len(blacklist))
print("Whitelist loaded      :", len(whitelist))
print("After whitelist       :", before_cleanup)
print("Redundant removed     :", removed_subdomains)
print("Final blacklist       :", len(final_blacklist))
print("Hosts output          :", OUTPUT_FILE)
print("Mihomo output         :", ADBLOCK_OUTPUT_FILE)
print("Sing-box JSON output  :", SINGBOX_JSON_OUTPUT_FILE)
print("Sing-box SRS output   :", SINGBOX_SRS_OUTPUT_FILE)
