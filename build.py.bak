from pathlib import Path
import urllib.request
import re

BLACKLIST_URLS = Path("sources/blacklist_urls.txt")
WHITELIST_URLS = Path("sources/whitelist_urls.txt")

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "hosts.txt"

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

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as f:

    for domain in sorted(final_blacklist):
        f.write(f"{domain}\n")

print()
print("Blacklist loaded      :", len(blacklist))
print("Whitelist loaded      :", len(whitelist))
print("After whitelist       :", before_cleanup)
print("Redundant removed     :", removed_subdomains)
print("Final blacklist       :", len(final_blacklist))
print("Output                :", OUTPUT_FILE)
