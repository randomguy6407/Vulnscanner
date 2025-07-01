import re
import base64
import httpx
from extras import utils
from config import payloads
from urllib.parse import urlencode, urlparse

# ----------------------
# Detection Heuristics
# ----------------------

direct_file_signatures = [
    r"root:x:[0-9]+:[0-9]+",              # /etc/passwd
    r"PATH=.*",                           # /proc/self/environ
    r"Linux version \d+\.\d+",            # /proc/version
    r"cmdline=.*",                        # /proc/cmdline
    r"\[.*?\] \[.*?\] \[.*?\]",           # Apache/nginx logs
    r"flags=.*",
    r"(?i)Content-Type:.*",
]

source_code_signatures = [
    r"<\?php",                            # PHP
    r"(from\s+\w+\s+import\s+|import\s+\w+)",  # Python
    r"(def\s+\w+\()",                     # Python
    r"(public\s+class\s+\w+)",            # Java
    r"(function\s+\w+\()",                # PHP/JS
    r"(?i)config\[.*?\]",                 # PHP arrays
    r"(?i)DB_(USER|PASS|HOST|NAME)",      # DB configs
]

flag_signatures = [
    r"FLAG\{.*?\}", r"CTF\{.*?\}", r"HACK\{.*?\}",
    r"[A-Za-z0-9+/=]{60,}",               # long base64
    r"(?i)password\s*[:=]\s*['\"].+?['\"]",
    r"(?i)secret\s*[:=]\s*['\"].+?['\"]",
    r"(?i)key\s*[:=]\s*['\"].+?['\"]",
]


def is_base64_encoded(s):
    if len(s) > 100 and re.match(r'^[A-Za-z0-9+/=]+$', s):
        try:
            decoded = base64.b64decode(s).decode(errors='ignore')
            return any(re.search(pat, decoded, re.IGNORECASE)
                       for pat in direct_file_signatures + source_code_signatures + flag_signatures)
        except Exception:
            return False
    return False


def is_lfi_successful(response_text):
    all_patterns = (
        direct_file_signatures +
        source_code_signatures +
        flag_signatures
    )

    for pattern in all_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True

    base64_blobs = re.findall(r'[A-Za-z0-9+/=]{100,}', response_text)
    for blob in base64_blobs:
        if is_base64_encoded(blob):
            return True

    return False


# ----------------------
# Main Scanner Function
# ----------------------

async def lfi_scanner(url, hit=True):

    lfi_payloads = await payloads.get_payloads("lfi")
    Input_Vectors = await utils.GetAllInputs(url=url, hit=hit)
    form_data = Input_Vectors["forms"]
    vuln_entries = []

    for payload in lfi_payloads:
        for form in form_data:
            if form["method"] != "GET":
                continue

            # Handle single-input GET forms
            if len(form["fields"]) == 1:
                input_name = form["fields"][0]["name"]
                print(f"[+] Testing payload on form '{form['name']}', input: {input_name}")

                query = urlencode({input_name: payload})
                full_url = f"{url}?{query}"
                res = await utils.custom_curl(url=full_url)
                response_text = res[1]

                if is_lfi_successful(response_text):
                    print(f"[!] LFI Detected! Input: {input_name}, Payload: {payload}")
                    vuln_entries.append((form["name"], input_name, payload, full_url))

            # Handle multi-input GET forms
            elif len(form["fields"]) > 1:
                for field in form["fields"]:
                    input_name = field["name"]
                    params = {
                        f["name"]: (payload if f["name"] == input_name else "test")
                        for f in form["fields"]
                    }
                    query = urlencode(params)
                    full_url = f"{url}?{query}"

                    res = await utils.custom_curl(url=full_url)
                    response_text = res[1]

                    if is_lfi_successful(response_text):
                        print(f"[!] LFI Detected in multi-input form! Input: {input_name}, Payload: {payload}")
                        vuln_entries.append((form["name"], input_name, payload, full_url))

    return vuln_entries

async def blind_lfi(base_url):
    INTERESTING_PATHS = {"search", "file", "load", "view", "preview", "doc", "page", "open", "download"}
    all_urls = await utils.crawl_urls(base_url)
    lfi_payloads = await payloads.get_payloads("lfi")
    vuln_entries = []

    for url in all_urls:
        parsed = urlparse(url)
        path_parts = parsed.path.lower().strip("/").split("/")

        if any(p in INTERESTING_PATHS for p in path_parts):
            for payload in lfi_payloads:
                test_url = f"{url}?q={payload}"
                try:
                    res = await httpx.AsyncClient().get(test_url, timeout=10)
                    if is_lfi_successful(res.text):
                        print(f"[*] POSSIBLE LFI FOUND: {test_url}")
                        vuln_entries.append((test_url, payload))
                except Exception as e:
                    print(f"[!] Error on {test_url}: {e}")

    return vuln_entries
    

    

