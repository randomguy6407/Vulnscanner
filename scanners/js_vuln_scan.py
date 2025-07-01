import re
import requests
from urllib.parse import urljoin
from extras import utils

# Keyword-based JS security smells
KEYWORD_PATTERNS = [
    ("Loose equality", re.compile(r"[^=!]==[^=]")),
    ("Dangerous functions", re.compile(r"\b(eval|Function|setTimeout|setInterval|constructor\.constructor)\s*\(")),
    ("HTML sinks", re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln)\b")),
    ("URL injection vectors", re.compile(r"location\.(hash|search|pathname|href)")),
    ("Raw JSON.parse", re.compile(r"JSON\.parse\s*\(")),
    ("Object merging", re.compile(r"Object\.assign|Object\.defineProperties|extend\s*\(")),
    ("Globals override", re.compile(r"\b(alert|confirm|prompt)\s*\(")),
    ("window.name usage", re.compile(r"window\.name")),
    ("Regex sanitizer", re.compile(r"</?script>")),
    ("JS URI handler", re.compile(r"javascript:\S*")),
    ("Sandbox escape risk", re.compile(r'sandbox=".*(allow-scripts).*"')),
    ("PostMessage without origin check", re.compile(r'addEventListener\("message"')),
    ("Console debug", re.compile(r"console\.(log|debug|info|warn|error)\(")),
    ("WebAssembly usage", re.compile(r"WebAssembly\.(instantiate|compile|validate)")),
    ("Script injection", re.compile(r"<script.*src=\"?\{?")),
    ("Storage access", re.compile(r"(localStorage|sessionStorage|window\.name)")),
    ("Function override", re.compile(r"window\.\w+\s*=\s*function")),
    ("Weak CSP", re.compile(r"unsafe-inline|unsafe-eval|data:|blob:")),
    ("Prototype pollution", re.compile(r"__proto__|constructor|prototype")),
    ("Dynamic import", re.compile(r"import\(.*\)")),
    ("Reflect/Proxy abuse", re.compile(r"Reflect\.|Proxy\(")),
    ("Blob or Object URL", re.compile(r"URL\.createObjectURL|new\s+Blob")),
    ("Function.bind abuse", re.compile(r"\.bind\(")),
    ("Regex injection", re.compile(r"new\s+RegExp\(.*user.*input.*\)")),
    ("Base64 decoding", re.compile(r"atob\(|btoa\(")),
    ("FileReader API", re.compile(r"new\s+FileReader\(")),
    ("Worker/SharedWorker usage", re.compile(r"new\s+(Shared)?Worker\(")),
    ("Intl/Date abuse", re.compile(r"toLocale(String|Date)\(")),
    ("Set prototype property", re.compile(r"Object\.setPrototypeOf|__defineGetter__|__defineSetter__")),
]

async def scan_script_content(script, src="inline"):
    hits = []
    for label, pattern in KEYWORD_PATTERNS:
        if pattern.search(script):
            hits.append((label, src))
    return hits

async def scan_page_js(url):
    try:
        results = []
        url = await utils.sanitize(url)
    
        page, ctx, browser, pw = await utils.dynamic_curl(url, ret_instance=True)
        print(f"[*] Scanning {url} for potential JS vulnerabilities ...")

        # grab inline scripts first
        inline_scripts = await page.query_selector_all("script:not([src])")
        for index, s in enumerate(inline_scripts):
            try:
                code = await s.text_content()
                results = await scan_script_content(code, f"<inline script #{index+1} block>")
                for r in results:
                    print(f"[!] {r[0]} found in {r[1]}")
            except:
                continue  # don't break the loop on bad script
        
        if results == []:
            print(f"[!] No Vulnerabilities Found related to javascript inside inline scripts!")

        # now external ones
        ext_scripts = await page.query_selector_all("script[src]")
        for s in ext_scripts:
            src = await s.get_attribute("src")
            if not src:
                continue

            if src.startswith("/"):
                src = urljoin(url, src)

            try:
                r = requests.get(src, headers={"User-Agent": "Mozilla/5.0"})
                if r.ok:
                    results = await scan_script_content(r.text, src)
                    for r in results:
                        print(f"[!] {r[0]} found in {r[1]}")
            except:
                continue  # again, skip broken links
        
        if results == []:
            print(f"[!] No Vulnerabilities Found related to javascript inside external scripts!")

    except Exception as e:
        print(f"[x] Something blew up: {e}")

    finally:
        try:
            await browser.close()
            await pw.stop()
        except:
            pass

