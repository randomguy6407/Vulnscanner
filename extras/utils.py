import os
import time
import requests
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse
import httpx
import re
from playwright.async_api import async_playwright

async def get_client(http2=True, timeout=10):
    # follow_redirects = False to make way for a custom redirect
    return httpx.AsyncClient(http2=http2, timeout=timeout, follow_redirects=False)

async def fix_url(url):
    if url.startswith("http://") or url.startswith("https://"):
        print("No need to fix url, url contains correct correct protocol!")
        return url
    
    client = await get_client(http2=True)
    first_url = "http://" + url
    second_url = "https://" + url
    # Sending 1st Attempt (HTTP)

    try:
        first_response = await client.get(first_url)
    except httpx.RequestError as err:
        first_response = None
        print("Cant Reach")

    # Sending 2nd Attempt (HTTPS)
    try:
        second_response = await client.get(second_url)
    except httpx.RequestError as err:
        second_response = None
        print("Cant Reach")

    # Compare Them:
    if first_response and second_response:
        url = "https://" + url
    elif first_response is None and second_response:
        url = "https://" + url
    elif first_response and second_response is None:
        url = "http://" + url
    else:
        return "BAD_URL"

    return url

async def custom_curl(url, http2=True, method="GET", data=None, headers=None, timeout=10, cookies=None):
    client = await get_client(http2=http2)
    url = await sanitize(url)
    try:
        if method == "GET":
            response = await client.get(url, headers=headers, cookies=cookies, timeout=timeout)
        elif method == "POST":
            response = await client.post(url, data=data, headers=headers, cookies=cookies, timeout=timeout)
        else:
            raise TypeError("Unknown method specified!")
        
        protocol = response.http_version

        # Redirect Edge case ()
        codes = {301, 302, 303, 307, 308}
        redirects = []
        redirect_hardcap = 100
        redirect_count = 0
        
        while response.status_code in codes and redirect_count < redirect_hardcap:
            header_dumps = response.headers
            redirect_code = response.status_code
            location = header_dumps.get("location")
            
            if not location:
                # Look into possibly using automated redirect link (BUT NO LOGS!)
                print("No location header found to craft redirect link! (breaking from redirect chain!)")
                break

            redirects.append({
                "redirect_count": redirect_count,
                "code": redirect_code,
                "location": location,
                "resolved_url": str(httpx.URL(url).join(location)),
                "headers": dict(header_dumps)
            })
            
            url = str(httpx.URL(url).join(location))

            try:
                if method == "GET":
                    response = await client.get(url, headers=headers, cookies=cookies, timeout=timeout)
                elif method == "POST":
                    response = await client.post(url, data=data, headers=headers, cookies=cookies, timeout=timeout)
                else:
                    raise TypeError("Unknown method specified!")
            
            except httpx.RequestError as err:
                print("Failed to follow the redirect!")

            redirect_count += 1
        
        header_dumps = response.headers

        return response.status_code, response.text, redirects, protocol, header_dumps
    
    except httpx.RequestError as err:
        print(f"[!] Request to {url} failed with error: {err}")
        return None
        
# Uses playwright to simulate an actual user entering the site!

async def dynamic_curl(url, timeout=10000, ret_instance=True, hit=True):
    # fake browser visit to get real page output
    url = await sanitize(url)
    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=True)
    ctx = await browser.new_context()
    page = await ctx.new_page()

    try:
        res = await page.goto(url=url, timeout=timeout)
        if not res:
            if hit == True:
                print("[!] No response came back.")
            return None
        
        if ret_instance:
            # Returning the ENTIRE INSTANCE of the headless browser so other funcs can examine it
            return page, ctx, browser, pw
        
        stuff = {
            "url": res.url,
            "status": res.status,
            "headers": res.headers,
            "cookies": await ctx.cookies(),
            "protocol": res.url.split(":")[0].upper(),
            "body": await page.content()
        }

        return stuff

    except Exception as err:
        print(f"[x] dynamic_curl blew up: {err}")
        return None

    finally:
        if not ret_instance:
            await browser.close()
            await pw.stop()

async def display_redirects(res_list):
    for idx, redirect in enumerate(res_list):
        print(f"Redirect #{idx+1}")
        print(f"Internal Count: {redirect['redirect_count']}")
        print(f"Code: {redirect['code']}")
        print(f"Location Header: {redirect['location']}")
        print(f"Resolved URL: {redirect['resolved_url']}")
        print(f"Headers: {redirect['headers']}")
        print("-" * 40)

async def sanitize(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = await fix_url(url=url)
    return url

async def GetAllInputs(url, hit=True):
    page, ctx, browser, pw = await dynamic_curl(url=url, hit=hit)
    form_data = []
    orphans = []

    for frame in page.frames:
        # Get forms in this frame
        for form in await frame.query_selector_all("form"):
            form_action = await form.get_attribute("action") or frame.url
            form_method = await form.get_attribute("method") or "GET"

            fields = []
            for current_element in await form.query_selector_all("input, textarea, select"):
                tag = await current_element.evaluate("e => e.tagName.toLowerCase()")
                input_type = await current_element.get_attribute("type") or "text"

                if input_type.lower() == "hidden":
                    continue
                if not await current_element.is_enabled():
                    continue
                if not await current_element.is_visible():
                    continue
                if not (await current_element.get_attribute("name") or await current_element.get_attribute("id")):
                    continue

                field_info = {
                    "tag": tag,
                    "type": input_type if tag == "input" else tag,
                    "name": await current_element.get_attribute("name"),
                    "id": await current_element.get_attribute("id"),
                }

                fields.append(field_info)

            form_data.append({
                "name": await form.get_attribute("name"),
                "action": form_action,
                "method": form_method.upper(),
                "fields": fields,
            })

        # Get orphan inputs in this frame
        elements = await frame.query_selector_all("input, textarea, select")
        for current_element in elements:
            tag = await current_element.evaluate("e => e.tagName.toLowerCase()")
            typ = await current_element.get_attribute("type") or "text"

            if typ.lower() == "hidden":
                continue
            if not await current_element.is_enabled() or not await current_element.is_visible():
                continue
            if not (await current_element.get_attribute("name") or await current_element.get_attribute("id")):
                continue
            if await current_element.evaluate("e => e.closest('form')"):
                continue

            orphans.append({
                "tag": tag,
                "type": typ if tag == "input" else tag,
                "name": await current_element.get_attribute("name"),
                "id": await current_element.get_attribute("id"),
                "orphan": True,
            })
    
    await browser.close()
    await pw.stop()

    return {
        "forms": form_data,
        "orphans": orphans,
    }

async def crawl_urls(url, max_depth=5):
    visited = set()
    to_visit = [(url, 0)]
    found_urls = []

    href_regex = re.compile(r'href=[\'"]?([^\'" >]+)')

    while to_visit:
        current_url, depth = to_visit.pop()
        if depth > max_depth or current_url in visited:
            continue
        visited.add(current_url)
        found_urls.append(current_url)

        try:
            res = await httpx.AsyncClient().get(current_url, timeout=10)
            hrefs = href_regex.findall(res.text)

            for href in hrefs:
                absolute_url = urljoin(current_url, href)
                if absolute_url.startswith(url):
                    to_visit.append((absolute_url, depth + 1))

        except Exception as e:
            print(f"[!] Error at {current_url}: {e}")
    
    return found_urls

# ---------- paths -------------------------------------------------
VEC_PATH = Path(__file__).parent.parent / "config" / "config.json"
VEC_PATH.parent.mkdir(parents=True, exist_ok=True)

# ---------- defaults ---------------------------------------------
DEFAULT_VECTORS = {
    "web_protocol": True,
    "return_server_info": True,
    "xss": True,
    "js_vulns": True,
    "lfi": True,
    "blind_lfi": True,
    "crawl": True,
    "sqli": True,
    "ssti": True,
}

# ---------- load / save helpers ----------------------------------
def _save(d: dict) -> None:
    """Write dict d to disk (pretty‑printed JSON)."""
    with VEC_PATH.open("w") as f:
        json.dump(d, f, indent=2)

def _load() -> dict:
    if VEC_PATH.exists():
        try:
            with VEC_PATH.open() as f:
                user = json.load(f)
            # merge with defaults in case keys were removed
            merged = {**DEFAULT_VECTORS, **user}
            _save(merged)                # rewrite to keep file complete
            return merged
        except (json.JSONDecodeError, OSError):
            pass            # fall back to defaults if file is broken
    _save(DEFAULT_VECTORS)
    return DEFAULT_VECTORS.copy()

vectors = _load()

# ---------- mutation helpers -------------------------------------
def set_vector(key: str, value: bool) -> None:
    """Set a single flag and persist immediately."""
    vectors[key] = bool(value)
    _save(vectors)

def toggle_vector(key: str) -> None:
    """Flip a single flag True ↔ False and persist."""
    vectors[key] = not vectors.get(key, False)
    _save(vectors)
