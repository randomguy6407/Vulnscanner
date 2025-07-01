import time
import html
import asyncio
from extras import utils
from config.payloads import get_payloads
from urllib.parse import urljoin, urlencode

async def ssti_scan(url, hit=True):
    ssti_payloads = await get_payloads("ssti")
    Input_Vectors = await utils.GetAllInputs(url=url, hit=hit)
    form_data = Input_Vectors["forms"]
    orphan_data = Input_Vectors["orphans"]
    vuln_entries = []

    for payload in ssti_payloads:
        for form in form_data:
            data = {}
            for field in form["fields"]:
                name = field.get("name") or field.get("id")
                if name:
                    data[name] = payload

            action_url = urljoin(url, form["action"])
            method = form["method"].upper()

            try:
                if method == "GET":
                    full_url = action_url + "?" + urlencode(data)
                    status_code, body, _, _, _  = await utils.custom_curl(url=full_url)
                else:
                    status_code, body, _, _, _ = await utils.custom_curl(
                        url=action_url,
                        data=data,
                        method="POST",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )

                body = html.unescape(body.lower())
                print("Content:", body)

                # Detect keywords relevant to SSTI (Manual added, if u plan to add more payloads you need to configure this and add more keywords!)
                interesting_keywords = [
                    "1000000", "error", "secret", "<class 'list'>", "undefined", "config", "debug", "cookie"
                ]

                unlikely_ssti_keywords = [
                    "{{ 1000 * 1000 }}", "{{ config }}", "{{ [].__class__ }}"
                ]


                interesting_stuff = any(keyword in body for keyword in interesting_keywords)
                not_likely = any(raw in body for raw in unlikely_ssti_keywords)

                if interesting_stuff:
                    vuln_entries.append({
                        "form_name": form.get("name", "Unnamed"),
                        "url": action_url,
                        "method": method,
                        "payload": payload,
                        "params": data,
                        "type": "likely SSTI vulnerable"
                    })
                elif not_likely:
                    vuln_entries.append({
                        "form_name": form.get("name", "Unnamed"),
                        "url": action_url,
                        "method": method,
                        "payload": payload,
                        "params": data,
                        "type": "unlikely SSTI vulnerable"
                    })

            except Exception as e:
                print(f"[X] Error during SSTI test: {e}")
    
    for payload in ssti_payloads:
        for orphan in orphan_data:
            data = {}
            for field in orphan["fields"]:
                name = field.get("name") or field.get("id")
                if name:
                    data[name] = payload

            method = orphan.get("method", "GET").upper()
            action_url = orphan.get("action", url)

            try:
                if method == "GET":
                    full_url = action_url + "?" + urlencode(data)
                    status_code, body, _, _, _  = await utils.custom_curl(url=full_url)
                else:
                    status_code, body, _, _, _ = await utils.custom_curl(
                        url=action_url,
                        data=data,
                        method="POST",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )

                body = body.lower()

                # Detect keywords relevant to SSTI (Manual added, if u plan to add more payloads you need to configure this and add more keywords!)
                interesting_keywords = [
                    "1000000", "Error", "Secret", "<class 'list'>", "Undefined"
                ]

                unlikely_ssti_keywords = [
                    "{{ 1000 * 1000 }}", "{{ config }}", "{{ [].__class__ }}"
                ]


                interesting_stuff = any(keyword in body for keyword in interesting_keywords)
                not_likely = any(raw in body for raw in unlikely_ssti_keywords)

                if interesting_stuff:
                    vuln_entries.append({
                        "form_name": orphan.get("name", "Unnamed"),
                        "url": action_url,
                        "method": method,
                        "payload": payload,
                        "params": data,
                        "type": "likely SSTI vulnerable"
                    })
                elif not_likely:
                    vuln_entries.append({
                        "form_name": orphan.get("name", "Unnamed"),
                        "url": action_url,
                        "method": method,
                        "payload": payload,
                        "params": data,
                        "type": "unlikely SSTI vulnerable"
                    })


            except Exception as e:
                print(f"[X] Error during SSTI test: {e}")


    if vuln_entries:
        for vuln in vuln_entries:
            if vuln["type"] == "likely SSTI vulnerable":
                print(f"[!] Possible SSTI vulnerability at {vuln['url']} ({vuln['method']})")
                print(f"[.] Payload: {vuln['payload']}")
                print(f"[.] Type: Injection / Error Based")
            elif vuln["type"] == "unlikely SSTI vulnerable":
                print(f"[-] Payload reflected but not executed at {vuln['url']} — likely not injectable")
                print(f"[.] Payload: {vuln['payload']}")
    else:
        print("[✓] No possible SSTI injection vulnerabilities detected.")
