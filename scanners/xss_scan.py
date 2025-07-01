import time
import html
import json
import asyncio
from extras import utils
from config.payloads import get_payloads
from urllib.parse import urljoin, urlencode

def loosely_reflected(payload, body):
    encoded = html.escape(payload)
    return payload in body or encoded in body

async def test_xss(url,hit=True):
    payloads = await get_payloads("xss")
    Input_Vectors = await utils.GetAllInputs(url=url, hit=hit)
    form_data = Input_Vectors["forms"]
    orphan_data = Input_Vectors["orphans"]
    vuln_forms = []

    for payload in payloads:
        for form in form_data:
            xss_trigger = {"fired": False, "message": None}
            dialog_event = asyncio.Event()

            async def handle_dialog(dialog):
                xss_trigger["fired"] = True
                xss_trigger["message"] = dialog.message
                await dialog.dismiss()
                dialog_event.set()
            data = {}

            for field in form["fields"]:
                name = field["name"] or field["id"]
                if name:
                    data[name] = payload

            action_url = urljoin(url, form["action"])
            method = form["method"]

            if method == "GET":
                action_url = action_url + "?" + urlencode(data)

            try:
                xss_trigger = {"fired": False, "message": None}
                page, ctx, browser, pw = await utils.dynamic_curl(url=action_url, hit=hit)

                page.on("dialog", handle_dialog)

                if method == "GET":
                    await page.goto(action_url)
                else:
                    await page.set_content("<html><body></body></html>")
                    form_creation_script = f"""
                        const form = document.createElement('form');
                        form.method = "POST";
                        form.action = "{action_url}";
                        {"".join([f'''
                            const input_{i} = document.createElement('input');
                            input_{i}.type = 'hidden';
                            input_{i}.name = "{k}";
                            input_{i}.value = {json.dumps(v)};
                            form.appendChild(input_{i});
                        ''' for i, (k, v) in enumerate(data.items())])}
                        document.body.appendChild(form);
                        form.submit();
                    """
                    async with page.expect_navigation():
                        await page.evaluate(form_creation_script)

                try:
                    await asyncio.wait_for(dialog_event.wait(), timeout=3)
                except asyncio.TimeoutError:
                    pass
                
                body = await page.content()


                if xss_trigger["fired"] and hit == True:
                    print("ALERT triggered with message:", xss_trigger["message"])
                    if "XSS" in xss_trigger["message"]:
                        print("Confirmed exact XSS execution.")

                vuln_forms.append({
                    "form_name": form["name"],
                    "url": url,
                    "method": method,
                    "payload": payload,
                    "params": data,
                    "reflected": loosely_reflected(payload, body),
                    "executed": xss_trigger["fired"]
                })

            except Exception as e:
                print(f"[X] Error while testing XSS: {e}")

            finally:
                await ctx.close()
                await browser.close()
    # Test for orphans now

    for payload in payloads:
        for orphan in orphan_data:
            xss_trigger = {"fired": False, "message": None}
            dialog_event = asyncio.Event()
            async def handle_dialog(dialog):
                xss_trigger["fired"] = True
                xss_trigger["message"] = dialog.message
                await dialog.dismiss()
                dialog_event.set()
            data = {}
        
            name = orphan["name"] or orphan["id"]
            if name:
                data[name] = payload
            
            # defaulting to GET since orphans do not have a defined method (maybe fuzzing but longer)
            # also defaulting to normal url since its hard to pinpoint a orphan's url (possible thru scanning page for fetch() / other methods)

            method = orphan.get("method", "GET").upper()
            action_url = orphan.get("action", url)

            if method == "GET":
                action_url = action_url + "?" + urlencode(data)

            try:
                xss_trigger = {"fired": False, "message": None}
                page, ctx, browser, pw = await utils.dynamic_curl(url=action_url, hit=hit)

                page.on("dialog", handle_dialog)

                if method == "GET":
                    await page.goto(action_url)
                else:
                    await page.set_content("<html><body></body></html>")
                    form_creation_script = f"""
                        const form = document.createElement('form');
                        form.method = "POST";
                        form.action = "{action_url}";
                        {"".join([f'''
                            const input_{i} = document.createElement('input');
                            input_{i}.type = 'hidden';
                            input_{i}.name = "{k}";
                            input_{i}.value = {json.dumps(v)};
                            form.appendChild(input_{i});
                            ''' for i, (k, v) in enumerate(data.items())])}
                            document.body.appendChild(form);
                            form.submit();
                        """
                    async with page.expect_navigation():
                        await page.evaluate(form_creation_script)

                try:
                    await asyncio.wait_for(dialog_event.wait(), timeout=3)
                except asyncio.TimeoutError:
                    pass
                
                body = await page.content()


                if xss_trigger["fired"] and hit == True:
                    print("ALERT triggered with message:", xss_trigger["message"])
                    if "XSS" in xss_trigger["message"]:
                        print("Confirmed exact XSS execution.")

                vuln_forms.append({
                    "form_name": name + " (orphan)",
                    "url": url,
                    "method": method,
                    "payload": payload,
                    "params": data,
                    "reflected": loosely_reflected(payload, body),
                    "executed": xss_trigger["fired"]
                })

            except Exception as e:
                print(f"[X] Error while testing XSS: {e}")

    for vuln in vuln_forms:
        if vuln["executed"] and vuln["reflected"]:
            print(f"[!] XSS confirmed in form '{vuln['form_name']}' at {vuln['url']} with payload: {vuln['payload']}")
        elif vuln["reflected"]:
            print(f"[-] Payload reflected in response but no execution: {vuln['payload']}")
        elif vuln["executed"]:
            print(f"[!] ALERT() triggered but payload not reflected: {vuln['payload']}")

    vuln = [v for v in vuln_forms if v["executed"] and v["reflected"]]
    if vuln == []:
        print("[!] No vulnerable forms detected. (XSS)")
    