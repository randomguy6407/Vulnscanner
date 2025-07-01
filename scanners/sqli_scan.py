import time
import html
import asyncio
from extras import utils
from config.payloads import get_payloads
from urllib.parse import urljoin, urlencode

async def sqli_scan(url, hit=True):
    sqli_payloads = await get_payloads("sqli")
    Input_Vectors = await utils.GetAllInputs(url=url, hit=hit)
    form_data = Input_Vectors["forms"]
    orphan_data = Input_Vectors["orphans"]
    vuln_entries = []

    for payload in sqli_payloads:
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

                body = body.lower()

                # SQL error signature detection
                sql_error_keywords = [
                    "syntax", "invalid", "unexpected", "unrecognized", "unclosed", "unterminated", "malformed",
                    "mismatch", "incorrect", "truncated", "token", "operator", "delimiter", "unterminated string",
                    "error", "fail", "exception", "fatal", "warning", "unknown", "query failed", "could not execute",
                    "conversion failed", "timeout", "crash", "aborted", "panic", "unavailable", "rejected", "denied",
                    "not found", "does not exist", "missing", "unresolved", "reference", "duplicate", "ambiguous",
                    "conflict", "constraint", "violation", "schema", "database", "table", "column", "field", "row",
                    "record", "index", "primary key", "foreign key", "relation", "view", "sequence", "sql", "stack trace",
                    "sqlstate", "driver", "adapter", "engine", "backend", "module", "context", "connection refused",
                    "session", "ORA-", "SQLSTATE", "pg_", "mysql_", "sqlite_", "mssql_"
                ]


                error_detected = any(keyword in body for keyword in sql_error_keywords)
                reflected_fully = all(payload.lower() in body for payload in data.values())

                if error_detected:
                    vuln_entries.append({
                        "form_name": form.get("name", "Unnamed"),
                        "url": action_url,
                        "method": method,
                        "payload": payload,
                        "params": data,
                        "type": "error-based"
                    })
                elif reflected_fully:
                    vuln_entries.append({
                        "form_name": form.get("name", "Unnamed"),
                        "url": action_url,
                        "method": method,
                        "payload": payload,
                        "params": data,
                        "type": "unlikely"
                    })

            except Exception as e:
                print(f"[X] Error during SQLi test: {e}")
    
    for payload in sqli_payloads:
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

                body = html.unescape(body.lower())

                # SQL error signature detection
                sql_error_keywords = [
                    "syntax", "invalid", "unexpected", "unrecognized", "unclosed", "unterminated", "malformed",
                    "mismatch", "incorrect", "truncated", "token", "operator", "delimiter", "unterminated string",
                    "error", "fail", "exception", "fatal", "warning", "unknown", "query failed", "could not execute",
                    "conversion failed", "timeout", "crash", "aborted", "panic", "unavailable", "rejected", "denied",
                    "not found", "does not exist", "missing", "unresolved", "reference", "duplicate", "ambiguous",
                    "conflict", "constraint", "violation", "schema", "database", "table", "column", "field", "row",
                    "record", "index", "primary key", "foreign key", "relation", "view", "sequence", "sql", "stack trace",
                    "sqlstate", "driver", "adapter", "engine", "backend", "module", "context", "connection refused",
                    "session", "ORA-", "SQLSTATE", "pg_", "mysql_", "sqlite_", "mssql_"
                ]


                error_detected = any(keyword in body for keyword in sql_error_keywords)
                reflected_fully = all(payload.lower() in body for payload in data.values())

                if error_detected:
                    vuln_entries.append({
                        "form_name": orphan.get("name", "Unnamed"),
                        "url": action_url,
                        "method": method,
                        "payload": payload,
                        "params": data,
                        "type": "error-based"
                    })
                elif reflected_fully:
                    vuln_entries.append({
                        "form_name": orphan.get("name", "Unnamed"),
                        "url": action_url,
                        "method": method,
                        "payload": payload,
                        "params": data,
                        "type": "unlikely"
                    })

            except Exception as e:
                print(f"[X] Error during SQLi test: {e}")


    if vuln_entries:
        for vuln in vuln_entries:
            if vuln["type"] == "error-based":
                print(f"[!] Possible SQLi vulnerability at {vuln['url']} ({vuln['method']})")
                print(f"[.] Payload: {vuln['payload']}")
                print(f"[.] Type: Error-based")
            elif vuln["type"] == "unlikely":
                print(f"[-] Payload reflected at {vuln['url']} — likely not injectable")
                print(f"[.] Payload: {vuln['payload']}")
    else:
        print("[✓] No possible SQL injection vulnerabilities detected.")
