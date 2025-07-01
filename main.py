import os
import time
import asyncio
import math
import sys
import json
from pathlib import Path
from rich import print
from scanners import httpscan, js_vuln_scan, lfi_scan, sqli_scan, xss_scan, ssti_scan
from extras import utils
from playwright.async_api import async_playwright

async def main():
    while True:
        print("Vulnscanner CLI tool")
        print(f"{20*'-'}")
        print("1 | Start Scanning a Website")
        print("2 | Change Scanning Vectors")
        print("0 | Exit Application")
        choice = input("Please input your choice | ").strip()
        if choice == "1":
            target_url = input("Please input the website's url | ")
            target_url = await utils.sanitize(target_url)
            print(f"Scanning Website Url Now | {target_url} ")
            if utils.vectors["web_protocol"]:
                web_protocol = await httpscan.check_protocol(target_url)
            if utils.vectors["return_server_info"]:
                await httpscan.return_serverinfo(target_url)
            if utils.vectors["xss"]:
                await xss_scan.test_xss(target_url, hit=False)
            if utils.vectors["js_vulns"]:
                await js_vuln_scan.scan_page_js(target_url)
            if utils.vectors["lfi"]:
                await lfi_scan.lfi_scanner(target_url)
                if utils.vectors["blind_lfi"]:
                    await lfi_scan.blind_lfi(target_url)
            if utils.vectors["crawl"]:
                all_urls = await utils.crawl_urls(target_url)
                if len(all_urls) == 1:
                    print("No extra urls found!")
                else:
                    for idx, url in enumerate(all_urls, 1):
                        print(f"Url {idx} | {url}")
            if utils.vectors["sqli"]:
                await sqli_scan.sqli_scan(target_url)
            if utils.vectors["ssti"]:
                await ssti_scan.ssti_scan(target_url)
            print("Completed Scan...")

        elif choice == "2":
            while True:
                print("Modules:")
                print(f"{20*'-'}")
                idx = 1
                for module, status in utils.vectors.items():
                    if status:
                        print(f"Module {idx}: [green]{module} | {status}[/green]")
                    else:
                        print(f"Module {idx}: [red]{module} | {status}[/red]")
                    idx += 1
                print(f"{20*'-'}")
                choice = input("Please input which module to toggle (input the index of the module) or exit to return to menu | ")
                if choice.strip().lower() == "exit":
                    break

                try:
                    choice = int(choice.strip())
                    keys = list(utils.vectors.keys())
                    if 0 < choice < idx:
                        modulename = keys[choice-1]
                        utils.toggle_vector(modulename)
                    else:
                        print("Index out of range!")
                except ValueError:
                    print("Invalid Option!")
        elif choice == "0":
            print("Exited!")
            exit()
        else:
            print("Not a valid choice!")


        
if __name__ == "__main__":
    asyncio.run(main())