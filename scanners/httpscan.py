import os
import time
import requests
from extras import utils

async def check_protocol(url):
    # Test if http2 protocols are allowed
    http2_res = await utils.custom_curl(url, http2=True)
    normal_res = await utils.custom_curl(url, http2=False)

    http2_protocol = http2_res[3] if http2_res else None
    normal_protocol = normal_res[3] if normal_res else None

    if http2_res[3] == "HTTP/1.1":
        http2_protocol = None

    if http2_protocol == "HTTP/2" and normal_protocol == "HTTP/1.1":
        print("Website supports both protocols!")
        while True:
            choice = input("Which protocol to use? (h1 for http1.1, h2 for http2)")
            if choice.strip() == "h2":
                return "h2", http2_res
            elif choice.strip() == "h1":
                return "h1", normal_res
            else:
                print("Invalid Choice!") 
    elif http2_protocol == "HTTP/2" and not normal_protocol:
        print("Strange... Website only supports HTTP2!")
        return "h2", http2_res
    elif not http2_protocol and normal_protocol == "HTTP/1.1":
        print("Website only supports HTTP/1.1 !")
        return "h1", normal_res
    else:
        print("Website doesnt support any web protocols!")
        print("Exiting!")
        quit()

async def return_serverinfo(url):
    res = await utils.custom_curl(url)
    if res != "BAD_URL":
        print(res[0])
        print(res[1])
        print("Redirects")
        print("-"*40)
        await utils.display_redirects(res[2])

        print("\n[+] Final Headers:")
        print("-" * 40)
        for k, v in res[4].items():
            print(f"{k}: {v}")

        print("\n[+] Cookies:")
        print("-" * 40)
        if 'set-cookie' in res[4]:
            for cookie in res[4].get_list('set-cookie'):
                print(cookie)
        else:
            print("No Set-Cookie headers.")

        print("\n[+] Content Info:")
        print("-" * 40)
        print(f"Content-Type : {res[4].get('content-type', 'N/A')}")
        print(f"X-Powered-By: {res[4].get('x-powered-by', 'N/A')}")
        print(f"Server: {res[4].get('server', 'N/A')}")
