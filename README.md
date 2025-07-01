# Vulnscanner
 A Simple CLI python tool to scan a website for various common vulnerabilities. For example, XSS, SQLi, SSTI and directory traversal. I plan to improve this by adding much more features than the current version. The list of features that I plan / hope to add is listed below!

# ⚠️ Notes:
 Vulnscanner is heavily a POC that I made. Although it works on basic webpages with obvious vulnerabilities exposed, it will most likely not detect any vulnerabilities in actual websites due to the complexity of the websites. In the future, I might add features which make it more compatible and more viable with actual websites but for now, Vulnscanner is currently heavily a POC. Furthermore, I used AI-assistance for some parts of this project to refine some of the code I have written for this programme as well as assisting me in fixing bugs. Without AI-assistance, this project would be heavily limited with very little features and most likely will have many bugs present.

 This is also not a substitute for tools such as burpsuite or OWASP ZAP for now. This tool is just to scan for surface level vulnerabilities the website might have and it will not be a very accurate representation of the vulnerabilities present in the scanned website.

# 🛠️ Features:
 This CLI tool helps to scan a webpage for the following vulnerabilities:
 - Cross-Site Scripting (XSS)
 - Potential JavaScript code Vulnerabilities scanner (dangerous functions / prototype pollution)
 - (Blind) Local File Inclusion [LFI]
 - SQL injection (SQLi)
 - Server Side Template Injection (SSTI)
 This CLI tool also serves other aspects such as:
 - HTTP 2 Support checking
 - Server Information / Headers checking
 - Crawling all urls (Via href) that can be accessed
 - Also uses playwright to simulate an actual user entering the website (utilized together with httpx)
 

# 📅 Plans for future:
 As this project is very new, it does not have much features to it. Below is what i plan / hope to add in the future:
 - SSRF + CSRF detection vectors
 - More edge cases (possibly expose more vulnerabilities)
 - .Wasm extraction from page 
 - Maybe recreation of entire webpages
 - Possibility Registration / Login detection (If possible?)
 - Registration / Login Automation (If possible?)
 - JWT / Cookie scanner (checks if the website is using any type of JWT / cookies)
 - Extra Positional arguments (ie: allowing users to add specific fields like JWTs)
 - Possibly reading source code for common vulnerabilities in code (unlikely due to the amount of edge cases)

# 💻 Setup:
```bash
git clone https://github.com/randomguy6407/Vulnscanner.git
cd Vulnscanner
pip install -r requirements.txt
playwright install
python3 main.py
```
