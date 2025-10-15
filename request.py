# request_requests.py
import requests
import mimetypes
import os
import tempfile
import webbrowser
from urllib.parse import urlparse

url = "http://127.0.0.1:5038/Cart/Cart"

headers = {
    "Host": "localhost:5038",
    "sec-ch-ua": '"Not=A?Brand";v="24", "Chromium";v="140"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Referer": "http://localhost:5038/Product",
    "Accept-Encoding": "gzip, deflate, br",
    "Cookie": ".AspNetCore.Antiforgery.Y_gGJxvhNok=CfDJ8Iv6l09TVjhEkHv2C0PLgvnqPayAHKnF-I9Fr3YXvuhiJpgiNWwzWNnXa2qbyyZ9yXP2bnBrxziVH9setUbAjZC7zHu-KdPsI46iP-_hSzJOacQ3gGBEecygcRbtyudzlVmsT8QUWIT36zrdx3ps_m0; .AspNetCore.Session=CfDJ8Iv6l09TVjhEkHv2C0PLgvn%2FOCIAxkRSYXl0CFdt2MPYYDgdBrHFABHKqB8%2BvyGeWqFTGQheTSbK4IQ9p5SveKO5PdS2yJ60xPE2MTkGre3fPLVhgHCAusECXAytBSDBmsnfDVDIkD43FWJlCIaip51BiRfAGSSj3Xb8%2Fadm9Awi",
    "Connection": "keep-alive",
}

def save_and_render_response(resp):
    content_type = resp.headers.get("Content-Type", "")
    # Normalize content type (strip params)
    main_type = content_type.split(";")[0].strip().lower()
    # Determine file extension
    ext = None
    if main_type:
        ext = mimetypes.guess_extension(main_type.split("/")[0] + "/" + main_type.split("/")[1]) if "/" in main_type else None

    # If content looks like HTML (or unspecified), treat as text/html
    if "html" in main_type or main_type == "" or main_type.startswith("text"):
        # Choose encoding: resp.encoding (requests inferred) or fallback utf-8
        enc = resp.encoding if resp.encoding else "utf-8"
        text = resp.text  # requests will decode using encoding
        # create temp file
        suffix = ext if ext else ".html"
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=suffix, encoding=enc) as tmp:
            tmp.write(text)
            tmp_path = tmp.name
        print(f"Saved HTML to: {tmp_path}")
        # open in default browser
        webbrowser.open("file://" + os.path.abspath(tmp_path))
    else:
        # Binary (image/pdf/etc) — save raw bytes
        suffix = ext if ext else ""
        with tempfile.NamedTemporaryFile("wb", delete=False, suffix=suffix) as tmp:
            tmp.write(resp.content)
            tmp_path = tmp.name
        print(f"Saved binary response to: {tmp_path}")
        # try to open with default app (browser can open many types)
        webbrowser.open("file://" + os.path.abspath(tmp_path))

def main():
    try:
        resp = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException as e:
        print("Request failed:", e)
        return

    print("Status:", resp.status_code)
    print("--- Response headers ---")
    for k, v in resp.headers.items():
        print(f"{k}: {v}")

    # If server returned non-200, still save and open so you can see error page
    save_and_render_response(resp)

if __name__ == "__main__":
    main()
