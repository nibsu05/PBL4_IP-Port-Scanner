#!/usr/bin/env python3
# intercept_log_http.py
# HTTP proxy that logs full requests and responses and saves them to files.
# Usage: pip install requests ; python intercept_log_http.py --host 127.0.0.1 --port 8080

import argparse, socketserver, http.server, urllib.parse, requests, threading, os, time, json
from datetime import datetime

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8080
TIMEOUT = 60
BUFFER_SIZE = 8192
CAPTURE_DIR = "captures"

os.makedirs(CAPTURE_DIR, exist_ok=True)

def safe_bytes_to_str(b):
    if b is None: return ""
    try:
        return b.decode("utf-8")
    except Exception:
        try:
            return b.decode("latin-1")
        except Exception:
            return repr(b)

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log(self, *args):
        print("[" + datetime.now().strftime("%H:%M:%S") + "]", *args)

    def _save_capture(self, prefix, meta):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        fname = os.path.join(CAPTURE_DIR, f"{ts}_{prefix}.json")
        try:
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)
            self.log("Saved capture:", fname)
        except Exception as e:
            self.log("Failed saving capture:", e)

    def _handle_http(self):
        try:
            url = self.path
            if not urllib.parse.urlparse(url).scheme:
                host = self.headers.get("Host")
                if not host:
                    self.send_error(400, "Host header missing")
                    return
                url = f"http://{host}{url}"

            method = self.command
            self.log("Incoming:", method, url, "from", self.client_address[0])

            content_length = int(self.headers.get("Content-Length", 0) or 0)
            body = None
            if content_length > 0:
                try:
                    body = self.rfile.read(content_length)
                except Exception:
                    self.log("Read body failed or client closed")
                    body = None

            # build forward headers, preserve Host
            forward_headers = {}
            for k, v in self.headers.items():
                if k.lower() in ("proxy-connection", "connection", "keep-alive"):
                    continue
                forward_headers[k] = v
            parsed = urllib.parse.urlparse(url)
            forward_headers["Host"] = parsed.netloc
            forward_headers.pop("Expect", None)

            # Log request and save
            req_preview = safe_bytes_to_str(body)[:2000] if body else ""
            req_meta = {
                "type": "request",
                "method": method,
                "url": url,
                "headers": dict(forward_headers),
                "body_preview": req_preview
            }
            self.log("REQUEST HEADERS:", {k: forward_headers.get(k) for k in ("Host","User-Agent","Content-Type","Content-Length") if k in forward_headers})
            self._save_capture("request", req_meta)

            # send upstream
            try:
                resp = requests.request(method, url, headers=forward_headers, data=body, allow_redirects=False, timeout=TIMEOUT, stream=True)
            except Exception as e:
                self.log("Upstream request failed:", e)
                try:
                    self.send_error(502, f"Bad gateway: {e}")
                except Exception:
                    pass
                return

            # read response content (careful with large bodies)
            try:
                content = resp.content
            except Exception:
                content = b""

            content_preview = safe_bytes_to_str(content)[:2000]
            resp_headers = dict(resp.headers)
            resp_meta = {
                "type": "response",
                "url": url,
                "status": resp.status_code,
                "headers": resp_headers,
                "body_preview": content_preview
            }
            self.log("RESPONSE:", resp.status_code, "Content-Type:", resp_headers.get("Content-Type"))
            self._save_capture("response", resp_meta)

            # send response to client
            try:
                self.send_response(resp.status_code)
                hop_by_hop = ("Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade")
                for k, v in resp_headers.items():
                    if k.title() in hop_by_hop:
                        continue
                    try:
                        self.send_header(k, v)
                    except Exception:
                        self.send_header(k, str(v))
                self.end_headers()
                if content:
                    try:
                        self.wfile.write(content)
                    except Exception:
                        pass
            except Exception as e:
                self.log("Error sending response back to client:", e)
                return

        except Exception as e:
            self.log("Unhandled:", e)
            return

    def do_GET(self): self._handle_http()
    def do_POST(self): self._handle_http()
    def do_PUT(self): self._handle_http()
    def do_DELETE(self): self._handle_http()
    def do_OPTIONS(self): self._handle_http()
    def do_HEAD(self): self._handle_http()
    def do_PATCH(self): self._handle_http()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=LISTEN_HOST)
    parser.add_argument("--port", default=LISTEN_PORT, type=int)
    args = parser.parse_args()

    server = ThreadingTCPServer((args.host, args.port), ProxyHandler)
    print("HTTP logging proxy listening on", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down")
        server.server_close()

#python intercept.py --host 127.0.0.1 --port 8080