# MITM_fixed.py
# mitmproxy addon — logs requests/responses and websocket messages, saves JSON captures.
# Usage: mitmweb -s MITM_fixed.py --listen-port 8080

from mitmproxy import ctx, http, websocket
import os, time, json

CAP_DIR = "mitm_captures"
os.makedirs(CAP_DIR, exist_ok=True)

def now_ts():
    return time.strftime("%Y%m%d_%H%M%S")

def save_flow_file(prefix, identifier, data):
    ts = now_ts()
    fname = os.path.join(CAP_DIR, f"{ts}_{prefix}_{identifier}.json")
    try:
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        ctx.log.info(f"Saved capture: {fname}")
    except Exception as e:
        ctx.log.warn(f"Failed saving capture {fname}: {e}")

class FullInspector:
    def request(self, flow: http.HTTPFlow):
        try:
            ctx.log.info(f"REQ -> {flow.request.method} {flow.request.pretty_url}")
            req_text = flow.request.get_text(errors="replace") if flow.request.content else ""
            req_data = {
                "id": flow.id,
                "when": now_ts(),
                "type": "request",
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "text": req_text
            }
            save_flow_file("req", flow.id, req_data)
        except Exception as e:
            ctx.log.warn(f"Request handler error: {e}")

    def response(self, flow: http.HTTPFlow):
        try:
            status = flow.response.status_code if flow.response else None
            ctx.log.info(f"RESP <- {status} {flow.request.pretty_url}")
            resp_text = flow.response.get_text(errors="replace") if flow.response and flow.response.content else ""
            resp_data = {
                "id": flow.id,
                "when": now_ts(),
                "type": "response",
                "url": flow.request.pretty_url,
                "status": status,
                "headers": dict(flow.response.headers) if flow.response else {},
                "text": resp_text
            }
            save_flow_file("resp", flow.id, resp_data)
        except Exception as e:
            ctx.log.warn(f"Response handler error: {e}")

    # This signature works across mitmproxy versions: (flow, message)
    def websocket_message(self, flow, message):
        """
        Called per websocket message.
        message may have attributes .from_client (bool) and .content or .text
        We'll try to extract text if possible, otherwise repr binary content.
        """
        try:
            direction = "client->server" if getattr(message, "from_client", False) else "server->client"
            # try text first
            content = None
            if hasattr(message, "text") and message.text is not None:
                content = message.text
            elif hasattr(message, "content"):
                # bytes or other
                try:
                    content = message.content.decode("utf-8", errors="replace")
                except Exception:
                    content = repr(message.content)
            else:
                content = repr(message)

            ctx.log.info(f"WS {direction} {flow.server_conn.address} preview: {content[:500]}")
            ws_data = {
                "id": flow.id,
                "when": now_ts(),
                "direction": direction,
                "from": str(flow.client_conn.address) if getattr(flow, "client_conn", None) else None,
                "to": str(flow.server_conn.address) if getattr(flow, "server_conn", None) else None,
                "content": content
            }
            # Save each ws message with flow id + timestamp
            save_flow_file("wsmsg", f"{flow.id}_{int(time.time()*1000)}", ws_data)
        except Exception as e:
            ctx.log.warn(f"Websocket handler error: {e}")

addons = [FullInspector()]
