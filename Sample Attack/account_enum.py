# register_gui.py
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import threading, requests, time, os, re, tempfile, webbrowser, random, csv
from datetime import datetime
from bs4 import BeautifulSoup

# ========== CONFIG ==========
BASE_URL = "http://localhost:5038"
REGISTER_PATH = "/Account/Register"
FULL_REGISTER_URL = BASE_URL + REGISTER_PATH

USERNAME_PREFIX = "auto_user"
DEFAULT_PASSWORD = "123456789"
NUM_ACCOUNTS = 20   # chỉ dùng nếu không load từ file
PASSFILE = "accounts.csv"  # optional CSV: Account,Password,Name,Date,Sex,PhoneNumber,RoleName
BASE_DELAY = 0.5
MAX_DELAY = 30
BACKOFF_FACTOR = 2.0
MAX_RETRIES = 4
# ============================

session = requests.Session()
session.headers.update({
    "User-Agent": "register-gui/1.0",
    "Accept": "text/html,application/xhtml+xml"
})

responses = {}   # account -> raw response str
bodies = {}      # account -> response body (HTML)
current_delay = BASE_DELAY
delay_lock = threading.Lock()

# ---------- helpers ----------
def fetch_csrf_token():
    """GET page to get __RequestVerificationToken value (and cookies)."""
    try:
        r = session.get(FULL_REGISTER_URL, timeout=15)
        r.raise_for_status()
    except Exception as e:
        return None, f"ERROR fetching register page: {e}"
    # parse token from HTML
    soup = BeautifulSoup(r.text, "html.parser")
    inp = soup.find("input", {"name": "__RequestVerificationToken"})
    token = inp["value"] if inp and inp.has_attr("value") else None
    return token, None

def build_raw_response_from_req(r):
    try:
        status_line = f"HTTP/1.1 {r.status_code} {r.reason}"
        headers_lines = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body = r.text or ""
        return f"{status_line}\n{headers_lines}\n\n{body}"
    except Exception as e:
        return f"ERROR building response: {e}"

def strip_tags(html):
    return re.sub(r'<[^>]+>', '', html)

def create_temp_html(body):
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".html", prefix="register_resp_")
    tf.write(body.encode("utf-8", errors="ignore"))
    tf.flush(); tf.close()
    return tf.name

# ---------- registration with backoff ----------
def submit_register_with_backoff(account):
    """
    account: dict with keys matching form field names expected by server.
    Returns raw_response_text or error message.
    """
    global current_delay
    attempt = 0
    while attempt <= MAX_RETRIES:
        attempt += 1

        # GET token before POST
        token, err = fetch_csrf_token()
        if err:
            return err
        if not token:
            return "NO_CSRF_TOKEN_FOUND"

        data = {
            "Account": account["Account"],
            "Password": account["Password"],
            "RePassword": account["RePassword"],
            "Name": account["Name"],
            "Date": account["Date"],
            "__Invariant": account.get("__Invariant","Date"),
            "Sex": account.get("Sex","0"),
            "PhoneNumber": account["PhoneNumber"],
            "RoleName": account.get("RoleName","Buyer"),
            "__RequestVerificationToken": token
        }

        try:
            r = session.post(FULL_REGISTER_URL, data=data, timeout=20, allow_redirects=True)
        except Exception as e:
            return f"ERROR POST: {e}"

        # if 429 -> backoff logic and retry
        if r.status_code == 429:
            ra = r.headers.get("Retry-After")
            if ra:
                try:
                    wait = int(ra)
                except:
                    wait = int(current_delay)
            else:
                wait = int(current_delay)
            # increase global delay
            with delay_lock:
                current_delay = min(MAX_DELAY, max(current_delay * BACKOFF_FACTOR, current_delay + 1))
            if attempt > MAX_RETRIES:
                raw = build_raw_response_from_req(r)
                # store body too
                bodies[account["Account"]] = r.text or ""
                return raw
            time.sleep(wait)
            continue

        # not 429 -> reset delay
        with delay_lock:
            current_delay = BASE_DELAY

        bodies[account["Account"]] = r.text or ""
        return build_raw_response_from_req(r)

    return "No response recorded."

# ---------- accounts loading / generation ----------
def load_accounts_from_csv(path):
    if not os.path.exists(path):
        return None
    res = []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # ensure required keys exist; normalize
                acct = {
                    "Account": row.get("Account") or row.get("account") or "",
                    "Password": row.get("Password") or row.get("password") or DEFAULT_PASSWORD,
                    "RePassword": row.get("RePassword") or row.get("RePassword") or row.get("Repassword") or row.get("repassword") or DEFAULT_PASSWORD,
                    "Name": row.get("Name") or row.get("name") or "Auto User",
                    "Date": row.get("Date") or row.get("date") or "2025-10-01",
                    "__Invariant": row.get("__Invariant") or "Date",
                    "Sex": row.get("Sex") or "0",
                    "PhoneNumber": row.get("PhoneNumber") or row.get("phone") or "",
                    "RoleName": row.get("RoleName") or "Buyer"
                }
                res.append(acct)
    except Exception:
        return None
    return res

def generate_accounts(n):
    res = []
    base_phone = 900000000  # will prefix with 0 to get 10 digits
    for i in range(n):
        uname = f"{USERNAME_PREFIX}{int(time.time())%10000}{random.randint(0,9999)}_{i}"
        phone = f"0{base_phone + i}"
        res.append({
            "Account": uname,
            "Password": DEFAULT_PASSWORD,
            "RePassword": DEFAULT_PASSWORD,
            "Name": f"Le Van Dat {i}",
            "Date": "2025-10-01",
            "__Invariant": "Date",
            "Sex": "0",
            "PhoneNumber": phone,
            "RoleName": "Buyer"
        })
    return res

# ========== GUI ==========
def attack_thread():
    # load accounts: prefer CSV if exists
    accounts = load_accounts_from_csv(PASSFILE)
    if accounts is None:
        accounts = generate_accounts(NUM_ACCOUNTS)

    # init listbox
    def _init():
        listbox.delete(0, tk.END)
        for acc in accounts:
            listbox.insert(tk.END, f"[WAIT] {acc['Account']}")
            listbox.itemconfig(tk.END, fg='gray')
    root.after(0, _init)

    for idx, acc in enumerate(accounts):
        acc_name = acc["Account"]
        # mark sending
        def _mark_send(i, a):
            listbox.delete(i); listbox.insert(i, f"[SENDING] {a}"); listbox.itemconfig(i, fg='orange')
        root.after(0, _mark_send, idx, acc_name)

        raw = submit_register_with_backoff(acc)
        responses[acc_name] = raw  # raw headers+body
        # raw stored; body stored in bodies[]

        # mark done
        def _mark_done(i, a):
            listbox.delete(i); listbox.insert(i, f"[DONE] {a}"); listbox.itemconfig(i, fg='black')
        root.after(0, _mark_done, idx, acc_name)

        # log and delay based on current_delay
        with delay_lock:
            wait = current_delay
        log.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Sent {acc_name}. Waiting {wait}s\n")
        log.see(tk.END)
        time.sleep(wait)

    log.insert(tk.END, "✅ Done sending all accounts.\n")

def on_select(event):
    sel = listbox.curselection()
    if not sel:
        return
    idx = sel[0]
    label = listbox.get(idx)
    try:
        acct = label.split("] ", 1)[1]
    except:
        acct = label
    raw = responses.get(acct, "(no raw response)")
    body = bodies.get(acct, "")
    # update raw tab
    raw_box.config(state='normal'); raw_box.delete("1.0", tk.END); raw_box.insert(tk.END, raw); raw_box.config(state='disabled')
    # update rendered tab:
    # try to use tkhtmlview if available
    try:
        from tkhtmlview import HTMLLabel
        html_lbl.config(html=body)
        render_frame_open_button.config(state='disabled')
    except Exception:
        # save temp file and enable open in browser
        if body:
            tmp = create_temp_html(body)
            render_frame_open_button.config(command=lambda p=tmp: webbrowser.open("file://" + p))
            render_frame_open_button.config(state='normal')
            rendered_plain = strip_tags(body)[:50000]
            rendered_text.config(state='normal'); rendered_text.delete("1.0", tk.END); rendered_text.insert(tk.END, rendered_plain); rendered_text.config(state='disabled')
        else:
            render_frame_open_button.config(state='disabled')
            rendered_text.config(state='normal'); rendered_text.delete("1.0", tk.END); rendered_text.insert(tk.END, "(No body)"); rendered_text.config(state='disabled')

# GUI build
root = tk.Tk()
root.title("Bulk Register GUI (Backoff on 429)")
root.geometry("1100x700")

left = tk.Frame(root); left.pack(side='left', fill='y', padx=8, pady=8)
tk.Label(left, text="Accounts").pack()
listbox = tk.Listbox(left, width=45, height=35)
listbox.pack(side='left', fill='y')
listbox.bind("<<ListboxSelect>>", on_select)
scroll = tk.Scrollbar(left); scroll.pack(side='right', fill='y')
listbox.config(yscrollcommand=scroll.set); scroll.config(command=listbox.yview)

right = tk.Frame(root); right.pack(side='right', fill='both', expand=True, padx=8, pady=8)
tk.Label(right, text="Response (select an account)").pack()

# Notebook for Raw / Rendered
nb = ttk.Notebook(right); nb.pack(fill='both', expand=True)
# Raw tab
raw_tab = tk.Frame(nb); nb.add(raw_tab, text="Raw")
raw_box = scrolledtext.ScrolledText(raw_tab, wrap='word'); raw_box.pack(fill='both', expand=True); raw_box.config(state='disabled')
# Rendered tab
render_tab = tk.Frame(nb); nb.add(render_tab, text="Rendered")
# try HTMLLabel area and fallback text + open button
try:
    from tkhtmlview import HTMLLabel
    html_lbl = HTMLLabel(render_tab, html="", width=80, height=40)
    html_lbl.pack(fill='both', expand=True)
    render_frame_open_button = tk.Button(render_tab, text="Open in browser", state='disabled')
    render_frame_open_button.pack(pady=4)
except Exception:
    rendered_text = scrolledtext.ScrolledText(render_tab, wrap='word'); rendered_text.pack(fill='both', expand=True); rendered_text.config(state='disabled')
    render_frame_open_button = tk.Button(render_tab, text="Open in browser (no renderer available)", state='disabled')
    render_frame_open_button.pack(pady=4)

bottom = tk.Frame(root); bottom.pack(side='bottom', fill='x', padx=8, pady=6)
status_label = tk.Label(bottom, text="Ready.")
status_label.pack(side='left', padx=6)
start_btn = tk.Button(bottom, text="Start Sending", command=lambda: threading.Thread(target=attack_thread, daemon=True).start())
start_btn.pack(side='left', padx=6)

log = scrolledtext.ScrolledText(root, height=6); log.pack(side='bottom', fill='x', padx=8, pady=6)

# pre-populate accounts list visually (either CSV or generated)
acct_preview = load_accounts_from_csv(PASSFILE) or generate_accounts(NUM_ACCOUNTS)
for a in acct_preview:
    listbox.insert(tk.END, f"[WAIT] {a['Account']}")
    listbox.itemconfig(tk.END, fg='gray')

root.mainloop()
