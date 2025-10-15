# save as bulk_register.py
import requests
from bs4 import BeautifulSoup
import time
import random
import csv
from datetime import datetime, timedelta

# --- Cấu hình chính ---
BASE_URL = "http://localhost:5038"
REGISTER_PATH = "/Account/Register"  
FULL_REGISTER_URL = BASE_URL + REGISTER_PATH

DEFAULT_PASSWORD = "123456789"

# Tổng số account muốn gửi (ở đây tạo ~30)
NUM_ACCOUNTS = 30

# Khoảng delay giữa 2 request (giây)
DELAY_MIN = 1.0
DELAY_MAX = 3.0

DEFAULT_DATE = "2025-10-01"   # dạng YYYY-MM-DD
DEFAULT_INVARIANT = "Date"
DEFAULT_SEX = "0"             # 0 hoặc 1 tùy server
DEFAULT_ROLE = "Buyer"        # Buyer/Seller ...
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": BASE_URL,
    "Referer": FULL_REGISTER_URL,
    "Content-Type": "application/x-www-form-urlencoded"
}

# --- Tạo danh sách tài khoản và số điện thoại ---
def generate_accounts_and_phones(n):
    accounts = []
    # base phone number (10 digits) - bạn có thể đổi prefix cho phù hợp
    base_phone = 6789000000
    for i in range(n):
        username = f"user_{int(time.time()) % 10000}_{i}"  # thêm timestamp để giảm trùng lặp
        # Tạo fullname đơn giản, không dấu
        fullname = f"Le Van Dat {i}"
        phone = str(base_phone + i)
        accounts.append({
            "Account": username,
            "Password": DEFAULT_PASSWORD,
            "RePassword": DEFAULT_PASSWORD,
            "Name": fullname,
            "Date": DEFAULT_DATE,
            "__Invariant": DEFAULT_INVARIANT,
            "Sex": DEFAULT_SEX,
            "PhoneNumber": phone,
            "RoleName": DEFAULT_ROLE
        })
    return accounts

# --- Hàm lấy token __RequestVerificationToken từ trang Register ---
def fetch_csrf_token(session):
    resp = session.get(FULL_REGISTER_URL, headers=DEFAULT_HEADERS, timeout=10)
    resp.raise_for_status()
    # parse token từ html (input hidden)
    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": "__RequestVerificationToken"})
    if token_input and token_input.has_attr("value"):
        return token_input["value"]
    # fallback: có thể token nằm trong cookie; nhiều app ASP.NET dùng cookie __RequestVerificationToken nhưng
    # thông thường giá trị cũng cần gửi trong form field. Trả về None nếu không tìm.
    return None

# --- Gửi form đăng ký cho 1 account ---
def submit_registration(session, account_data, token):
    data = {
        "Account": account_data["Account"],
        "Password": account_data["Password"],
        "RePassword": account_data["RePassword"],
        "Name": account_data["Name"],
        "Date": account_data["Date"],
        "__Invariant": account_data["__Invariant"],
        "Sex": account_data["Sex"],
        "PhoneNumber": account_data["PhoneNumber"],
        "RoleName": account_data["RoleName"],
        "__RequestVerificationToken": token
    }
    # cập nhật referer header (session.get đã set trước)
    headers = DEFAULT_HEADERS.copy()
    headers["Referer"] = FULL_REGISTER_URL
    resp = session.post(FULL_REGISTER_URL, data=data, headers=headers, timeout=15, allow_redirects=True)
    return resp

# --- Main workflow ---
def main():
    accounts = generate_accounts_and_phones(NUM_ACCOUNTS)
    results = []
    s = requests.Session()

    for idx, acc in enumerate(accounts, start=1):
        try:
            print(f"[{idx}/{len(accounts)}] Preparing register for {acc['Account']} (phone {acc['PhoneNumber']})")
            # 1) GET trang đăng ký để lấy token
            token = fetch_csrf_token(s)
            if not token:
                print("  - Không tìm thấy __RequestVerificationToken trên trang. Kiểm tra form hoặc token nằm ở chỗ khác.")
                # Bạn có thể chọn break hoặc tiếp tục (ở đây ta dừng để tránh gửi request không có token)
                results.append((acc['Account'], acc['PhoneNumber'], "NO_TOKEN", None))
                break

            # 2) POST đăng ký
            resp = submit_registration(s, acc, token)
            status = resp.status_code
            # Kiểm tra redirect hoặc nội dung để biết có đăng ký thành công hay không
            success = False
            # Ví dụ: nếu server redirect về login hoặc chứa chuỗi "Registration successful"...
            if resp.history and any(r.status_code in (302, 301) for r in resp.history):
                success = True
            else:
                # Kiểm tra nội dung trả về để dự đoán thành công (tùy app)
                body = resp.text.lower()
                if "successful" in body or "đăng ký thành công" in body or "verify" in body:
                    success = True

            print(f"  - HTTP {status}  Success? {success}")
            results.append((acc['Account'], acc['PhoneNumber'], "OK" if success else "FAIL", status))
        except Exception as e:
            print(f"  - Lỗi khi đăng ký {acc['Account']}: {e}")
            results.append((acc['Account'], acc['PhoneNumber'], "ERROR", str(e)))

        # delay ngẫu nhiên để giảm tải
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

    # Lưu kết quả ra CSV
    csv_file = "results.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Account", "PhoneNumber", "Result", "Info"])
        for r in results:
            writer.writerow(r)

    print(f"Hoàn tất. Kết quả lưu ở: {csv_file}")

if __name__ == "__main__":
    main()
