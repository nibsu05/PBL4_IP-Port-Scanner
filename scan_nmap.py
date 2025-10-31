#!/usr/bin/env python3
"""
scan_nmap_discord.py (extended with removal detection)
- Quét port trên target chính
- Quét subnet để phát hiện host mới
- Gửi Discord webhook và Telegram khi:
  + Lần đầu chạy (báo toàn bộ port target chính)
  + Target chính mở thêm port
  + Target chính đóng port
  + Có host mới xuất hiện trong subnet
  + Có host biến mất khỏi subnet
"""

import subprocess
import json
import os
import time
import argparse
import logging
from dotenv import load_dotenv
import requests
from datetime import datetime

# --- CONFIG / LOAD ENV ---
load_dotenv()

WEBHOOK = os.getenv("DISCORD_WEBHOOK")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
NMAPPATH = os.getenv("NMAP_PATH")
PREV_PORTS_FILE = os.getenv("PREV_PORTS_FILE")
PREV_HOSTS_FILE = os.getenv("PREV_HOSTS_FILE")
LOG_FILE = os.getenv("LOG_FILE")

TARGET = os.getenv("TARGET")    # target chính để quét port
SUBNET = os.getenv("SUBNET")    # subnet để dò host

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# --- NMAP HELPERS ---

def run_nmap_ports(target, timeout=300):
    """Quét full port 1 target"""
    cmd = [NMAPPATH, "-p-", "-sV", "-Pn", "-oG", "-", target]
    logging.info("Running: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.stdout

def run_nmap_hosts(subnet, timeout=120):
    """Dò host sống trong subnet"""
    cmd = [NMAPPATH, "-sn", "-oG", "-", subnet]
    logging.info("Running: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.stdout

def parse_ports(out):
    ports = []
    for line in out.splitlines():
        if "Ports:" in line:
            parts = line.split("Ports:")[1].strip()
            for p in parts.split(","):
                segs = p.strip().split("/")
                if len(segs) >= 2 and segs[1] == "open":
                    ports.append(int(segs[0]))
    return sorted(set(ports))

def parse_hosts(out):
    hosts = []
    for line in out.splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            parts = line.split()
            hosts.append(parts[1])  # lấy IP
    return sorted(set(hosts))

# --- FILE HELPERS ---

def load_json(path, default):
    if os.path.exists(path):
        try:
            return json.load(open(path, "r"))
        except:
            return default
    return default

def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# --- ALERTS ---

def send_telegram(title, description, fields=None):
    """Send message to Telegram"""
    try:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        message = f"*{title}*\n\n{description}\n\n"
        
        if fields:
            for field in fields:
                message += f"*{field['name']}*: {field['value']}\n"
        
        message += f"\n*Timestamp*: {ts}"
        
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        r = requests.post(url, json=payload, timeout=10)
        logging.info("Telegram message sent. Status: %s", r.status_code)
        if r.status_code != 200:
            logging.error("Telegram API error: %s", r.text)
    except Exception as e:
        logging.error("Telegram error: %s", e)

def send_discord(title, description, fields=None, color=5814783):
    if not WEBHOOK:
        logging.error("Webhook not set")
        return
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields or []
    }
    embed["fields"].append({"name": "Timestamp", "value": ts, "inline": False})
    payload = {"username": "Webhooks BOT", "embeds": [embed]}
    try:
        r = requests.post(WEBHOOK, json=payload, timeout=10)
        logging.info("Webhook status %s", r.status_code)
    except Exception as e:
        logging.error("Webhook error: %s", e)

# --- MAIN LOGIC ---

def main():
    # 1) Scan ports on main target
    out_ports = run_nmap_ports(TARGET)
    current_ports = parse_ports(out_ports)
    prev_ports_data = load_json(PREV_PORTS_FILE, {"ports": []})
    prev_ports = prev_ports_data["ports"]

    # Check for new ports
    new_ports = [p for p in current_ports if p not in prev_ports]
    # Check for closed ports
    closed_ports = [p for p in prev_ports if p not in current_ports]

    # First run notification
    if not prev_ports:
        fields = [{"name":"Target","value":TARGET},{"name":"Open ports","value":str(current_ports)}]
        logging.info("Sending first scan notification")
        send_telegram("🔰 First scan (ports)", 
                     f"Target {TARGET} open ports: {current_ports}", 
                     fields)
        if WEBHOOK:
            send_discord("🔰 First scan (ports)", 
                        f"Target {TARGET} open ports: {current_ports}", 
                        fields)
    else:
        # New ports detected
        if new_ports:
            fields = [{"name":"Target","value":TARGET},
                     {"name":"All open ports","value":str(current_ports)},
                     {"name":"New ports","value":str(new_ports)}]
            send_discord("⚠️ New ports detected", 
                         f"Target {TARGET} has new ports: {new_ports}", 
                         fields,
                         color=15158332)  # Red color
            send_telegram("⚠️ New ports detected", 
                         f"Target {TARGET} has new ports: {new_ports}", 
                         fields)
        
        # Closed ports detected
        if closed_ports:
            fields = [{"name":"Target","value":TARGET},
                     {"name":"Current open ports","value":str(current_ports)},
                     {"name":"Closed ports","value":str(closed_ports)}]
            send_discord("🔒 Ports closed", 
                         f"Target {TARGET} has closed ports: {closed_ports}", 
                         fields,
                         color=16776960)  # Yellow color
            send_telegram("🔒 Ports closed", 
                         f"Target {TARGET} has closed ports: {closed_ports}", 
                         fields)
    
    save_json({"ports": current_ports, "ts": int(time.time())}, PREV_PORTS_FILE)

    # 2) Scan subnet hosts
    out_hosts = run_nmap_hosts(SUBNET)
    current_hosts = parse_hosts(out_hosts)
    prev_hosts_data = load_json(PREV_HOSTS_FILE, {"hosts": []})
    prev_hosts = prev_hosts_data["hosts"]

    # Check for new hosts
    new_hosts = [h for h in current_hosts if h not in prev_hosts]
    # Check for disappeared hosts
    disappeared_hosts = [h for h in prev_hosts if h not in current_hosts]

    # First run or new hosts
    if new_hosts:
        fields = [{"name":"Subnet","value":SUBNET},
                 {"name":"New hosts","value":str(new_hosts)},
                 {"name":"All active hosts","value":str(current_hosts)}]
        send_discord("🆕 New hosts detected",
                     f"New hosts appeared in {SUBNET}: {new_hosts}",
                     fields,
                     color=3447003)  # Blue color
        send_telegram("🆕 New hosts detected",
                     f"New hosts appeared in {SUBNET}: {new_hosts}",
                     fields)

    # Disappeared hosts
    if disappeared_hosts:
        fields = [{"name":"Subnet","value":SUBNET},
                 {"name":"Disappeared hosts","value":str(disappeared_hosts)},
                 {"name":"Current active hosts","value":str(current_hosts)}]
        send_discord("👻 Hosts disappeared",
                     f"Hosts disappeared from {SUBNET}: {disappeared_hosts}",
                     fields,
                     color=10181046)  # Purple color
        send_telegram("👻 Hosts disappeared",
                     f"Hosts disappeared from {SUBNET}: {disappeared_hosts}",
                     fields)

    save_json({"hosts": current_hosts, "ts": int(time.time())}, PREV_HOSTS_FILE)

    # Log summary
    logging.info("Scan completed - Target: %s ports, Subnet: %s hosts", len(current_ports), len(current_hosts))


if __name__ == "__main__":
    try:
        # Test Telegram connection
        test_message = "🔄 Scanner service started"
        send_telegram(test_message, "Port and host scanning service is starting up.", 
                     [{"name": "Status", "value": "Initializing"}])
        logging.info("Telegram connection test successful")
        
        main()
    except Exception as e:
        logging.error("Main execution error: %s", e)
        # Try to send error notification
        try:
            send_telegram("❌ Scanner Error", f"An error occurred: {str(e)}", 
                         [{"name": "Error Type", "value": type(e).__name__}])
        except:
            logging.error("Failed to send error notification")
