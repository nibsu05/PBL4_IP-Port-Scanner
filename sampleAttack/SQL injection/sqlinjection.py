# sqlinjection.py
"""
Wrapper chạy sqlmap trên Windows - có thêm parsing/summary cho output.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
import datetime
import re

# --- Thay giá trị này theo máy bạn ---
USER_SITE_PACKAGES = r"C:\Users\ADMIN\AppData\Local\Programs\Python\Python312\Lib\site-packages"
# -------------------------------------

# --- Các mẫu để tìm trong stdout của sqlmap ---
PATTERNS = {
    "dbms": re.compile(r"back-end DBMS is:?\s*([A-Za-z0-9_\-]+)", re.IGNORECASE),
    "vulnerable_param": re.compile(r"parameter '([^']+)' is \w+ injectable", re.IGNORECASE),
    "vulnerable": re.compile(r"is vulnerable", re.IGNORECASE),
    "technique": re.compile(r"for the (?:payload|technique):\s*(.+)", re.IGNORECASE),
    "error": re.compile(r"\[ERROR\]\s*(.+)"),
    "warning": re.compile(r"\[WARNING\]\s*(.+)"),
    "tables": re.compile(r"Tables found:\s*(.+)", re.IGNORECASE),
    "databases": re.compile(r"available databases:\s*(.+)", re.IGNORECASE),
    "dumped": re.compile(r"dumped:\s*(.+)", re.IGNORECASE),
    "retrieved": re.compile(r"retrieved:\s*(.+)", re.IGNORECASE),
    "os_cmd": re.compile(r"exec\('(.+)'\)", re.IGNORECASE),
}

def find_sqlmap():
    exe = shutil.which("sqlmap")
    if exe:
        return exe

    sp = Path(USER_SITE_PACKAGES)
    try:
        python_root = sp.parents[1]
        scripts_dir = python_root / "Scripts"
    except Exception:
        scripts_dir = sp.parent.parent / "Scripts"

    candidates = [
        scripts_dir / "sqlmap.exe",
        scripts_dir / "sqlmap",
        scripts_dir / "sqlmap-script.py",
        scripts_dir / "sqlmap.py",
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    possible = [
        Path(sys.prefix) / "Scripts" / "sqlmap.exe",
        Path(sys.prefix) / "Scripts" / "sqlmap",
        Path.home() / "AppData" / "Roaming" / "Python" / "Python312" / "Scripts" / "sqlmap.exe",
    ]
    for p in possible:
        if p.exists():
            return str(p)
    return None

def run_sqlmap(sqlmap_path, args_list, timeout):
    p = Path(sqlmap_path)
    if p.suffix.lower() in {".py"} and not p.name.lower().endswith(".exe"):
        cmd = [sys.executable, str(p)] + args_list
    else:
        cmd = [str(p)] + args_list

    started = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = Path.cwd() / f"sqlmap_output_{started}.txt"
    err_file = Path.cwd() / f"sqlmap_error_{started}.txt"

    try:
        print("Chạy command:", " ".join(cmd))
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out_text = completed.stdout or ""
        err_text = completed.stderr or ""

        out_file.write_text(out_text, encoding="utf-8")
        err_file.write_text(err_text, encoding="utf-8")

        return completed.returncode, str(out_file), str(err_file), started
    except subprocess.TimeoutExpired as e:
        msg = f"sqlmap timed out after {timeout} seconds.\n{e}"
        timeout_file = Path.cwd() / f"sqlmap_timeout_{started}.txt"
        timeout_file.write_text(msg, encoding="utf-8")
        return -1, None, None, started
    except Exception as e:
        return -2, None, str(e), started

def parse_sqlmap_output(out_text):
    """
    Parse sqlmap stdout text and return a dict summary.
    We search for common markers/patterns. This is heuristic — sqlmap output format may vary.
    """
    summary = {
        "dbms": set(),
        "vulnerable_params": set(),
        "warnings": [],
        "errors": [],
        "other": []
    }

    # Normalize lines
    lines = out_text.splitlines()
    joined = "\n".join(lines)

    # quick checks for common keywords
    for key, pat in PATTERNS.items():
        for m in pat.finditer(joined):
            if key == "dbms":
                summary["dbms"].add(m.group(1).strip())
            elif key == "vulnerable_param":
                summary["vulnerable_params"].add(m.group(1).strip())
            elif key == "warning":
                summary["warnings"].append(m.group(1).strip())
            elif key == "error":
                summary["errors"].append(m.group(1).strip())
            else:
                summary["other"].append(f"{key}: {m.group(1).strip()}")

    # Additional heuristics
    if re.search(r"all tested parameters do not appear to be injectable", joined, re.IGNORECASE):
        summary["other"].append("No injectable parameters found.")
    if re.search(r"could be unstable|back-end DBMS is unknown", joined, re.IGNORECASE):
        summary["warnings"].append("DBMS unknown or behavior unstable.")
    if re.search(r"heuristic check|possible injection", joined, re.IGNORECASE):
        summary["other"].append("Heuristic/possible injection found — manual verification recommended.")

    return summary

def write_summary_file(started, summary, out_path):
    summary_file = Path.cwd() / f"sqlmap_summary_{started}.txt"
    lines = []
    lines.append(f"Summary generated: {datetime.datetime.now().isoformat()}")
    lines.append("")
    if summary["dbms"]:
        lines.append("Detected DBMS:")
        for db in summary["dbms"]:
            lines.append("  - " + db)
        lines.append("")
    if summary["vulnerable_params"]:
        lines.append("Vulnerable parameters:")
        for p in summary["vulnerable_params"]:
            lines.append("  - " + p)
        lines.append("")
    if summary["warnings"]:
        lines.append("Warnings:")
        for w in summary["warnings"]:
            lines.append("  - " + w)
        lines.append("")
    if summary["errors"]:
        lines.append("Errors (from sqlmap stderr/stdout):")
        for e in summary["errors"]:
            lines.append("  - " + e)
        lines.append("")
    if summary["other"]:
        lines.append("Other findings:")
        for o in summary["other"]:
            lines.append("  - " + o)
        lines.append("")

    lines.append(f"Full stdout saved at: {out_path}")
    summary_file.write_text("\n".join(lines), encoding="utf-8")
    return str(summary_file)

def build_args_from_cli(args):
    args_list = []
    if args.url:
        args_list += ["-u", args.url]
    if args.data:
        args_list += ["--data", args.data]
    if args.cookie:
        args_list += ["--cookie", args.cookie]
    if args.batch or (args.args and "--batch" in args.args):
        args_list += ["--batch"]
    if args.level:
        args_list += ["--level", str(args.level)]
    if args.risk:
        args_list += ["--risk", str(args.risk)]
    if args.args:
        extra = args.args.strip()
        if extra:
            args_list += extra.split()
    return args_list

def main():
    parser = argparse.ArgumentParser(description="Wrapper sqlmap with basic parsing/summary.")
    parser.add_argument("--url", "-u", help="Target URL", required=True)
    parser.add_argument("--data", help="POST data if needed")
    parser.add_argument("--cookie", help="Cookie header if needed")
    parser.add_argument("--batch", action="store_true", help="Non-interactive")
    parser.add_argument("--level", type=int, default=2, help="sqlmap --level (1-5)")
    parser.add_argument("--risk", type=int, default=1, help="sqlmap --risk (1-3)")
    parser.add_argument("--args", help="Extra args for sqlmap (e.g. '--dbs --threads=5')")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout seconds")
    parser.add_argument("--show-path", action="store_true", help="Show found sqlmap path")
    parsed = parser.parse_args()

    sqlmap_path = find_sqlmap()
    if not sqlmap_path:
        print("Không tìm thấy sqlmap. Kiểm tra pip/ thêm Scripts vào PATH.")
        print("Site-packages:", USER_SITE_PACKAGES)
        sys.exit(1)

    if parsed.show_path:
        print("Đường dẫn sqlmap tìm được:", sqlmap_path)
        sys.exit(0)

    args_list = build_args_from_cli(parsed)
    rc, out_path, err_path, started = run_sqlmap(sqlmap_path, args_list, parsed.timeout)

    if rc == 0 and out_path:
        print("sqlmap chạy xong. Kết quả stdout lưu tại:", out_path)
        try:
            out_text = Path(out_path).read_text(encoding="utf-8")
        except Exception:
            out_text = ""
        summary = parse_sqlmap_output(out_text)

        # in tóm tắt nhanh ra console
        if summary["dbms"]:
            print("Detected DBMS:", ", ".join(summary["dbms"]))
        if summary["vulnerable_params"]:
            print("Vulnerable parameters:", ", ".join(summary["vulnerable_params"]))
        if summary["warnings"]:
            print("Warnings:", "; ".join(summary["warnings"]))
        if summary["errors"]:
            print("Errors found (see summary file):")
            for e in summary["errors"]:
                print(" -", e)
        if not (summary["dbms"] or summary["vulnerable_params"] or summary["warnings"] or summary["errors"]):
            print("Không tìm thấy dấu hiệu rõ ràng. Kiểm tra file đầy đủ nếu cần.")

        summary_file = write_summary_file(started, summary, out_path)
        print("Summary file:", summary_file)

        if err_path:
            try:
                err_content = Path(err_path).read_text(encoding="utf-8")
                if err_content.strip():
                    print("Có nội dung trên stderr (xem file):", err_path)
            except Exception:
                pass
    elif rc == -1:
        print("Quá thời gian chờ. sqlmap bị timeout.")
    elif rc == -2:
        print("Lỗi khi cố chạy sqlmap. Chi tiết:", out_path)
    else:
        print(f"sqlmap trả về mã lỗi {rc}. Xem các file stdout/stderr nếu có.")

if __name__ == "__main__":
    main()

#py -3 sqlinjection.py --url "http://localhost:5038/Product/Details/3" --batch --level 2 --risk 1

#python sqlinjection.py --url "http://localhost:5038/Buyer/EditComment" --data '{"ReviewId":12,"Content":"Đánh giá test"}' --batch --level 3 --risk 2 --args "--headers='Content-Type: application/json' --proxy=http://127.0.0.1:8080"