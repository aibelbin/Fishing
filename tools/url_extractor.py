import os
import sys
import subprocess
import csv
from io import StringIO
from typing import List, Dict, Tuple
import openpyxl
import time
import threading

def read_whitelist(xlsx_path: str) -> List[str]:
    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    ws = wb.active
    headers = [str(c.value).strip().lower() if c.value is not None else "" for c in next(ws.iter_rows(min_row=1, max_row=1))]
    try:
        if "whitelisted domains" in headers:
            col_idx = headers.index("whitelisted domains") + 1
        else:
            col_idx = 4
    except Exception:
        col_idx = 4
    domains = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        if len(row) >= col_idx:
            cell = row[col_idx - 1]
            if isinstance(cell, str):
                d = cell.strip().lower()
                if d and "." in d:
                    domains.append(d)
    wb.close()
    seen = set()
    out = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out

def run_dnstwist(domain: str) -> Tuple[List[str], List[Dict[str, str]]]:
    cmd = ["dnstwist", "--registered", "--format", "csv", domain]
    result = {"returncode": None, "stdout": "", "stderr": ""}
    def target():
        p = subprocess.run(cmd, capture_output=True, text=True)
        result["returncode"] = p.returncode
        result["stdout"] = p.stdout
        result["stderr"] = p.stderr
    t = threading.Thread(target=target, daemon=True)
    t.start()
    start = time.time()
    frames = ["|", "/", "-", "\\"]
    fi = 0
    while t.is_alive():
        msg = f"\r[{frames[fi]}] dnstwist {domain} {int(time.time()-start)}s"
        print(msg, end="", flush=True)
        fi = (fi + 1) % len(frames)
        time.sleep(0.15)
    print(f"\r[+] dnstwist {domain} {int(time.time()-start)}s", flush=True)
    if result["returncode"] != 0 or not result["stdout"].strip():
        return [], []
    sio = StringIO(result["stdout"])
    reader = csv.reader(sio)
    rows = list(reader)
    if not rows:
        return [], []
    header = rows[0]
    data = []
    for r in rows[1:]:
        item = {}
        for i, k in enumerate(header):
            item[str(k)] = r[i] if i < len(r) else ""
        data.append(item)
    return [str(h) for h in header], data

def read_existing_csv(path: str) -> Tuple[List[str], List[Dict[str, str]]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)
    if not rows:
        return [], []
    header = [str(x) for x in rows[0]]
    data = []
    for r in rows[1:]:
        item = {}
        for i, k in enumerate(header):
            item[k] = r[i] if i < len(r) else ""
        data.append(item)
    return header, data

def key_field(header: List[str]) -> str:
    for k in header:
        if str(k).strip().lower() in {"domain", "fqdn"}:
            return k
    return header[0] if header else "domain"

def merge_rows(h1: List[str], rows1: List[Dict[str, str]], h2: List[str], rows2: List[Dict[str, str]]) -> Tuple[List[str], List[Dict[str, str]]]:
    k1 = key_field(h1) if h1 else None
    k2 = key_field(h2) if h2 else None
    header = []
    seenh = set()
    for k in (h1 or []):
        if k not in seenh:
            seenh.add(k)
            header.append(k)
    for k in (h2 or []):
        if k not in seenh:
            seenh.add(k)
            header.append(k)
    if not header and k2:
        header = [k2]
    index = {}
    out = []
    if rows1:
        for r in rows1:
            out.append(dict(r))
            idx_key = r.get(k1) if k1 else None
            if idx_key is not None:
                index[idx_key] = len(out) - 1
    if rows2:
        for r in rows2:
            src_key = r.get(k2) if k2 else None
            if src_key is not None and src_key in index:
                i = index[src_key]
                merged = out[i]
                for k in r.keys():
                    merged[k] = r[k]
                out[i] = merged
            else:
                out.append(dict(r))
                if src_key is not None:
                    index[src_key] = len(out) - 1
    norm_out = []
    for r in out:
        norm = {}
        for k in header:
            norm[k] = r.get(k, "")
        norm_out.append(norm)
    return header, norm_out

def write_csv(path: str, header: List[str], rows: List[Dict[str, str]]):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for r in rows:
            writer.writerow([r.get(k, "") for k in header])
    os.replace(tmp, path)

def process_domain(domain: str, out_dir: str) -> Tuple[int, int]:
    h2, r2 = run_dnstwist(domain)
    if not h2 and not r2:
        return 0, 0
    out_path = os.path.join(out_dir, f"{domain}.csv")
    if os.path.isfile(out_path):
        h1, r1 = read_existing_csv(out_path)
        k1 = key_field(h1) if h1 else None
        k2 = key_field(h2) if h2 else None
        existing = set()
        if k1:
            for r in r1:
                v = r.get(k1)
                if v is not None:
                    existing.add(v)
        added = 0
        if k2:
            for r in r2:
                v = r.get(k2)
                if v is not None and v not in existing:
                    added += 1
        h, rows = merge_rows(h1, r1, h2, r2)
        write_csv(out_path, h, rows)
        return added, len(rows)
    else:
        write_csv(out_path, h2, r2)
        return len(r2), len(r2)

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    xlsx = os.path.join(root, "files", "white_list.xlsx")
    out_dir = os.path.join(root, "sus")
    if not os.path.isfile(xlsx):
        sys.exit(1)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    domains = read_whitelist(xlsx)
    total = len(domains)
    print(f"domains: {total}", flush=True)
    for i, d in enumerate(domains, 1):
        print(f"[{i}/{total}] {d}", flush=True)
        added, total_rows = process_domain(d, out_dir)
        print(f"[{i}/{total}] {d} added:{added} total:{total_rows}", flush=True)

if __name__ == "__main__":
    main()