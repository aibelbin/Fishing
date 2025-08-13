import os
import sys
import subprocess
import csv
from io import StringIO
from typing import List, Dict, Tuple, Optional
import openpyxl
import time
import threading
import concurrent.futures as cf
import requests
import json

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

def run_dnstwist(domain: str, tlds_path: Optional[str]) -> Tuple[List[str], List[Dict[str, str]]]:
    cmd = ["dnstwist", "--registered"]
    if tlds_path:
        cmd += ["--tld", tlds_path]
    cmd += ["--format", "csv", domain]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout.strip():
        return [], []
    sio = StringIO(p.stdout)
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

def process_domain(domain: str, out_dir: str, tlds_path: Optional[str]) -> Tuple[str, int, int, int]:
    s = time.time()
    h2, r2 = run_dnstwist(domain, tlds_path)
    kw_parts = domain.split('.')
    if len(kw_parts) >= 2:
        keyword = kw_parts[-2]
    else:
        keyword = kw_parts[0]
    platform_map = {"ngrok": "ngrok.io", "vercel": "vercel.app", "netlify": "netlify.app"}
    ct_rows = []
    def fetch(platform, base):
        try:
            params = {"q": f"%{keyword}%.{base}", "output": "json"}
            r = requests.get("https://crt.sh/", params=params, timeout=15)
            if r.status_code != 200:
                return []
            data = json.loads(r.text)
            out = []
            seen_local = set()
            for entry in data:
                name = entry.get("name_value")
                if not name:
                    continue
                for line in str(name).split("\n"):
                    d = line.strip().lower()
                    if d.endswith(base) and keyword in d and d not in seen_local:
                        seen_local.add(d)
                        out.append({"domain": d, "type": "ct_log", "source": platform})
            return out
        except Exception:
            return []
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(fetch, p, b) for p, b in platform_map.items()]
        for f in futs:
            try:
                ct_rows.extend(f.result())
            except Exception:
                continue
    if ct_rows:
        if not h2:
            h2 = ["domain", "type", "source"]
        existing_cols = set(h2)
        for col in ["domain", "type", "source"]:
            if col not in existing_cols:
                h2.append(col)
        r2.extend(ct_rows)
    if not h2 and not r2:
        return domain, 0, 0, int(time.time() - s)
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
        return domain, added, len(rows), int(time.time() - s)
    else:
        write_csv(out_path, h2, r2)
        return domain, len(r2), len(r2), int(time.time() - s)

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    xlsx = os.path.join(root, "files", "white_list.xlsx")
    out_dir = os.path.join(root, "sus")
    tlds_path = os.path.join(root, "files", "tlds.txt")
    if not os.path.isfile(tlds_path):
        tlds_path = None
    if not os.path.isfile(xlsx):
        sys.exit(1)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    domains = read_whitelist(xlsx)
    total = len(domains)
    env_workers = os.getenv("URL_EXTRACTOR_WORKERS")
    try:
        env_workers_val = int(env_workers) if env_workers else None
    except Exception:
        env_workers_val = None
    cpu = os.cpu_count() or 4
    workers = min(total, env_workers_val if env_workers_val and env_workers_val > 0 else cpu)
    print(f"domains:{total} workers:{workers}", flush=True)
    stop = threading.Event()
    start = time.time()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(process_domain, d, out_dir, tlds_path) for d in domains]
        def status():
            frames = ["|", "/", "-", "\\"]
            i = 0
            while not stop.is_set():
                done = sum(1 for f in futs if f.done())
                running = sum(1 for f in futs if f.running())
                pending = total - done - running
                elapsed = int(time.time() - start)
                s = f"\r[{frames[i]}] running:{running} done:{done}/{total} pending:{pending} elapsed:{elapsed}s"
                print(s, end="", flush=True)
                i = (i + 1) % 4
                time.sleep(0.2)
        th = threading.Thread(target=status, daemon=True)
        th.start()
        done_count = 0
        for f in cf.as_completed(futs):
            try:
                domain, added, total_rows, dur = f.result()
            except Exception:
                domain, added, total_rows, dur = "unknown", 0, 0, 0
            done_count += 1
            sys.stdout.write("\r" + " " * 120 + "\r")
            sys.stdout.flush()
            print(f"[{done_count}/{total}] {domain} added:{added} total:{total_rows} time:{dur}s", flush=True)
        stop.set()
        th.join()
    elapsed = int(time.time() - start)
    print(f"done elapsed:{elapsed}s", flush=True)

if __name__ == "__main__":
    main()