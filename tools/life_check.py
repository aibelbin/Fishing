import os
import sys
import csv
import socket
import concurrent.futures as cf
from typing import List, Dict, Tuple
import time
import threading
import whois

def read_domains(path: str) -> List[str]:
	with open(path, "r", encoding="utf-8", newline="") as f:
		r = csv.reader(f)
		rows = list(r)
	if not rows:
		return []
	header = [str(x).strip().lower() for x in rows[0]] if rows and any(rows[0]) else []
	idx = None
	if header:
		for i, k in enumerate(header):
			if k in {"domain", "fqdn"}:
				idx = i
				break
	out = []
	if idx is not None:
		for row in rows[1:]:
			if len(row) > idx:
				d = str(row[idx]).strip()
				if d:
					out.append(d)
	else:
		for row in rows:
			if row:
				d = str(row[0]).strip()
				if d:
					out.append(d)
	seen = set()
	uniq = []
	for d in out:
		if d not in seen:
			seen.add(d)
			uniq.append(d)
	return uniq

def read_existing(path: str) -> Dict[str, Tuple[bool, bool]]:
	if not os.path.isfile(path):
		return {}
	with open(path, "r", encoding="utf-8", newline="") as f:
		r = csv.reader(f)
		rows = list(r)
	if not rows:
		return {}
	header = [str(x).strip().lower() for x in rows[0]]
	cols = {k: i for i, k in enumerate(header)}
	need = {"domain", "resolvable", "registered"}
	if not need.issubset(cols.keys()):
		return {}
	out = {}
	for row in rows[1:]:
		try:
			d = str(row[cols["domain"]]).strip()
			rv = str(row[cols["resolvable"]]).strip().lower() in {"1", "true", "yes"}
			rg = str(row[cols["registered"]]).strip().lower() in {"1", "true", "yes"}
			if d:
				out[d] = (rv, rg)
		except Exception:
			continue
	return out

def idna(domain: str) -> str:
	try:
		return domain.encode("idna").decode("ascii")
	except Exception:
		return domain

def resolve(domain: str, timeout: float) -> bool:
	dn = idna(domain)
	try:
		res = socket.getaddrinfo(dn, None, proto=socket.IPPROTO_TCP, family=socket.AF_UNSPEC)
		return bool(res)
	except Exception:
		return False

def whois_registered(domain: str, timeout: float) -> bool:
	dn = idna(domain)
	try:
		start = time.time()
		data = whois.whois(dn)
		if data is None:
			return False
		fields = [
			getattr(data, "domain_name", None),
			getattr(data, "registrar", None),
			getattr(data, "creation_date", None),
			getattr(data, "updated_date", None),
			getattr(data, "expiration_date", None),
			getattr(data, "name_servers", None),
		]
		for v in fields:
			if v:
				return True
		return False
	except Exception:
		return False

def process_file(in_path: str, out_path: str, dns_workers: int, whois_workers: int, dns_timeout: float, whois_timeout: float) -> Tuple[int, int]:
	domains = read_domains(in_path)
	cache = read_existing(out_path)
	todo = [d for d in domains if d not in cache]
	resolvable: Dict[str, bool] = {}
	registered: Dict[str, bool] = {}
	if todo:
		with cf.ThreadPoolExecutor(max_workers=dns_workers) as ex:
			futs = {ex.submit(resolve, d, dns_timeout): d for d in todo}
			for f in cf.as_completed(futs):
				d = futs[f]
				try:
					resolvable[d] = bool(f.result())
				except Exception:
					resolvable[d] = False
		whois_targets = [d for d in todo if not resolvable.get(d, False)]
		def whois_task(d: str) -> Tuple[str, bool]:
			ok = whois_registered(d, whois_timeout)
			return d, ok
		with cf.ThreadPoolExecutor(max_workers=whois_workers) as ex:
			futs = {ex.submit(whois_task, d): d for d in whois_targets}
			for f in cf.as_completed(futs):
				try:
					d, ok = f.result()
					registered[d] = ok
				except Exception:
					d = futs[f]
					registered[d] = False
	rows = []
	for d in domains:
		if d in cache:
			rv, rg = cache[d]
		else:
			rv = resolvable.get(d, False)
			rg = registered.get(d, False)
		if rv or rg:
			rows.append((d, rv, rg))
	tmp = out_path + ".tmp"
	with open(tmp, "w", encoding="utf-8", newline="") as f:
		w = csv.writer(f)
		w.writerow(["domain", "resolvable", "registered"])
		for d, rv, rg in rows:
			w.writerow([d, "true" if rv else "false", "true" if rg else "false"])
	os.replace(tmp, out_path)
	return len(rows), len(domains)

def main():
	root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
	in_dir = os.path.join(root, "sus")
	out_dir = os.path.join(root, "sus1")
	if not os.path.isdir(in_dir):
		sys.exit(1)
	os.makedirs(out_dir, exist_ok=True)
	env_dns = os.getenv("LIFECHECK_DNS_WORKERS")
	env_whois = os.getenv("LIFECHECK_WHOIS_WORKERS")
	env_dns_timeout = os.getenv("LIFECHECK_DNS_TIMEOUT")
	env_whois_timeout = os.getenv("LIFECHECK_WHOIS_TIMEOUT")
	try:
		dns_workers = int(env_dns) if env_dns else max(8, (os.cpu_count() or 4) // 2)
	except Exception:
		dns_workers = max(8, (os.cpu_count() or 4) // 2)
	try:
		whois_workers = int(env_whois) if env_whois else 8
	except Exception:
		whois_workers = 8
	try:
		dns_timeout = float(env_dns_timeout) if env_dns_timeout else 2.0
	except Exception:
		dns_timeout = 2.0
	try:
		whois_timeout = float(env_whois_timeout) if env_whois_timeout else 10.0
	except Exception:
		whois_timeout = 10.0
	files = [f for f in os.listdir(in_dir) if f.lower().endswith(".csv")]
	total = len(files)
	if total == 0:
		return
	if not os.getenv("LIFECHECK_DNS_WORKERS"):
		cpu = os.cpu_count() or 4
		dns_workers = max(8, cpu // 2)
	if not os.getenv("LIFECHECK_WHOIS_WORKERS"):
		cpu = os.cpu_count() or 4
		whois_workers = 8 if cpu < 16 else max(8, cpu // 4)
	env_file_workers = os.getenv("LIFECHECK_FILE_WORKERS")
	try:
		file_workers = int(env_file_workers) if env_file_workers else None
	except Exception:
		file_workers = None
	if file_workers is None:
		cpu = os.cpu_count() or 4
		threads_per_file = dns_workers + whois_workers
		target_threads = cpu * 2
		file_workers = max(1, min(total, max(1, target_threads // max(1, threads_per_file))))
	print(f"files:{total} file_workers:{file_workers} dns_workers:{dns_workers} whois_workers:{whois_workers}", flush=True)
	start = time.time()
	with cf.ThreadPoolExecutor(max_workers=file_workers) as ex:
		futs = []
		for name in files:
			in_path = os.path.join(in_dir, name)
			out_path = os.path.join(out_dir, name)
			futs.append(ex.submit(process_file, in_path, out_path, dns_workers, whois_workers, dns_timeout, whois_timeout))
		done = 0
		kept_total = 0
		for i, f in enumerate(cf.as_completed(futs), 1):
			try:
				kept, count = f.result()
			except Exception:
				kept, count = 0, 0
			done += 1
			kept_total += kept
			print(f"[{done}/{total}] kept:{kept} total:{count}", flush=True)
	elapsed = int(time.time() - start)
	print(f"done files:{total} kept:{kept_total} time:{elapsed}s", flush=True)

if __name__ == "__main__":
	main()
