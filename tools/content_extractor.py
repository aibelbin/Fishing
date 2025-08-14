import os
import sys
import csv
import json
import hashlib
import asyncio
import ssl as sslmod
import socket
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from PIL import Image
import imagehash
import pytesseract
import aiohttp
from aiohttp import ClientSession
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

def read_domains(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        out = []
        for row in r:
            d = str(row.get("domain", "")).strip().lower()
            res = str(row.get("resolvable", "")).strip().lower() in {"1", "true", "yes"}
            reg = str(row.get("registered", "")).strip().lower() in {"1", "true", "yes"}
            if d and res and reg:
                out.append(d)
    return out

async def fetch_ssl_info(domain: str, timeout: float = 10.0) -> Dict[str, str]:
    ctx = sslmod.create_default_context()
    try:
        loop = asyncio.get_running_loop()
        def get_cert():
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        cert = await loop.run_in_executor(None, get_cert)
    except Exception:
        return {}
    out = {}
    try:
        issuer = cert.get("issuer")
        if issuer:
            out["issuer"] = ", ".join("=".join([a for a in t if a]) for t in [[x[0][0], x[0][1]] for x in issuer if x and x[0] and len(x[0]) >= 2])
    except Exception:
        pass
    try:
        not_before = cert.get("notBefore")
        if not_before:
            out["valid_from"] = not_before
    except Exception:
        pass
    try:
        not_after = cert.get("notAfter")
        if not_after:
            out["valid_to"] = not_after
    except Exception:
        pass
    return out

def flag_ssl(cert: Dict[str, str]) -> Dict[str, bool]:
    flags = {"recent": False, "self_signed": False, "untrusted": False}
    try:
        vf = cert.get("valid_from")
        if vf:
            dt = datetime.strptime(vf, "%b %d %H:%M:%S %Y %Z")
            if datetime.utcnow() - dt < timedelta(days=30):
                flags["recent"] = True
    except Exception:
        pass
    try:
        issuer = cert.get("issuer", "").lower()
        if issuer:
            if "commonname=%s" % "%s" in issuer:
                flags["self_signed"] = True
            trusted = ["let's encrypt", "google trust services", "sectigo", "digicert", "globalsign", "amazon", "buypass", "godaddy"]
            if not any(t in issuer for t in trusted):
                flags["untrusted"] = True
    except Exception:
        pass
    return flags

async def download_file(session: ClientSession, url: str, path: str, timeout: float = 20.0) -> bool:
    try:
        async with session.get(url, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            data = await resp.read()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return True
    except Exception:
        return False

def compute_md5(path: str) -> str:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def compute_phash(path: str) -> str:
    try:
        with Image.open(path) as im:
            return str(imagehash.phash(im))
    except Exception:
        return ""

async def capture_page(pw, domain: str, out_dir: str) -> Tuple[str, str, str]:
    url = "https://" + domain
    browser = await pw.chromium.launch(headless=True)
    context = await browser.new_context(user_agent=UA, viewport={"width": 1920, "height": 1080})
    page = await context.new_page()
    try:
        await page.goto(url, wait_until="networkidle", timeout=45000)
    except Exception:
        try:
            url = "http://" + domain
            await page.goto(url, wait_until="networkidle", timeout=45000)
        except Exception:
            await context.close()
            await browser.close()
            return "", "", ""
    full_png = os.path.join(out_dir, "full.png")
    top_png = os.path.join(out_dir, "top.png")
    html_path = os.path.join(out_dir, "page.html")
    try:
        await page.screenshot(path=full_png, full_page=True)
    except Exception:
        pass
    try:
        await page.screenshot(path=top_png, full_page=False)
    except Exception:
        pass
    try:
        html = await page.content()
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception:
        pass
    await context.close()
    await browser.close()
    return full_png, top_png, html_path

def parse_meta(html: str) -> Dict[str, str]:
    out = {}
    try:
        soup = BeautifulSoup(html, "html.parser")
        t = soup.find("title")
        if t and t.text:
            out["title"] = t.text.strip()
        md = soup.find("meta", attrs={"name": "description"})
        if md and md.get("content"):
            out["description"] = md.get("content").strip()
        ogt = soup.find("meta", attrs={"property": "og:title"})
        if ogt and ogt.get("content"):
            out["og:title"] = ogt.get("content").strip()
        ogd = soup.find("meta", attrs={"property": "og:description"})
        if ogd and ogd.get("content"):
            out["og:description"] = ogd.get("content").strip()
    except Exception:
        pass
    return out

def extract_favicon_url(html: str, base_url: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        link = soup.find("link", rel=lambda v: v and "icon" in v)
        if link and link.get("href"):
            href = link.get("href").strip()
            if href.startswith("http://") or href.startswith("https://"):
                return href
            if href.startswith("//"):
                return "https:" + href
            return base_url.rstrip("/") + "/" + href.lstrip("/")
    except Exception:
        pass
    return base_url.rstrip("/") + "/favicon.ico"

def extract_images(html: str, base_url: str) -> List[str]:
    urls = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for img in soup.find_all("img"):
            src = img.get("src")
            if not src:
                continue
            s = src.strip()
            if s.startswith("http://") or s.startswith("https://"):
                urls.append(s)
            elif s.startswith("//"):
                urls.append("https:" + s)
            else:
                urls.append(base_url.rstrip("/") + "/" + s.lstrip("/"))
    except Exception:
        pass
    return urls

async def ocr_image(path: str) -> str:
    try:
        return pytesseract.image_to_string(Image.open(path))
    except Exception:
        return ""

async def process_domain(pw, session: ClientSession, domain: str, out_root: str) -> None:
    ddir = os.path.join(out_root, domain)
    os.makedirs(ddir, exist_ok=True)
    full_png, top_png, html_path = await capture_page(pw, domain, ddir)
    html = ""
    if os.path.isfile(html_path):
        try:
            with open(html_path, "r", encoding="utf-8") as f:
                html = f.read()
        except Exception:
            html = ""
    meta = parse_meta(html) if html else {}
    with open(os.path.join(ddir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False)
    base_url = "https://" + domain
    fav_url = extract_favicon_url(html or "", base_url)
    fav_path = os.path.join(ddir, "favicon.png")
    ok = await download_file(session, fav_url, fav_path)
    if ok:
        md5 = compute_md5(fav_path)
        ph = compute_phash(fav_path)
        with open(os.path.join(ddir, "favicon_md5.txt"), "w", encoding="utf-8") as f:
            f.write(md5)
        with open(os.path.join(ddir, "favicon_phash.txt"), "w", encoding="utf-8") as f:
            f.write(ph)
    imgs = extract_images(html or "", base_url)
    imgs_dir = os.path.join(ddir, "images")
    os.makedirs(imgs_dir, exist_ok=True)
    dl_tasks = []
    for i, u in enumerate(imgs, 1):
        ipath = os.path.join(imgs_dir, f"image{i}.png")
        dl_tasks.append(download_file(session, u, ipath))
    if dl_tasks:
        await asyncio.gather(*dl_tasks, return_exceptions=True)
    ocr_texts = []
    for name in sorted(os.listdir(imgs_dir)):
        p = os.path.join(imgs_dir, name)
        if os.path.isfile(p):
            try:
                txt = await ocr_image(p)
            except Exception:
                txt = ""
            if txt:
                ocr_texts.append({"file": name, "text": txt})
    with open(os.path.join(ddir, "ocr_text.txt"), "w", encoding="utf-8") as f:
        for item in ocr_texts:
            f.write(item["file"] + "\n")
            f.write(item["text"] + "\n\n")
    cert = await fetch_ssl_info(domain)
    flags = flag_ssl(cert) if cert else {}
    with open(os.path.join(ddir, "ssl.json"), "w", encoding="utf-8") as f:
        json.dump({"cert": cert, "flags": flags}, f, ensure_ascii=False)

async def bounded_sem(sem, coro):
    async with sem:
        return await coro

async def run_pipeline():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    src_dir = os.path.join(root, "sus1")
    out_root = os.path.join(root, "data")
    os.makedirs(out_root, exist_ok=True)
    files = [os.path.join(src_dir, f) for f in os.listdir(src_dir) if f.endswith(".csv")]
    domains = []
    for p in files:
        domains.extend(read_domains(p))
    seen = set()
    uniq = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    sem = asyncio.Semaphore(5)
    async with async_playwright() as pw:
        async with aiohttp.ClientSession() as session:
            tasks = []
            for d in uniq:
                tasks.append(bounded_sem(sem, process_domain(pw, session, d, out_root)))
            for i in range(0, len(tasks), 50):
                batch = tasks[i:i+50]
                await asyncio.gather(*batch, return_exceptions=True)

def main():
    try:
        asyncio.run(run_pipeline())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()