#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import csv
import sys
import gzip
import zlib
import json
import shutil
import hashlib
import argparse
import platform
from datetime import datetime
from collections import Counter
from html import escape as html_escape

# -------------------------------
# Discord / Chromium artifacts
# -------------------------------
ATTACHMENT_REGEX = re.compile(
    r"https://(?:cdn|media)\.discordapp\.com/attachments/[^\s\"'<>]+",
    re.IGNORECASE,
)
WEBHOOK_REGEX = re.compile(
    r"https://discord\.com/api/webhooks/[^\s\"'<>]+",
    re.IGNORECASE,
)
API_REGEX = re.compile(
    r"https://discord(?:app)?\.com/api/v\d+/[^\s\"'<>]+",
    re.IGNORECASE,
)

# --------- Magic bytes / type detection (now with WEBM/MKV) ---------
MAGIC_SIGNATURES = [
    (b"\xFF\xD8\xFF", ".jpg", "Image"),
    (b"\x89PNG\r\n\x1A\n", ".png", "Image"),
    (b"GIF87a", ".gif", "Image"),
    (b"GIF89a", ".gif", "Image"),
    # WebP (RIFF....WEBP)
    (b"RIFF", ".webp", "Image"),  # coarse; we'll refine by footer sniff
    # MP4 family
    (b"\x00\x00\x00\x18ftypmp4", ".mp4", "Video"),
    (b"\x00\x00\x00 ftypisom", ".mp4", "Video"),
    (b"\x00\x00\x00 ftypMSNV", ".mp4", "Video"),
    # Matroska / WebM / MKV (EBML)
    (b"\x1A\x45\xDF\xA3", ".webm", "Video"),  # treat MKV/WEBM as Video
]

# Some browsers write uppercase drive letters in bodies.
def normalize_path(p: str) -> str:
    return os.path.normpath(p)

# Optional Brotli
try:
    import brotli  # type: ignore
    HAS_BROTLI = True
except Exception:
    HAS_BROTLI = False

# -------------------------------
# Utilities
# -------------------------------
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def utc_iso(ts: float) -> str:
    # store in UTC for report sorting
    return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

def default_cache_dir() -> str:
    sysname = platform.system()
    if sysname == "Windows":
        return os.path.expandvars(r"%AppData%\discord\Cache\Cache_Data")
    if sysname == "Darwin":
        return os.path.expanduser("~/Library/Application Support/discord/Cache/Cache_Data")
    return os.path.expanduser("~/.config/discord/Cache/Cache_Data")

def ensure_dir(d: str) -> None:
    os.makedirs(d, exist_ok=True)

# -------------------------------
# Body decoding (handles br/gzip/deflate)
# -------------------------------
def maybe_decompress(headers: dict, body: bytes) -> bytes:
    enc = headers.get("Content-Encoding", "").lower()
    if not enc:
        return body
    try:
        if "br" in enc and HAS_BROTLI:
            return brotli.decompress(body)
        if "gzip" in enc or "x-gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body)
    except Exception:
        # Return raw if decoding fails
        return body
    return body

# -------------------------------
# Sniff magic bytes
# -------------------------------
def sniff_magic(data: bytes) -> tuple[str | None, str | None]:
    """
    Return (ext, kind) where kind is 'Image' or 'Video'
    """
    head = data[:64]
    for sig, ext, kind in MAGIC_SIGNATURES:
        if head.startswith(sig):
            # Slightly refine WebP (RIFF...WEBP) check
            if ext == ".webp" and b"WEBP" not in data[8:16]:
                continue
            return ext, kind
    return None, None

# -------------------------------
# Evidence store (relative to HTML)
# -------------------------------
class EvidenceStore:
    def __init__(self, out_dir: str, base_name: str):
        self.root = os.path.join(out_dir, f"{base_name}_media")
        ensure_dir(self.root)

    def save_bytes(self, data: bytes, suggested_ext: str, prefix: str) -> tuple[str, str]:
        """
        Save bytes to /<root>/<prefix>_<sha256><ext>, return (abs_path, rel_path)
        """
        digest = sha256_bytes(data)
        ext = suggested_ext or ".bin"
        fname = f"{prefix}_{digest}{ext}"
        abs_path = os.path.join(self.root, fname)
        if not os.path.exists(abs_path):
            with open(abs_path, "wb") as f:
                f.write(data)
        rel_path = os.path.relpath(abs_path, os.path.dirname(self.root))
        # If HTML is in out_dir, rel from HTML is `base_name_media/...`
        rel_from_html = os.path.join(os.path.basename(self.root), fname)
        return abs_path, rel_from_html

    def copy_file(self, src: str, ext_hint: str = "") -> tuple[str, str]:
        with open(src, "rb") as f:
            data = f.read()
        return self.save_bytes(data, ext_hint, prefix=os.path.basename(src))

# -------------------------------
# Parsing Chromium simple cache f_* (with body)
# -------------------------------
def parse_f_entry(abs_path: str, store: EvidenceStore, url_to_local: dict, verbose: bool) -> list[dict]:
    rows = []
    try:
        with open(abs_path, "rb") as f:
            raw = f.read()
        i = raw.find(b"\r\n\r\n")
        if i == -1:
            return rows
        header_block = raw[:i].decode(errors="ignore")
        body = raw[i + 4 :]
        # Headers -> dict
        headers = {}
        for line in header_block.split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        content_loc = headers.get("Content-Location") or headers.get("X-Original-URL") or ""
        content_type = (headers.get("Content-Type") or "").lower()
        body = maybe_decompress(headers, body)

        # Decide what this is
        ext, kind = (None, None)
        if content_type.startswith("image/"):
            ext = "." + content_type.split("/")[-1].split(";")[0]
            kind = "Image"
        elif content_type.startswith("video/"):
            ext = "." + content_type.split("/")[-1].split(";")[0]
            kind = "Video"
        else:
            # sniff magic if CT is missing or generic
            ext, kind = sniff_magic(body)

        # Save media if we believe it's image/video
        if kind in ("Image", "Video"):
            _, rel = store.save_bytes(body, ext or ".bin", prefix=os.path.basename(abs_path))
            # If we know the original URL, map it for preview pairing later
            if content_loc:
                url_to_local[content_loc] = rel
            # Add a local media row
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": kind,
                "source": "Local",
                "preview": rel,           # local preview path
                "remote": content_loc,    # may be blank
                "cache_file": abs_path,
                "sha256": sha256_bytes(body),
                "carved": 0,
            })
        else:
            # Non-media f_* bodies still might have a meaningful Content-Location (e.g., attachments URL)
            if content_loc:
                rows.append({
                    "modified": utc_iso(os.path.getmtime(abs_path)),
                    "type": "Attachment",
                    "source": "Remote",
                    "preview": "",          # no local
                    "remote": content_loc,
                    "cache_file": abs_path,
                    "sha256": sha256_file(abs_path),
                    "carved": 0,
                })
    except Exception as e:
        if verbose:
            print(f"[WARN] f_* parse failed for {abs_path}: {e}")
    return rows

# -------------------------------
# Carving
# -------------------------------
def carve_from_bytes(b: bytes, store: EvidenceStore, src_name: str) -> list[dict]:
    """
    Very light carving: find the first occurrence of known magic and carve to EOF.
    For forensic previews this is usually enough for images and WebM.
    """
    carved = []
    # scan head for any signature
    for sig, ext, kind in MAGIC_SIGNATURES:
        idx = b.find(sig)
        if idx != -1:
            chunk = b[idx:]
            _, rel = store.save_bytes(chunk, ext, prefix=f"{src_name}_carved")
            carved.append((rel, kind, sha256_bytes(chunk)))
            # do not break: there may be more than one type in the same cache file
    rows = []
    for rel, kind, digest in carved:
        rows.append({
            "modified": "",                # filled by caller
            "type": kind,                  # Image/Video
            "source": "Local",
            "preview": rel,
            "remote": "",
            "cache_file": "",              # filled by caller
            "sha256": digest,
            "carved": 1,
        })
    return rows

# -------------------------------
# Scan arbitrary cache file (no body index)
# -------------------------------
def scan_cache_file(abs_path: str, url_to_local: dict, store: EvidenceStore,
                    do_carve: bool, verbose: bool) -> list[dict]:
    rows = []
    try:
        with open(abs_path, "rb") as f:
            raw = f.read()
        text = raw.decode(errors="ignore")

        # Regex artifacts (user activity only)
        for url in ATTACHMENT_REGEX.findall(text):
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": "Attachment",
                "source": "Remote",
                "preview": url_to_local.get(url, ""),  # local preview if we captured it elsewhere
                "remote": url,
                "cache_file": abs_path,
                "sha256": sha256_file(abs_path),
                "carved": 0,
            })

        for url in WEBHOOK_REGEX.findall(text):
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": "Webhook",
                "source": "Remote",
                "preview": "",
                "remote": url,
                "cache_file": abs_path,
                "sha256": sha256_file(abs_path),
                "carved": 0,
            })

        for url in API_REGEX.findall(text):
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": "API Call",
                "source": "Remote",
                "preview": "",
                "remote": url,
                "cache_file": abs_path,
                "sha256": sha256_file(abs_path),
                "carved": 0,
            })

        # Optional carving (preview only)
        if do_carve:
            carved_rows = carve_from_bytes(raw, store, os.path.basename(abs_path))
            if carved_rows:
                for r in carved_rows:
                    r["modified"] = utc_iso(os.path.getmtime(abs_path))
                    r["cache_file"] = abs_path
                rows.extend(carved_rows)
    except Exception as e:
        if verbose:
            print(f"[WARN] scan failed for {abs_path}: {e}")
    return rows

# -------------------------------
# HTML Report
# -------------------------------
HTML_STYLE = """
<style>
:root { --bg:#0f1420; --bg2:#171e2b; --fg:#e9eef7; --mut:#93a2bd; --chip:#202a3d; --chipOn:#2b3954; --accent:#6cc7ff; --accent2:#ffd166; --ok:#66f2a3; }
*{box-sizing:border-box}
body{margin:18px;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--fg)}
h1{margin:0 0 12px 0;font-weight:700}
small{color:var(--mut)}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{padding:10px 12px;border-bottom:1px solid #223046;vertical-align:middle}
th{position:sticky;top:0;background:var(--bg2);z-index:2}
tbody tr:hover{background:rgba(255,255,255,0.04)}
a{color:var(--accent)}
.badge{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;background:var(--chip);color:var(--fg);margin-right:8px;cursor:pointer;border:1px solid #273349;font-weight:600}
.badge.on{background:var(--chipOn)}
.badge .dot{display:inline-block;width:8px;height:8px;border-radius:50%}
.dot.api{background:#6cc7ff}
.dot.att{background:#ffd166}
.dot.web{background:#f48fb1}
.dot.img{background:#80ffea}
.dot.vid{background:#a0c4ff}
.dot.carv{background:#cdb4db}
input[type=search]{width:340px;padding:8px 10px;border-radius:8px;border:1px solid #273349;background:#101726;color:var(--fg)}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.aux{margin-left:auto;color:var(--mut)}
.tag{background:#2b3954;color:#d6e4ff;padding:2px 8px;border-radius:6px;margin-left:6px;font-size:12px}
.preview img{max-height:56px;border-radius:8px}
.preview video{height:64px;border-radius:8px}
.label{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;margin-left:6px;background:#2b3954}
kbd{padding:2px 6px;border-radius:4px;border:1px solid #2a3750;background:#0f1726;color:#bcd0ff}
</style>
"""

HTML_SCRIPT = """
<script>
(() => {
  const qs = s => document.querySelector(s);
  const qsa = s => Array.from(document.querySelectorAll(s));
  const chips = {
    api: qs('[data-chip="api"]'),
    att: qs('[data-chip="att"]'),
    web: qs('[data-chip="web"]'),
    img: qs('[data-chip="img"]'),
    vid: qs('[data-chip="vid"]'),
    carv: qs('[data-chip="carv"]'),
  };
  const search = qs('#search');
  const rows = qsa('tbody tr[data-type]');

  const state = { api:true, att:true, web:true, img:true, vid:true, carvedOnly:false, q:"" };

  function sync() {
    const q = state.q.toLowerCase();
    let visible = 0;
    rows.forEach(tr => {
      const t = tr.dataset.type;             // api|attachment|webhook|image|video
      const carved = tr.dataset.carved === "1";
      const text = tr.dataset.all;

      const typeOk =
        (t === "api"        && state.api) ||
        (t === "attachment" && state.att) ||
        (t === "webhook"    && state.web) ||
        (t === "image"      && state.img) ||
        (t === "video"      && state.vid);

      const carvedOk = state.carvedOnly ? carved : true;
      const qOk = !q || (text && text.indexOf(q) !== -1);

      const show = typeOk && carvedOk && qOk;
      tr.style.display = show ? "" : "none";
      if (show) visible++;
    });
    qs('#visibleCount').textContent = visible;
  }

  function toggle(chip, key) {
    chip.classList.toggle('on');
    state[key] = chip.classList.contains('on');
    sync();
  }

  chips.api.addEventListener('click', () => toggle(chips.api, 'api'));
  chips.att.addEventListener('click', () => toggle(chips.att, 'att'));
  chips.web.addEventListener('click', () => toggle(chips.web, 'web'));
  chips.img.addEventListener('click', () => toggle(chips.img, 'img'));
  chips.vid.addEventListener('click', () => toggle(chips.vid, 'vid'));
  chips.carv.addEventListener('click', () => { chips.carv.classList.toggle('on'); state.carvedOnly = chips.carv.classList.contains('on'); sync(); });

  search.addEventListener('input', e => { state.q = e.target.value; sync(); });

  // Select all / none
  qs('#all').addEventListener('click', () => {
    ['api','att','web','img','vid'].forEach(k => { chips[k].classList.add('on'); state[k]=true; });
    sync();
  });
  qs('#none').addEventListener('click', () => {
    ['api','att','web','img','vid'].forEach(k => { chips[k].classList.remove('on'); state[k]=false; });
    sync();
  });

  // initial on
  ['api','att','web','img','vid'].forEach(k => chips[k].classList.add('on'));
  sync();
})();
</script>
"""

def generate_html(rows: list[dict], out_html: str, title: str = "Discord Cache Forensic Report") -> None:
    # Counters
    ctr = Counter(r["type"] for r in rows)
    carved_count = sum(1 for r in rows if r.get("carved"))

    total = len(rows)
    visible_placeholder = "0"

    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'/>")
    html.append(f"<title>{html_escape(title)}</title>")
    html.append(HTML_STYLE)
    html.append("</head><body>")
    html.append(f"<h1>{html_escape(title)}</h1>")
    html.append("<div class='controls'>")

    def chip(key, label, count, dotclass):
        return f"""<span class="badge" data-chip="{key}" title="toggle">
          <span class="dot {dotclass}"></span> {label} <b>{count}</b>
        </span>"""

    html.append(chip("api", "🔧 API Call", ctr.get("API Call", 0), "api"))
    html.append(chip("att", "📎 Attachment", ctr.get("Attachment", 0), "att"))
    html.append(chip("web", "🧩 Webhook", ctr.get("Webhook", 0), "web"))
    html.append(chip("img", "🖼️ Image", ctr.get("Image", 0), "img"))
    html.append(chip("vid", "🎞️ Video", ctr.get("Video", 0), "vid"))
    # Carved filter (NEW – counts carved rows but keeps type Image/Video)
    html.append(chip("carv", "🪓 Carved Media", carved_count, "carv"))

    html.append('<input id="search" type="search" placeholder="Search URL, path, hash, etc."/>')
    html.append(f"<span class='aux'>Visible: <b id='visibleCount'>{visible_placeholder}</b> / Total: <b>{total}</b> &nbsp;·&nbsp; <a id='all' href='javascript:void(0)'>Select all</a> · <a id='none' href='javascript:void(0)'>Select none</a></span>")
    html.append("</div>")

    # Table
    html.append("<table>")
    html.append("<thead><tr>")
    html.append("<th>Modified (UTC)</th><th>Type</th><th>Source</th><th>Preview / Remote</th><th>Cache File</th><th>SHA256</th>")
    html.append("</tr></thead><tbody>")

    def data_type_value(t: str) -> str:
        t = t.lower()
        if t.startswith("api"): return "api"
        if t.startswith("attach"): return "attachment"
        if t.startswith("webhook"): return "webhook"
        if t.startswith("image"): return "image"
        if t.startswith("video"): return "video"
        return "other"

    for r in rows:
        dtype = data_type_value(r["type"])
        carved = "1" if r.get("carved") else "0"
        alltext = " ".join([
            r.get("modified",""),
            r.get("type",""),
            r.get("source",""),
            r.get("preview",""),
            r.get("remote",""),
            r.get("cache_file",""),
            r.get("sha256","")
        ]).lower()

        html.append(f"<tr data-type='{dtype}' data-carved='{carved}' data-all='{html_escape(alltext)}'>")
        html.append(f"<td>{html_escape(r.get('modified',''))}</td>")
        # Type + carved label
        tcell = html_escape(r['type'])
        if r.get("carved"):
            tcell += " <span class='label'>carved</span>"
        html.append(f"<td>{tcell}</td>")
        html.append(f"<td>{html_escape(r.get('source',''))}</td>")

        # Preview cell
        prev_html = ""
        if r.get("preview"):  # local
            if r["type"] == "Image":
                prev_html += f"<div class='preview'><a href='{html_escape(r['preview'])}' target='_blank'><img src='{html_escape(r['preview'])}' alt='preview'/></a></div>"
            elif r["type"] == "Video":
                prev_html += f"<div class='preview'><video src='{html_escape(r['preview'])}' controls preload='metadata'></video></div>"
            prev_html += " <span class='label'>Local</span>"
        if r.get("remote"):
            link = html_escape(r["remote"])
            prev_html += f" <a href='{link}' target='_blank'>Remote</a>"
        html.append(f"<td>{prev_html}</td>")

        html.append(f"<td class='mono'>{html_escape(r.get('cache_file',''))}</td>")
        html.append(f"<td class='mono'>{html_escape(r.get('sha256',''))}</td>")
        html.append("</tr>")

    html.append("</tbody></table>")
    html.append("<small>Media thumbnails load from local copies stored next to this report. Click <b>Remote</b> to open the original CDN URL.</small>")
    html.append(HTML_SCRIPT)
    html.append("</body></html>")

    with open(out_html, "w", encoding="utf-8") as f:
        f.write("".join(html))

# -------------------------------
# CSV & Timeline (optional)
# -------------------------------
def write_csv(rows: list[dict], out_csv: str) -> None:
    cols = ["modified", "type", "source", "preview", "remote", "cache_file", "sha256", "carved"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k,"") for k in cols})

def write_timeline(rows: list[dict], out_csv: str) -> None:
    rows_sorted = sorted(rows, key=lambda r: r.get("modified",""))
    cols = ["modified", "type", "source", "remote", "preview", "cache_file", "sha256", "carved"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows_sorted:
            w.writerow({k: r.get(k,"") for k in cols})

# -------------------------------
# CLI
# -------------------------------
def get_args():
    p = argparse.ArgumentParser(description="Discord Cache Forensic Parser (CLI)")
    p.add_argument("--cache", default=default_cache_dir(), help="Path to Discord Cache_Data directory")
    p.add_argument("--output", default="discord_cache_report", help="Base name for output files (no extension)")
    p.add_argument("--outdir", default=os.getcwd(), help="Directory to write the report and media folder")
    p.add_argument("--format", choices=["html","csv","both"], default="html", help="Report format")
    p.add_argument("--timeline", action="store_true", help="Also write a chronological CSV (timeline)")
    p.add_argument("--extra", action="store_true", help="Also scan sibling 'Code Cache' and 'GPUCache'")
    p.add_argument("--carve", action="store_true", help="Carve media from cache bytes (adds 'Carved Media' filter)")
    p.add_argument("--verbose", action="store_true", help="Verbose console output")
    return p.parse_args()

def interactive_setup():
    print("=== Discord Cache Forensic Parser (Interactive) ===")
    cache = input(f"Cache directory [{default_cache_dir()}]: ").strip() or default_cache_dir()
    outbase = input("Output base name [discord_cache_report]: ").strip() or "discord_cache_report"
    outdir = input(f"Output directory [{os.getcwd()}]: ").strip() or os.getcwd()
    fmt = (input("Export format (html/csv/both) [html]: ").strip() or "html").lower()
    timeline = (input("Generate timeline CSV? (y/n): ").strip().lower().startswith("y"))
    extra = (input("Include Code Cache & GPUCache? (y/n): ").strip().lower().startswith("y"))
    carve = (input("Enable carving near URLs? (y/n): ").strip().lower().startswith("y"))
    verbose = (input("Verbose output? (y/n): ").strip().lower().startswith("y"))
    ns = argparse.Namespace(cache=cache, output=outbase, outdir=outdir, format=fmt, timeline=timeline, extra=extra, carve=carve, verbose=verbose)
    return ns

# -------------------------------
# Main
# -------------------------------
def main():
    args = interactive_setup() if len(sys.argv) == 1 else get_args()

    print("\n=== Discord Cache Forensic Parser (CLI) ===")
    print(f"Cache directory   : {args.cache}")
    print(f"Output base name  : {args.output}")
    print(f"Output directory  : {args.outdir}")
    print(f"Export format     : {args.format}")
    print(f"Timeline export   : {'Enabled' if args.timeline else 'Disabled'}")
    print(f"Include extra     : {'Enabled' if getattr(args,'extra',False) else 'Disabled'}")
    print(f"Carving           : {'Enabled' if args.carve else 'Disabled'}")
    print(f"Verbose mode      : {'Enabled' if args.verbose else 'Disabled'}\n")

    if not os.path.isdir(args.cache):
        print(f"[ERROR] Cache directory not found: {args.cache}")
        sys.exit(1)

    ensure_dir(args.outdir)
    store = EvidenceStore(args.outdir, args.output)
    url_to_local: dict[str,str] = {}

    # Build list of dirs to scan
    scan_dirs = [args.cache]
    if getattr(args, "extra", False):
        base = os.path.dirname(args.cache.rstrip("\\/"))
        for extra in ("Code Cache","GPUCache"):
            p = os.path.join(base, extra)
            if os.path.isdir(p):
                scan_dirs.append(p)

    # First pass: parse all f_* bodies to populate url->local map + local media rows
    all_rows: list[dict] = []
    for d in scan_dirs:
        files = []
        for root, _, fs in os.walk(d):
            for fn in fs:
                if fn == "index":
                    continue
                if fn.startswith("f_"):
                    files.append(os.path.join(root, fn))
        if args.verbose:
            print(f"Parsing f_* bodies in {d} ({len(files)} files)...")
        for idx, fp in enumerate(files, 1):
            if args.verbose and idx % 50 == 0:
                print(f"  {idx}/{len(files)} f_*")
            all_rows.extend(parse_f_entry(fp, store, url_to_local, args.verbose))

    # Second pass: scan all files for URLs + optional carving
    for d in scan_dirs:
        files = []
        for root, _, fs in os.walk(d):
            for fn in fs:
                if fn == "index":
                    continue
                files.append(os.path.join(root, fn))
        print(f"Scanning {len(files)} files in {d}...")
        for idx, fp in enumerate(files, 1):
            # skip already handled f_* here? No, we still scan them for URLs
            rows = scan_cache_file(fp, url_to_local, store, args.carve, args.verbose)
            all_rows.extend(rows)

    # Deduplicate exact rows (by type+remote+preview+cache_file+sha256)
    seen = set()
    deduped = []
    for r in all_rows:
        key = (r.get("type",""), r.get("remote",""), r.get("preview",""), r.get("cache_file",""), r.get("sha256",""), r.get("carved",0))
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    all_rows = deduped

    # Sort by modified desc
    all_rows.sort(key=lambda r: r.get("modified",""), reverse=True)

    # Write outputs
    out_html = os.path.join(args.outdir, f"{args.output}.html")
    out_csv  = os.path.join(args.outdir, f"{args.output}.csv")
    out_tl   = os.path.join(args.outdir, f"{args.output}_timeline.csv")

    if args.format in ("html","both"):
        generate_html(all_rows, out_html)
        print(f"HTML report generated: {out_html}")
    if args.format in ("csv","both"):
        write_csv(all_rows, out_csv)
        print(f"CSV report generated:  {out_csv}")
    if args.timeline:
        write_timeline(all_rows, out_tl)
        print(f"Timeline CSV written:  {out_tl}")

    # Summary
    ctr = Counter(r["type"] for r in all_rows)
    carved_count = sum(1 for r in all_rows if r.get("carved"))
    print("\n=== Discord Cache Forensic Summary ===")
    for k in ("Attachment","Webhook","API Call","Image","Video"):
        if ctr.get(k,0):
            print(f"- {ctr[k]:3d} {k}(s)")
    print(f"- {carved_count:3d} Carved Media (filtered via chip)")
    print(f"Total rows: {len(all_rows)}")
    print(f"\nReports saved to: {args.outdir}")
    print(f"Media folder:      {os.path.join(args.outdir, os.path.basename(store.root))}")

if __name__ == "__main__":
    main()
