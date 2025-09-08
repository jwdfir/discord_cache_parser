#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Discord Cache Forensic Suite
"""

import os, re, csv, sys, gzip, zlib, json, hashlib, platform, threading, webbrowser, time
from datetime import datetime
from collections import Counter
from html import escape as html_escape

# =======================
# Artifact definitions
# =======================
ATTACHMENT_REGEX = re.compile(r"https://(?:cdn|media)\.discordapp\.com/attachments/[^\s\"'<>]+", re.IGNORECASE)
WEBHOOK_REGEX    = re.compile(r"https://discord\.com/api/webhooks/[^\s\"'<>]+", re.IGNORECASE)
API_REGEX        = re.compile(r"https://discord(?:app)?\.com/api/v\d+/[^\s\"'<>]+", re.IGNORECASE)

MAGIC_SIGNATURES = [
    (b"\xFF\xD8\xFF",           ".jpg",  "Image"),
    (b"\x89PNG\r\n\x1A\n",      ".png",  "Image"),
    (b"GIF87a",                 ".gif",  "Image"),
    (b"GIF89a",                 ".gif",  "Image"),
    (b"RIFF",                   ".webp", "Image"),   # validated by WEBP token
    (b"\x00\x00\x00\x18ftypmp4",".mp4",  "Video"),
    (b"\x00\x00\x00 ftypisom",  ".mp4",  "Video"),
    (b"\x00\x00\x00 ftypMSNV",  ".mp4",  "Video"),
    (b"\x1A\x45\xDF\xA3",       ".webm", "Video"),   # EBML (treat mkv/webm as Video)
]

# Brotli (optional)
try:
    import brotli  # type: ignore
    HAS_BROTLI = True
except Exception:
    HAS_BROTLI = False

# =======================
# Utilities
# =======================
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def utc_iso(ts: float) -> str:
    # (3.13 warns; storing as naive UTC string is fine for the report)
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
        return body
    return body

def sniff_magic(data: bytes) -> tuple[str | None, str | None]:
    head = data[:64]
    for sig, ext, kind in MAGIC_SIGNATURES:
        if head.startswith(sig):
            if ext == ".webp" and b"WEBP" not in data[8:16]:
                continue
            return ext, kind
    return None, None

# =======================
# Evidence store
# =======================
class EvidenceStore:
    def __init__(self, out_dir: str, base_name: str):
        self.root = os.path.join(out_dir, f"{base_name}_media")
        ensure_dir(self.root)

    def save_bytes(self, data: bytes, suggested_ext: str, prefix: str) -> tuple[str, str]:
        digest = sha256_bytes(data)
        ext = suggested_ext or ".bin"
        fname = f"{prefix}_{digest}{ext}"
        abs_path = os.path.join(self.root, fname)
        if not os.path.exists(abs_path):
            with open(abs_path, "wb") as f:
                f.write(data)
        rel_from_html = os.path.join(os.path.basename(self.root), fname)
        return abs_path, rel_from_html

# =======================
# Cache parsing + carving
# =======================
def parse_f_entry(abs_path: str, store: EvidenceStore, url_to_local: dict, verbose: bool, log=None) -> list[dict]:
    rows = []
    try:
        with open(abs_path, "rb") as f:
            raw = f.read()
        i = raw.find(b"\r\n\r\n")
        if i == -1:
            return rows
        header_block = raw[:i].decode(errors="ignore")
        body = raw[i+4:]
        headers = {}
        for line in header_block.split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        content_loc = headers.get("Content-Location") or headers.get("X-Original-URL") or ""
        content_type = (headers.get("Content-Type") or "").lower()
        body = maybe_decompress(headers, body)

        ext, kind = (None, None)
        if content_type.startswith("image/"):
            ext  = "." + content_type.split("/")[-1].split(";")[0]
            kind = "Image"
        elif content_type.startswith("video/"):
            ext  = "." + content_type.split("/")[-1].split(";")[0]
            kind = "Video"
        else:
            ext, kind = sniff_magic(body)

        if kind in ("Image","Video"):
            _, rel = store.save_bytes(body, ext or ".bin", prefix=os.path.basename(abs_path))
            if content_loc:
                url_to_local[content_loc] = rel
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": kind, "source": "Local",
                "preview": rel, "remote": content_loc,
                "cache_file": abs_path, "sha256": sha256_bytes(body), "carved": 0,
            })
            if verbose and log: log(f"✅ f_* extracted: {os.path.basename(abs_path)} ({kind})")
        elif content_loc:
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": "Attachment", "source": "Remote",
                "preview": "", "remote": content_loc,
                "cache_file": abs_path, "sha256": sha256_file(abs_path), "carved": 0,
            })
    except Exception as e:
        if verbose and log: log(f"[WARN] f_* parse failed for {abs_path}: {e}")
    return rows

def carve_from_bytes(b: bytes, store: EvidenceStore, src_name: str) -> list[dict]:
    carved = []
    for sig, ext, kind in MAGIC_SIGNATURES:
        idx = b.find(sig)
        if idx != -1:
            chunk = b[idx:]
            _, rel = store.save_bytes(chunk, ext, prefix=f"{src_name}_carved")
            carved.append((rel, kind, sha256_bytes(chunk)))
    rows = []
    for rel, kind, digest in carved:
        rows.append({
            "modified": "", "type": kind, "source": "Local",
            "preview": rel, "remote": "", "cache_file": "",
            "sha256": digest, "carved": 1,
        })
    return rows

def scan_cache_file(abs_path: str, url_to_local: dict, store: EvidenceStore, do_carve: bool, verbose: bool, log=None) -> list[dict]:
    rows = []
    try:
        with open(abs_path, "rb") as f:
            raw = f.read()
        text = raw.decode(errors="ignore")

        for url in ATTACHMENT_REGEX.findall(text):
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": "Attachment", "source": "Remote",
                "preview": url_to_local.get(url, ""), "remote": url,
                "cache_file": abs_path, "sha256": sha256_file(abs_path), "carved": 0,
            })
        for url in WEBHOOK_REGEX.findall(text):
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": "Webhook", "source": "Remote",
                "preview": "", "remote": url,
                "cache_file": abs_path, "sha256": sha256_file(abs_path), "carved": 0,
            })
        for url in API_REGEX.findall(text):
            rows.append({
                "modified": utc_iso(os.path.getmtime(abs_path)),
                "type": "API Call", "source": "Remote",
                "preview": "", "remote": url,
                "cache_file": abs_path, "sha256": sha256_file(abs_path), "carved": 0,
            })

        if do_carve:
            carved_rows = carve_from_bytes(raw, store, os.path.basename(abs_path))
            if carved_rows:
                for r in carved_rows:
                    r["modified"]  = utc_iso(os.path.getmtime(abs_path))
                    r["cache_file"] = abs_path
                rows.extend(carved_rows)
    except Exception as e:
        if verbose and log: log(f"[WARN] scan failed for {abs_path}: {e}")
    return rows

# =======================
# HTML report (with Carved chip)
# =======================
HTML_STYLE = """
<style>
:root { --bg:#0e1320; --bg2:#151d2c; --fg:#e9eef7; --mut:#9fb0cd; --chip:#1c283d; --chipOn:#273855; --accent:#6cc7ff; }
*{box-sizing:border-box}
body{margin:18px;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--fg)}
h1{margin:0 0 12px 0;font-weight:800;letter-spacing:.2px}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{padding:10px 12px;border-bottom:1px solid #24324a;vertical-align:middle}
th{position:sticky;top:0;background:var(--bg2);z-index:2}
tbody tr:hover{background:rgba(255,255,255,.045)}
a{color:var(--accent)}
.mono{font-family:Consolas,Menlo,monospace}
.badge{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;background:var(--chip);color:var(--fg);margin-right:8px;cursor:pointer;border:1px solid #2b3b59;font-weight:600}
.badge.on{background:var(--chipOn)}
.badge .dot{display:inline-block;width:8px;height:8px;border-radius:50%}
.dot.api{background:#6cc7ff}
.dot.att{background:#ffd166}
.dot.web{background:#f48fb1}
.dot.img{background:#80ffea}
.dot.vid{background:#a0c4ff}
.dot.carv{background:#cdb4db}
input[type=search]{width:360px;padding:10px;border-radius:10px;border:1px solid #2b3b59;background:#0f1726;color:var(--fg)}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.aux{margin-left:auto;color:var(--mut)}
.preview img{max-height:56px;border-radius:10px}
.preview video{height:64px;border-radius:10px}
.label{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;margin-left:6px;background:#2b3954}
</style>
"""
HTML_SCRIPT = """
<script>
(() => {
  const qs=s=>document.querySelector(s), qsa=s=>Array.from(document.querySelectorAll(s));
  const chips={api:qs('[data-chip="api"]'), att:qs('[data-chip="att"]'), web:qs('[data-chip="web"]'), img:qs('[data-chip="img"]'), vid:qs('[data-chip="vid"]'), carv:qs('[data-chip="carv"]')};
  const search=qs('#search'); const rows=qsa('tbody tr[data-type]');
  const state={api:true,att:true,web:true,img:true,vid:true,carvedOnly:false,q:""};
  function sync(){
    const q=state.q.toLowerCase(); let vis=0; const any=state.api||state.att||state.web||state.img||state.vid;
    rows.forEach(tr=>{
      const t=tr.dataset.type, carved=(tr.dataset.carved==="1"), text=tr.dataset.all;
      const typeOkRaw=(t==="api"&&state.api)||(t==="attachment"&&state.att)||(t==="webhook"&&state.web)||(t==="image"&&state.img)||(t==="video"&&state.vid);
      const typeOk=any?typeOkRaw:(state.carvedOnly?true:false);
      const carvedOk=state.carvedOnly?carved:true;
      const qOk=!state.q||(text&&text.indexOf(q)!==-1);
      const show=typeOk&&carvedOk&&qOk; tr.style.display=show?"":"none"; if(show) vis++;
    });
    qs('#visibleCount').textContent=vis;
  }
  function toggle(chip,key){ chip.classList.toggle('on'); state[key]=chip.classList.contains('on'); sync(); }
  chips.api.onclick=()=>toggle(chips.api,'api');
  chips.att.onclick=()=>toggle(chips.att,'att');
  chips.web.onclick=()=>toggle(chips.web,'web');
  chips.img.onclick=()=>toggle(chips.img,'img');
  chips.vid.onclick=()=>toggle(chips.vid,'vid');
  chips.carv.onclick=()=>{ chips.carv.classList.toggle('on'); state.carvedOnly=chips.carv.classList.contains('on'); sync(); }
  search.oninput=e=>{ state.q=e.target.value; sync(); }
  qs('#all').onclick=()=>{['api','att','web','img','vid'].forEach(k=>{chips[k].classList.add('on'); state[k]=true;}); sync();}
  qs('#none').onclick=()=>{['api','att','web','img','vid'].forEach(k=>{chips[k].classList.remove('on'); state[k]=false;}); sync();}
  ['api','att','web','img','vid'].forEach(k=>chips[k].classList.add('on')); sync();
})();
</script>
"""

def generate_html(rows: list[dict], out_html: str, title: str = "Discord Cache Forensic Report") -> None:
    ctr = Counter(r["type"] for r in rows)
    carved_count = sum(1 for r in rows if r.get("carved"))
    total = len(rows)
    html=[]
    html.append("<!doctype html><html><head><meta charset='utf-8'/>")
    html.append(f"<title>{html_escape(title)}</title>")
    html.append(HTML_STYLE)
    html.append("</head><body>")
    html.append(f"<h1>{html_escape(title)}</h1>")
    html.append("<div class='controls'>")

    def chip(key,label,count,dot):
        return f"""<span class="badge" data-chip="{key}"><span class="dot {dot}"></span> {label} <b>{count}</b></span>"""

    html.append(chip("api","🔧 API Call", ctr.get("API Call",0),"api"))
    html.append(chip("att","📎 Attachment", ctr.get("Attachment",0),"att"))
    html.append(chip("web","🧩 Webhook", ctr.get("Webhook",0),"web"))
    html.append(chip("img","🖼️ Image", ctr.get("Image",0),"img"))
    html.append(chip("vid","🎞️ Video", ctr.get("Video",0),"vid"))
    html.append(chip("carv","🪓 Carved Media", carved_count,"carv"))
    html.append('<input id="search" type="search" placeholder="Search URL, path, hash, etc.">')
    html.append(f"<span class='aux'>Visible: <b id='visibleCount'>0</b> / Total: <b>{total}</b> · <a id='all' href='javascript:void(0)'>Select all</a> · <a id='none' href='javascript:void(0)'>Select none</a></span>")
    html.append("</div>")

    html.append("<table><thead><tr><th>Modified (UTC)</th><th>Type</th><th>Source</th><th>Preview / Remote</th><th>Cache File</th><th>SHA256</th></tr></thead><tbody>")

    def dval(t: str) -> str:
        t=t.lower()
        if t.startswith("api"): return "api"
        if t.startswith("attach"): return "attachment"
        if t.startswith("webhook"): return "webhook"
        if t.startswith("image"): return "image"
        if t.startswith("video"): return "video"
        return "other"

    for r in rows:
        dtype=dval(r["type"]); carved="1" if r.get("carved") else "0"
        alltext=" ".join([r.get("modified",""), r.get("type",""), r.get("source",""), r.get("preview",""), r.get("remote",""), r.get("cache_file",""), r.get("sha256","")]).lower()
        html.append(f"<tr data-type='{dtype}' data-carved='{carved}' data-all='{html_escape(alltext)}'>")
        html.append(f"<td>{html_escape(r.get('modified',''))}</td>")
        tcell=html_escape(r['type']) + (" <span class='label'>carved</span>" if r.get("carved") else "")
        html.append(f"<td>{tcell}</td>")
        html.append(f"<td>{html_escape(r.get('source',''))}</td>")
        prev=""
        if r.get("preview"):
            if r["type"]=="Image":
                prev+=f"<div class='preview'><a href='{html_escape(r['preview'])}' target='_blank'><img src='{html_escape(r['preview'])}'></a></div>"
            elif r["type"]=="Video":
                prev+=f"<div class='preview'><video src='{html_escape(r['preview'])}' controls preload='metadata'></video></div>"
            prev+=" <span class='label'>Local</span>"
        if r.get("remote"):
            prev+=f" <a href='{html_escape(r['remote'])}' target='_blank'>Remote</a>"
        html.append(f"<td>{prev}</td>")
        html.append(f"<td class='mono'>{html_escape(r.get('cache_file',''))}</td>")
        html.append(f"<td class='mono'>{html_escape(r.get('sha256',''))}</td>")
        html.append("</tr>")
    html.append("</tbody></table>")
    html.append("<small>Media thumbnails load from local copies saved next to this report. Click <b>Remote</b> to open the original CDN URL.</small>")
    html.append(HTML_SCRIPT + "</body></html>")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("".join(html))

def write_csv(rows: list[dict], out_csv: str) -> None:
    cols=["modified","type","source","preview","remote","cache_file","sha256","carved"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,"") for k in cols})

def write_timeline(rows: list[dict], out_csv: str) -> None:
    rows_sorted = sorted(rows, key=lambda r: r.get("modified",""))
    cols=["modified","type","source","remote","preview","cache_file","sha256","carved"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for r in rows_sorted: w.writerow({k:r.get(k,"") for k in cols})

def run_pipeline(cache: str, outbase: str, outdir: str, fmt: str, timeline: bool, extra: bool, carve: bool, verbose: bool, log=lambda s: None) -> dict:
    if not os.path.isdir(cache):
        raise FileNotFoundError(f"Cache directory not found: {cache}")
    ensure_dir(outdir)
    store = EvidenceStore(outdir, outbase)
    url_to_local: dict[str,str] = {}
    scan_dirs=[cache]
    if extra:
        base=os.path.dirname(cache.rstrip("\\/"))
        for ex in ("Code Cache","GPUCache"):
            p=os.path.join(base, ex)
            if os.path.isdir(p): scan_dirs.append(p)

    all_rows=[]
    # Pass A — f_ bodies
    for d in scan_dirs:
        f_entries=[]
        for root,_,fs in os.walk(d):
            for fn in fs:
                if fn=="index": continue
                if fn.startswith("f_"): f_entries.append(os.path.join(root, fn))
        if verbose: log(f"Parsing f_* bodies in {d} ({len(f_entries)} files)...")
        for i,fp in enumerate(f_entries,1):
            if verbose and i%50==0: log(f"  {i}/{len(f_entries)} f_*")
            all_rows.extend(parse_f_entry(fp, store, url_to_local, verbose, log=log))
    # Pass B — scan & carve
    for d in scan_dirs:
        files=[]
        for root,_,fs in os.walk(d):
            for fn in fs:
                if fn=="index": continue
                files.append(os.path.join(root, fn))
        log(f"Scanning {len(files)} files in {d}...")
        for fp in files:
            all_rows.extend(scan_cache_file(fp, url_to_local, store, carve, verbose, log=log))

    # Dedup + sort
    seen=set(); ded=[]
    for r in all_rows:
        key=(r.get("type",""), r.get("remote",""), r.get("preview",""), r.get("cache_file",""), r.get("sha256",""), r.get("carved",0))
        if key not in seen:
            seen.add(key); ded.append(r)
    all_rows=sorted(ded, key=lambda r:r.get("modified",""), reverse=True)

    out_html=os.path.join(outdir, f"{outbase}.html")
    out_csv =os.path.join(outdir, f"{outbase}.csv")
    out_tl  =os.path.join(outdir, f"{outbase}_timeline.csv")
    if fmt in ("html","both"):
        generate_html(all_rows, out_html); log(f"HTML report generated:\n{out_html}")
    if fmt in ("csv","both"):
        write_csv(all_rows, out_csv);     log(f"CSV report generated:\n{out_csv}")
    if timeline:
        write_timeline(all_rows, out_tl); log(f"Timeline CSV written:\n{out_tl}")

    ctr=Counter(r["type"] for r in all_rows)
    carved_count=sum(1 for r in all_rows if r.get("carved"))
    return {
        "counts":ctr, "carved":carved_count, "total":len(all_rows),
        "out_html": out_html if fmt in ("html","both") else "",
        "out_csv":  out_csv  if fmt in ("csv","both")  else "",
        "out_tl":   out_tl   if timeline else "",
        "media_dir": os.path.join(outdir, f"{outbase}_media"),
    }

# =======================
# GUI
# =======================
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Optional: ttkbootstrap for an even nicer look
BOOTSTRAP = None
try:
    import ttkbootstrap as tb  # pip install ttkbootstrap
    BOOTSTRAP = tb
except Exception:
    BOOTSTRAP = None

# Fallback dark palette
DARK_BG   = "#0e1320"
CARD_BG   = "#151d2c"
FG        = "#e9eef7"
MUTED     = "#9fb0cd"
PRIMARY   = "#6cc7ff"
OK        = "#60f0a8"
WARN      = "#ffb86b"

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".discord_forensic_suite_settings.json")

def apply_dark_style(root):
    style = ttk.Style(root)
    try: style.theme_use("clam")
    except Exception: pass
    root.configure(bg=DARK_BG)
    style.configure(".", background=DARK_BG, foreground=FG, fieldbackground=DARK_BG)
    style.configure("TLabel", background=DARK_BG, foreground=FG)
    style.configure("Card.TLabelframe", background=CARD_BG, foreground=FG, relief="groove")
    style.configure("Card.TLabelframe.Label", background=CARD_BG, foreground=FG)
    style.configure("TEntry", fieldbackground="#0f1726", foreground=FG)
    style.configure("TCheckbutton", background=DARK_BG, foreground=FG)
    style.configure("TRadiobutton", background=DARK_BG, foreground=FG)
    style.configure("TButton", background="#1e2a3f", foreground=FG)
    style.map("TButton", background=[("active","#26344e")])
    style.configure("TProgressbar", troughcolor="#0f1726", background=PRIMARY)
    return style

# Simple tooltip fallback
class Tooltip:
    def __init__(self, widget, text):
        self.widget, self.text = widget, text
        self.tip = None
        widget.bind("<Enter>", self.on)
        widget.bind("<Leave>", self.off)
    def on(self, *_):
        if self.tip: return
        x, y, _, h = self.widget.bbox("insert") if hasattr(self.widget,"bbox") else (0,0,0,0)
        x += self.widget.winfo_rootx() + 12
        y += self.widget.winfo_rooty() + h + 12
        self.tip = tw = tk.Toplevel(self.widget)
        tw.overrideredirect(True); tw.attributes("-topmost", True)
        lbl = tk.Label(tw, text=self.text, bg="#1e2a3f", fg=FG, bd=1, relief="solid", padx=6, pady=4, font=("Segoe UI",9))
        lbl.pack()
        tw.geometry(f"+{x}+{y}")
    def off(self, *_):
        if self.tip:
            self.tip.destroy(); self.tip=None

class App(tk.Tk):
    def __init__(self):
        if BOOTSTRAP:
            self.win = BOOTSTRAP.Window(title="Discord Cache Forensic Suite — Pro GUI", themename="darkly")
            root = self.win
            self.style = self.win.style
            super().__init__()
        else:
            super().__init__()
            self.style = apply_dark_style(self)

        # vars
        self.var_cache   = tk.StringVar(value=default_cache_dir())
        self.var_outdir  = tk.StringVar(value=os.getcwd())
        self.var_outbase = tk.StringVar(value="discord_cache_report")
        self.var_fmt     = tk.StringVar(value="html")
        self.var_extra   = tk.BooleanVar(value=False)
        self.var_carve   = tk.BooleanVar(value=False)
        self.var_timeline= tk.BooleanVar(value=False)
        self.var_verbose = tk.BooleanVar(value=True)
        self.var_autoopen= tk.BooleanVar(value=True)

        self.out_html = ""

        self.title("Discord Cache Forensic Suite — Pro GUI")
        self.geometry("1080x680"); self.minsize(980, 620)

        self._build_ui()
        self._load_settings()

    # ---------- UI ----------
    def _header(self, parent):
        frm = ttk.Frame(parent); frm.pack(fill="x", padx=16, pady=(14,8))
        title = ttk.Label(frm, text="🔎  Discord Cache Forensic Suite", font=("Segoe UI", 18, "bold"))
        subtitle = ttk.Label(frm, text="by jwdfir",
                             foreground=MUTED)
        title.pack(anchor="w"); subtitle.pack(anchor="w")
        return frm

    def _card(self, parent, text=None):
        style = "Card.TLabelframe" if not BOOTSTRAP else None
        lf = ttk.Labelframe(parent, text=text or "", padding=12, style=style)
        lf.pack(fill="x", padx=16, pady=8)
        return lf

    def _badge(self, parent, emoji, text):
        frm = ttk.Frame(parent)
        lbl = ttk.Label(frm, text=f"{emoji} {text}", padding=(10,4))
        if not BOOTSTRAP:
            lbl.configure(background="#1e2a3f", foreground=FG)
        lbl.pack()
        return frm

    def _build_ui(self):
        self._header(self)

        # Paths
        pcard = self._card(self, "Paths")
        grid  = ttk.Frame(pcard); grid.pack(fill="x")
        ttk.Label(grid, text="🗃️  Cache directory").grid(row=0, column=0, sticky="w", pady=(0,6))
        ent_cache = ttk.Entry(grid, textvariable=self.var_cache); ent_cache.grid(row=0, column=1, sticky="we", padx=8, pady=(0,6))
        ttk.Button(grid, text="Browse…", command=self._choose_cache).grid(row=0, column=2, sticky="w", pady=(0,6))

        ttk.Label(grid, text="📁  Output directory").grid(row=1, column=0, sticky="w", pady=6)
        ent_out = ttk.Entry(grid, textvariable=self.var_outdir); ent_out.grid(row=1, column=1, sticky="we", padx=8, pady=6)
        ttk.Button(grid, text="Browse…", command=self._choose_outdir).grid(row=1, column=2, sticky="w", pady=6)

        ttk.Label(grid, text="🧾  Output base name").grid(row=2, column=0, sticky="w", pady=(6,0))
        ttk.Entry(grid, textvariable=self.var_outbase, width=40).grid(row=2, column=1, sticky="w", padx=8, pady=(6,0))
        grid.columnconfigure(1, weight=1)

        # Options
        ocard = self._card(self, "Options")
        opt = ttk.Frame(ocard); opt.pack(fill="x")
        cb1 = ttk.Checkbutton(opt, text="Include Code Cache & GPUCache", variable=self.var_extra)
        cb2 = ttk.Checkbutton(opt, text="Enable carving", variable=self.var_carve)
        cb3 = ttk.Checkbutton(opt, text="Generate timeline CSV", variable=self.var_timeline)
        cb4 = ttk.Checkbutton(opt, text="Verbose logs", variable=self.var_verbose)
        cb5 = ttk.Checkbutton(opt, text="Auto-open report", variable=self.var_autoopen)
        cb1.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        cb2.grid(row=0, column=1, sticky="w", padx=14, pady=2)
        cb3.grid(row=0, column=2, sticky="w", padx=14, pady=2)
        cb4.grid(row=0, column=3, sticky="w", padx=14, pady=2)
        cb5.grid(row=0, column=4, sticky="w", padx=14, pady=2)
        Tooltip(cb2, "Light carving for previews: finds media magic bytes and saves to the media folder")

        # Export
        fcard = self._card(self, "Export format")
        ef = ttk.Frame(fcard); ef.pack(fill="x")
        ttk.Radiobutton(ef, text="HTML", variable=self.var_fmt, value="html").pack(side="left", padx=4)
        ttk.Radiobutton(ef, text="CSV",   variable=self.var_fmt, value="csv").pack(side="left", padx=8)
        ttk.Radiobutton(ef, text="Both",  variable=self.var_fmt, value="both").pack(side="left", padx=8)

        # Actions
        acard = self._card(self, "Actions")
        bar = ttk.Frame(acard); bar.pack(fill="x")
        self.btn_run = ttk.Button(bar, text="▶ Run Parse", command=self._run)
        self.btn_run.pack(side="left")
        ttk.Button(bar, text="Open Output Folder", command=self._open_outdir).pack(side="left", padx=8)
        self.btn_report = ttk.Button(bar, text="Open Report", command=self._open_report, state="disabled")
        self.btn_report.pack(side="left", padx=8)
        ttk.Button(bar, text="Clear Log", command=self._clear_log).pack(side="left", padx=8)
        ttk.Button(bar, text="Save Settings", command=self._save_settings).pack(side="left", padx=8)

        # Progress line
        prog_wrap = ttk.Frame(acard); prog_wrap.pack(fill="x", pady=(10,4))
        self.progress = ttk.Progressbar(prog_wrap, mode="indeterminate")
        self.progress.pack(fill="x")

        # Summary badges
        badges = ttk.Frame(acard); badges.pack(fill="x", pady=(8,0))
        self.bad_api   = self._badge(badges, "🔧", "API 0");   self.bad_api.pack(side="left", padx=4)
        self.bad_att   = self._badge(badges, "📎", "Attach 0");self.bad_att.pack(side="left", padx=4)
        self.bad_web   = self._badge(badges, "🧩", "Webhook 0"); self.bad_web.pack(side="left", padx=4)
        self.bad_img   = self._badge(badges, "🖼️", "Image 0"); self.bad_img.pack(side="left", padx=4)
        self.bad_vid   = self._badge(badges, "🎞️", "Video 0"); self.bad_vid.pack(side="left", padx=4)
        self.bad_carv  = self._badge(badges, "🪓", "Carved 0"); self.bad_carv.pack(side="left", padx=4)
        self.bad_total = self._badge(badges, "Σ", "Total 0");  self.bad_total.pack(side="left", padx=4)

        # Log
        lcard = self._card(self, "Log")
        self.log = tk.Text(lcard, height=14, wrap="word", relief="flat")
        self.log.pack(fill="both", expand=True)
        if not BOOTSTRAP:
            self.log.configure(bg="#0f1726", fg=FG, insertbackground=FG)
        self._log("Ready.")

        # Statusbar
        self.status = ttk.Label(self, text="Idle", anchor="w", padding=(16,6))
        if not BOOTSTRAP:
            self.status.configure(background=CARD_BG, foreground=MUTED)
        self.status.pack(fill="x", side="bottom")

    # ---------- helpers ----------
    def _set_badges(self, summary):
        ctr = summary["counts"]
        self.bad_api.children[list(self.bad_api.children.keys())[0]].configure(text=f"🔧 API {ctr.get('API Call',0)}")
        self.bad_att.children[list(self.bad_att.children.keys())[0]].configure(text=f"📎 Attach {ctr.get('Attachment',0)}")
        self.bad_web.children[list(self.bad_web.children.keys())[0]].configure(text=f"🧩 Webhook {ctr.get('Webhook',0)}")
        self.bad_img.children[list(self.bad_img.children.keys())[0]].configure(text=f"🖼️ Image {ctr.get('Image',0)}")
        self.bad_vid.children[list(self.bad_vid.children.keys())[0]].configure(text=f"🎞️ Video {ctr.get('Video',0)}")
        self.bad_carv.children[list(self.bad_carv.children.keys())[0]].configure(text=f"🪓 Carved {summary['carved']}")
        self.bad_total.children[list(self.bad_total.children.keys())[0]].configure(text=f"Σ Total {summary['total']}")

    def _choose_cache(self):
        p = filedialog.askdirectory(title="Select Discord Cache_Data folder")
        if p: self.var_cache.set(p)

    def _choose_outdir(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p: self.var_outdir.set(p)

    def _log(self, msg: str):
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.update_idletasks()

    def _clear_log(self):
        self.log.delete("1.0", "end")

    def _open_outdir(self):
        d = self.var_outdir.get().strip()
        if not d or not os.path.isdir(d): messagebox.showerror("Error", "Output folder not found."); return
        if platform.system()=="Windows": os.startfile(d)  # nosec
        elif platform.system()=="Darwin": os.system(f'open "{d}"')  # nosec
        else: os.system(f'xdg-open "{d}"')  # nosec

    def _open_report(self):
        if self.out_html and os.path.exists(self.out_html):
            webbrowser.open_new_tab(self.out_html)
        else:
            messagebox.showinfo("Info", "No report found yet.")

    def _save_settings(self):
        cfg = dict(
            cache=self.var_cache.get(), outdir=self.var_outdir.get(), outbase=self.var_outbase.get(),
            fmt=self.var_fmt.get(), extra=self.var_extra.get(), carve=self.var_carve.get(),
            timeline=self.var_timeline.get(), verbose=self.var_verbose.get(), autoopen=self.var_autoopen.get(),
        )
        try:
            with open(SETTINGS_PATH, "w", encoding="utf-8") as f: json.dump(cfg, f, indent=2)
            self.status.configure(text=f"Settings saved → {SETTINGS_PATH}")
        except Exception as e:
            messagebox.showerror("Save settings failed", str(e))

    def _load_settings(self):
        try:
            if os.path.exists(SETTINGS_PATH):
                with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                    cfg=json.load(f)
                self.var_cache.set(cfg.get("cache", self.var_cache.get()))
                self.var_outdir.set(cfg.get("outdir", self.var_outdir.get()))
                self.var_outbase.set(cfg.get("outbase", self.var_outbase.get()))
                self.var_fmt.set(cfg.get("fmt", self.var_fmt.get()))
                self.var_extra.set(cfg.get("extra", False))
                self.var_carve.set(cfg.get("carve", False))
                self.var_timeline.set(cfg.get("timeline", False))
                self.var_verbose.set(cfg.get("verbose", True))
                self.var_autoopen.set(cfg.get("autoopen", True))
                self.status.configure(text=f"Settings loaded from {SETTINGS_PATH}")
        except Exception:
            pass

    # ---------- run ----------
    def _run(self):
        self.btn_run.config(state="disabled"); self.btn_report.config(state="disabled")
        self.progress.start(10)
        self.status.configure(text="Running…")
        self._save_settings()

        cache   = self.var_cache.get().strip() or default_cache_dir()
        outdir  = self.var_outdir.get().strip() or os.getcwd()
        outbase = self.var_outbase.get().strip() or "discord_cache_report"
        fmt     = self.var_fmt.get()
        extra   = self.var_extra.get()
        carve   = self.var_carve.get()
        timeline= self.var_timeline.get()
        verbose = self.var_verbose.get()
        autoopen= self.var_autoopen.get()

        def worker():
            start=time.time()
            try:
                self._log("=== Discord Cache Forensic Parser (GUI) ===")
                self._log(f"Cache directory   : {cache}")
                self._log(f"Output base name  : {outbase}")
                self._log(f"Output directory  : {outdir}")
                self._log(f"Export format     : {fmt}")
                self._log(f"Timeline export   : {'Enabled' if timeline else 'Disabled'}")
                self._log(f"Include extra     : {'Enabled' if extra else 'Disabled'}")
                self._log(f"Carving           : {'Enabled' if carve else 'Disabled'}")
                self._log(f"Verbose mode      : {'Enabled' if verbose else 'Disabled'}\n")

                summary = run_pipeline(cache, outbase, outdir, fmt, timeline, extra, carve, verbose,
                                       log=self._log if verbose else (lambda s: None))
                self.out_html = summary["out_html"]
                self._set_badges(summary)

                self._log("\n=== Discord Cache Forensic Summary ===")
                ctr=summary["counts"]
                for k in ("Attachment","Webhook","API Call","Image","Video"):
                    if ctr.get(k,0): self._log(f"- {ctr[k]:3d} {k}(s)")
                self._log(f"- {summary['carved']:3d} Carved Media (filtered via chip)")
                self._log(f"Total rows: {summary['total']}")
                self._log(f"\nReports saved to: {outdir}")
                self._log(f"Media folder:      {summary['media_dir']}")
                if self.out_html:
                    self.btn_report.config(state="normal")
                    self._log(f"\nOpen report: {self.out_html}")
                    if autoopen:
                        webbrowser.open_new_tab(self.out_html)
                elapsed = time.time()-start
                self.status.configure(text=f"Done in {elapsed:.1f}s — ready")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self.status.configure(text="Error")
            finally:
                self.progress.stop()
                self.btn_run.config(state="normal")

        threading.Thread(target=worker, daemon=True).start()

# Entrypoint
if __name__ == "__main__":
    App().mainloop()
