import os
import re
import struct
import hashlib
import zipfile
import json
from datetime import datetime
from tkinter import Tk, filedialog, Button, Label, messagebox, Frame, StringVar, BOTH, LEFT, RIGHT, X
from tkinter import ttk
import webbrowser
from shutil import copy2
from PIL import Image
from PIL.ExifTags import TAGS

# -------- Regex & Magic Bytes --------
WEBHOOK_REGEX = re.compile(r"https://discord\.com/api/webhooks/[^\s\"']+")
ATTACHMENT_REGEX = re.compile(r"https://cdn\.discordapp\.com/attachments/[^\s\"']+")
API_REGEX = re.compile(r"https://discord(app)?\.com/api/v\d+/[^\s\"']+")

SIGNATURES = {
    b"\xFF\xD8\xFF": ".jpg",
    b"\x89PNG\r\n\x1A\n": ".png",
    b"GIF87a": ".gif",
    b"GIF89a": ".gif",
    b"RIFF": ".webp",
    b"\x00\x00\x00\x18ftypmp4": ".mp4"
}

ASCII_CAT = (
    "  /\\_/\\  \n"
    " ( o.o ) \n"
    "  > ^ <  "
)

# -------- Helper Functions --------
def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def detect_file_type(filepath):
    with open(filepath, "rb") as f:
        header = f.read(16)
    for sig, ext in SIGNATURES.items():
        if header.startswith(sig):
            return ext
    return None

def extract_artifacts(data):
    return (
        [("Webhook", u) for u in WEBHOOK_REGEX.findall(data)]
        + [("Attachment", u) for u in ATTACHMENT_REGEX.findall(data)]
        + [("API Call", u) for u in API_REGEX.findall(data)]
    )

def extract_exif(filepath):
    try:
        image = Image.open(filepath)
        exif_data = image._getexif() or {}
        return {TAGS.get(tag, tag): val for tag, val in exif_data.items()}
    except:
        return {}

def parse_index(index_file):
    """Full parse of Chromium Simple Cache index for URL mapping."""
    entries = {}
    try:
        with open(index_file, "rb") as f:
            data = f.read()
        if not data.startswith(b"IDX\x01"):
            return entries
        entry_size = 36
        offset = 92
        while offset + entry_size <= len(data):
            chunk = data[offset:offset+entry_size]
            hash_val = struct.unpack("<I", chunk[:4])[0]
            addr = struct.unpack("<I", chunk[4:8])[0]
            if addr == 0:
                offset += entry_size
                continue
            # Extract key length (URL length)
            key_len = struct.unpack("<I", chunk[28:32])[0]
            entries[hash_val] = {"addr": addr, "key_len": key_len}
            offset += entry_size
    except:
        pass
    return entries

def parse_cache_file(filepath, index_map, out_dir):
    findings = []
    try:
        stats = os.stat(filepath)
        mod_time = datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        digest = sha256_file(filepath)
        ext = detect_file_type(filepath)
        filename = os.path.basename(filepath)

        # Save media
        if ext:
            out_path = os.path.join(out_dir, filename + ext)
            copy2(filepath, out_path)
            exif_data = extract_exif(out_path)
            findings.append({
                "file": filepath,
                "artifact": "Image/Video",
                "url": out_path,
                "modified": mod_time,
                "sha256": digest,
                "exif": exif_data
            })
            return findings

        # Extract text artifacts
        with open(filepath, "rb") as f:
            raw = f.read()
        decoded = raw.decode(errors="ignore")
        for a_type, url in extract_artifacts(decoded):
            findings.append({
                "file": filepath,
                "artifact": a_type,
                "url": url,
                "modified": mod_time,
                "sha256": digest
            })
    except:
        pass
    return findings

def generate_html(results, save_path):
    html = """
    <html><head><meta charset="utf-8"/>
    <title>Discord Forensic Report</title>
    <style>
    body { font-family: Arial; background:#1e1e2f; color:#f0f0f0; margin:20px; }
    h1 { text-align:center; color:#ffcc00; }
    table { border-collapse:collapse; width:100%; margin-top:20px; }
    th,td { border:1px solid #444; padding:8px; }
    th { background:#333; color:#ffcc00; }
    tr:nth-child(even) { background:#2a2a40; }
    img { max-width:150px; }
    a { color:#66ccff; }
    .mono { font-family:Consolas,monospace; }
    </style></head><body>
    <h1>Discord Cache Forensic Report</h1><table>
    <tr><th>File</th><th>Artifact</th><th>Preview/URL</th><th>Modified</th><th>SHA256</th></tr>
    """
    for row in results:
        if row["artifact"] == "Image/Video":
            link = f"<a href='{row['url']}'><img src='{row['url']}'></a>"
        else:
            link = f"<a href='{row['url']}'>{row['url']}</a>"
        html += f"<tr><td class='mono'>{row['file']}</td><td>{row['artifact']}</td>"
        html += f"<td>{link}</td><td class='mono'>{row['modified']}</td>"
        html += f"<td class='mono'>{row['sha256']}</td></tr>"
    html += "</table></body></html>"
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(html)

def make_evidence_bag(report_path, results, bag_path):
    with zipfile.ZipFile(bag_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(report_path, os.path.basename(report_path))
        manifest = []
        for r in results:
            manifest.append({
                "file": r["file"], "artifact": r["artifact"],
                "url": r.get("url"), "sha256": r["sha256"],
                "modified": r["modified"], "exif": r.get("exif")
            })
            if r["artifact"] == "Image/Video" and os.path.exists(r["url"]):
                zf.write(r["url"], os.path.join("media", os.path.basename(r["url"])))
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

# -------- GUI Logic --------
def run_parser(cache_dir, status_var, progress_var, progress_bar):
    results = []
    all_files = [os.path.join(root, f) for root, _, files in os.walk(cache_dir) for f in files if f != "index"]
    total = len(all_files) or 1
    media_dir = os.path.join(os.path.dirname(__file__), "extracted_media")
    os.makedirs(media_dir, exist_ok=True)

    idx = parse_index(os.path.join(cache_dir, "index")) if os.path.exists(os.path.join(cache_dir, "index")) else {}

    for i, fp in enumerate(all_files, 1):
        status_var.set(f"Scanning {i}/{total}: {os.path.basename(fp)}")
        progress_var.set(int(i * 100 / total))
        progress_bar.update_idletasks()
        results.extend(parse_cache_file(fp, idx, media_dir))

    if not results:
        messagebox.showinfo("Done", "No artifacts found.")
        return

    report_path = filedialog.asksaveasfilename(
        defaultextension=".html", filetypes=[("HTML files", "*.html")],
        title="Save HTML Report"
    )
    if not report_path:
        return
    generate_html(results, report_path)

    bag_path = report_path.replace(".html", "_evidence.zip")
    make_evidence_bag(report_path, results, bag_path)

    webbrowser.open(report_path)
    messagebox.showinfo("Done", f"Report: {report_path}\nEvidence Bag: {bag_path}")

def build_gui():
    root = Tk()
    root.title("Discord Forensic Suite")
    root.configure(bg="#1e1e2f")

    # Header
    header = Frame(root, bg="#1e1e2f")
    header.pack(fill=X, padx=16, pady=10)
    Label(header, text=ASCII_CAT, font=("Consolas", 14),
          bg="#1e1e2f", fg="#ffcc00", justify="left").pack(side=LEFT, padx=10)
    Label(header, text="Discord Cache Forensic Suite\nRecover evidence, URLs, and media from Discord cache.",
          fg="#ffcc00", bg="#1e1e2f", font=("Segoe UI", 12), justify="left").pack(side=LEFT, anchor="w")

    # Vars
    selected = StringVar()
    status = StringVar(value="Idle")
    progress = StringVar(value="0")

    # Controls
    control_frame = Frame(root, bg="#1e1e2f")
    control_frame.pack(fill=X, padx=16, pady=5)
    Button(control_frame, text="Select Cache Folder",
           command=lambda: selected.set(filedialog.askdirectory(title="Select Cache Folder")),
           bg="#333", fg="#ffcc00", font=("Segoe UI", 11)).pack(side=LEFT, padx=5)
    Button(control_frame, text="Run Parse",
           command=lambda: run_parser(selected.get(), status, progress, bar),
           bg="#333", fg="#ffcc00", font=("Segoe UI", 11)).pack(side=LEFT, padx=5)

    Label(root, textvariable=selected, bg="#1e1e2f", fg="#66ccff", font=("Consolas", 10)).pack(fill=X, padx=16)
    bar = ttk.Progressbar(root, orient="horizontal", mode="determinate", maximum=100, length=400)
    bar.pack(padx=16, pady=5)
    Label(root, textvariable=status, bg="#1e1e2f", fg="#f0f0f0").pack(padx=16)

    root.geometry("580x380")
    return root

if __name__ == "__main__":
    app = build_gui()
    app.mainloop()
