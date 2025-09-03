import os
import re
import struct
import hashlib
from datetime import datetime

# === CONFIG ===
CACHE_DIR = r"C:\Users\joseph.williams\AppData\Roaming\discord\Cache\Cache_Data"
OUTPUT_HTML = "discord_cache_full_report.html"
IMAGE_DIR = "extracted_images"

# Regex patterns for useful artifacts
WEBHOOK_REGEX = re.compile(r"https://discord\.com/api/webhooks/[^\s\"']+")
ATTACHMENT_REGEX = re.compile(r"https://cdn\.discordapp\.com/attachments/[^\s\"']+")
API_REGEX = re.compile(r"https://discord(app)?\.com/api/v\d+/[^\s\"']+")

# Ensure image output folder exists
os.makedirs(IMAGE_DIR, exist_ok=True)

def sha256_file(filepath):
    """Generate SHA256 hash for integrity."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def detect_file_type(filepath):
    """Detect if a cache entry is a common image or video."""
    signatures = {
        b"\xFF\xD8\xFF": ".jpg",
        b"\x89PNG\r\n\x1A\n": ".png",
        b"GIF87a": ".gif",
        b"GIF89a": ".gif",
        b"RIFF": ".webp",
        b"\x00\x00\x00\x18ftypmp4": ".mp4"
    }
    with open(filepath, "rb") as f:
        header = f.read(16)
    for sig, ext in signatures.items():
        if header.startswith(sig):
            return ext
    return None

def extract_artifacts(data):
    """Extract URLs and webhook references."""
    artifacts = []
    artifacts += [("Webhook", url) for url in WEBHOOK_REGEX.findall(data)]
    artifacts += [("Attachment", url) for url in ATTACHMENT_REGEX.findall(data)]
    artifacts += [("API Call", url) for url in API_REGEX.findall(data)]
    return artifacts

def parse_index(index_file):
    """Parse Chromium Simple Cache index for URL mapping."""
    entries = {}
    try:
        with open(index_file, "rb") as f:
            data = f.read()
        if not data.startswith(b"IDX\x01"):
            print("Invalid index header.")
            return entries

        # Entry size and header offsets (from Chromium spec)
        entry_size = 36
        offset = 92

        while offset + entry_size <= len(data):
            entry_data = data[offset:offset+entry_size]
            hash_val, = struct.unpack("<I", entry_data[:4])
            next_entry = struct.unpack("<I", entry_data[20:24])[0]
            key_len = struct.unpack("<I", entry_data[28:32])[0]
            if key_len == 0:
                break
            entries[hash_val] = {"key_len": key_len}
            offset += entry_size
    except Exception as e:
        print(f"Error parsing index: {e}")
    return entries

def parse_cache_file(filepath, index_map):
    """Parse text artifacts and detect binary files."""
    findings = []
    try:
        stats = os.stat(filepath)
        mod_time = datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        sha256 = sha256_file(filepath)

        # Detect image/video files
        ext = detect_file_type(filepath)
        if ext:
            filename = os.path.basename(filepath) + ext
            out_path = os.path.join(IMAGE_DIR, filename)
            with open(filepath, "rb") as src, open(out_path, "wb") as dst:
                dst.write(src.read())
            findings.append({
                "file": filepath,
                "artifact": "Image/Video",
                "url": out_path,
                "modified": mod_time,
                "sha256": sha256
            })
            return findings

        # Parse as text
        with open(filepath, "rb") as f:
            raw_data = f.read()
        decoded = raw_data.decode(errors="ignore")
        artifacts = extract_artifacts(decoded)
        for artifact_type, url in artifacts:
            findings.append({
                "file": filepath,
                "artifact": artifact_type,
                "url": url,
                "modified": mod_time,
                "sha256": sha256
            })
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return findings

def generate_html(results):
    """Create HTML forensic report."""
    html = """
    <html>
    <head>
        <title>Discord Cache Forensic Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background-color: #f4f4f4; }
            tr:nth-child(even) { background-color: #fafafa; }
            img { max-width: 150px; }
            a { color: #0066cc; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>Discord Cache Forensic Report</h1>
        <table>
            <tr>
                <th>File</th>
                <th>Artifact Type</th>
                <th>Preview / URL</th>
                <th>Modified</th>
                <th>SHA256</th>
            </tr>
    """
    for row in results:
        if row['artifact'] == "Image/Video":
            link = f"<a href='{row['url']}'><img src='{row['url']}'></a>"
        else:
            link = f"<a href='{row['url']}'>{row['url']}</a>"
        html += f"""
            <tr>
                <td>{row['file']}</td>
                <td>{row['artifact']}</td>
                <td>{link}</td>
                <td>{row['modified']}</td>
                <td>{row['sha256']}</td>
            </tr>
        """
    html += """
        </table>
    </body>
    </html>
    """
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"HTML report generated: {OUTPUT_HTML}")

def main():
    index_file = os.path.join(CACHE_DIR, "index")
    index_map = {}
    if os.path.exists(index_file):
        index_map = parse_index(index_file)
        print(f"Parsed {len(index_map)} entries from index.")

    all_results = []
    for root, _, files in os.walk(CACHE_DIR):
        for file in files:
            if file == "index":  # Skip index itself
                continue
            filepath = os.path.join(root, file)
            all_results.extend(parse_cache_file(filepath, index_map))
    if all_results:
        generate_html(all_results)
    else:
        print("No artifacts found.")

if __name__ == "__main__":
    main()
