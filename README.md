# Discord Forensic Suite (by jwdfir)

A digital forensics toolset for analyzing Discord's local cache artifacts.  
Designed for DFIR practitioners to quickly triage compromised hosts, recover deleted content, and generate portable forensic reports.

---

✨ Features
- Parse `%AppData%\discord\Cache\Cache_Data` for:
  - Cached images, thumbnails, and attachments
  - Webhook URLs & API calls
  - Recon and exfil files
- HTML report with SHA256 hashes & timestamps
- Evidence Package Mode: 
  - Bundles artifacts, a manifest, and the HTML report into a single ZIP

---
