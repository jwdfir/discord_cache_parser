# Discord Forensic Suite (by jwdfir)

A digital forensics toolset for analyzing Discord's local cache artifacts.  
Designed for DFIR practitioners to quickly triage compromised hosts, recover deleted content, and generate portable forensic reports.

---

Features
- Parse `%AppData%\discord\Cache\Cache_Data` for:
  - Cached images, thumbnails, and attachments
  - Webhook URLs & API calls
  - Recon and exfil files
- HTML report with SHA256 hashes & timestamps
- Evidence Package Mode: 
  - Bundles artifacts, a manifest, and the HTML report into a single ZIP

---

<img width="478" height="259" alt="discord tool 2" src="https://github.com/user-attachments/assets/85b91e70-1abf-41fc-85f7-806b24b6366b" />

---

<img width="1845" height="242" alt="discord tool 3" src="https://github.com/user-attachments/assets/37d048ee-9156-45f5-9a7c-6741838b65ee" />

