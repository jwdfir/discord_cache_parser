# 🕵️‍♂️ Discord Forensic Suite
[![License](https://img.shields.io/github/license/jwdfir/discord_cache_parser)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Status](https://img.shields.io/badge/status-active-success)

A **digital forensics and incident response (DFIR)** tool for extracting, analyzing, and reporting on **Discord cache artifacts**.  
Built by **[jwdfir](https://github.com/jwdfir)** to help investigators quickly triage compromised systems, recover deleted files, and reconstruct attacker timelines.

---

## ✨ Features
- 🔍 **Deep Cache Analysis:** Parse `%AppData%\discord\Cache\Cache_Data` for:
  - Attachments, images, thumbnails
  - Webhook URLs & API calls
  - Recon and exfil files
- 📑 **HTML Reports:** Auto-generate forensic reports with SHA256 hashes and timestamps.
- 📦 **Evidence Package Mode:** Bundle artifacts, a manifest, and the HTML report into a portable ZIP.
- 🖥️ **GUI & CLI:** Choose between a command-line parser or a full GUI application.
- 🔒 **Investigator-Friendly:** Simple, self-contained tool. No Discord API keys or elevated privileges needed.

---

## 📸 Screenshots

| GUI | Sample Report |
|-----|---------------|
| <img width="478" height="259" alt="discord tool 2" src="https://github.com/user-attachments/assets/85b91e70-1abf-41fc-85f7-806b24b6366b" />

---

<img width="944" height="128" alt="image" src="https://github.com/user-attachments/assets/f39314be-dbb9-4749-a373-d1b4e1690ea7" />


