# apk-crypto-scan

**apk-crypto-scan** — Fast APK cryptography scanner with colorful output and parallel speed.

This tool helps security researchers, mobile pentesters, and developers analyze Android APKs for weak cryptographic practices and potential hardcoded keys. It automatically decompiles the APK using APKTool, scans Java and smali code, and reports risky patterns.

---

## 🌟 Features

- ⚡ **Fast scanning** → Parallel analysis of Java & smali code  
- 🛡 **Detects weak crypto** → MD5, SHA-1, DES, RC4, AES/ECB patterns  
- 🔑 **Flags potential hardcoded keys** → Hex & Base64 (warning: may include false positives)  
- 🌍 **Cross-platform** → Works on Windows, Linux, macOS  
- 📊 **Progress bar & live feedback** → Smooth experience on large APKs  
- 🎨 **Colored terminal output** → Cyan for info, yellow for sections, red for findings, green when clean  
- 🧩 **Easy integration** → Plug into your mobile appsec or pentesting workflow

---

## 📦 Requirements

- Python 3.6+
- [APKTool](https://ibotpeaches.github.io/Apktool/) installed and accessible (Windows users: check `.bat` path)
- Python modules:
  - tqdm
  - termcolor

Install dependencies:

```bash
pip install tqdm termcolor

