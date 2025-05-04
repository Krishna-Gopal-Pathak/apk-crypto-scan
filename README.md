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

1. **Install JRE 8u451 and set the PATH environment variable and that is included in this repository.**
   
2. **Install Python 3.6+**

3. **Install Python dependencies**

   ```bash
   pip install tqdm termcolor

4. **Run the Tool**:
    ```bash
    python check_cryptography.py <apk_file_path>
    ```

    Replace `<apk_file_path>` with the path to the APK file you want to analyze.

---

### 🖼️ Tool Screenshot:

![Tool Screenshot](https://github.com/user-attachments/assets/34f3848f-c05c-431b-a396-93b0f66ffa05)

---

### 📝 Notes:
- **No need to install APKTool separately** — the script includes it.
- Make sure **JRE is correctly installed** and available in your system `PATH`.
- **Hardcoded key detection** may produce false positives — treat them as warnings, not definite findings.
