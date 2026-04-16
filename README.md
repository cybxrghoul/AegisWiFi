# 🛡️ AegisWiFi — Wireless Security Analyzer

## Workflow
![AegisWiFi](screenshots/aegiswifi.gif)
AegisWiFi is a **cross-platform wireless network security analysis tool** designed to identify risks, misconfigurations, and anomalies in nearby WiFi environments.

It performs **real-time scanning, security scoring, and intelligent risk detection** to provide a structured overview of wireless network security.

---

## Features

**CROSS-PLATFORM SCANNING**

  * Windows (`netsh`)
  * Linux (`nmcli`)

**SECURITY ANALYSIS ENGINE**

  * Risk scoring (0–100)
  * Network classification
  * Security interpretation

**THREAT & RISK DETECTION**

  * Open network detection
  * Weak encryption (WEP / legacy WPA)
  * Hidden SSID identification
  * Duplicate SSID detection *(possible evil twin)*
  * Channel congestion analysis

  **ENVIRONMENT SUMMARY**

  * Overall risk level
  * Secure vs vulnerable networks breakdown

  **EXPORT CAPABILITY**

  * CSV report generation

---

## How It Works

1. Scans nearby wireless networks
2. Parses network data into structured objects
3. Applies a security scoring model
4. Detects anomalies and misconfigurations
5. Outputs a clean, human-readable report

---

## 📩Installation

```bash
git clone https://github.com/cybxrghoul/AegisWiFi.git
cd AegisWiFi
pip install -r requirements.txt
```

---

## Usage

### WINDOWS

```powershell
python aegiswifi.py
```

### LINUX (Kali / Parrot / Ubuntu)

```bash
python3 aegiswifi.py
```

---

## EXAMPLE OUTPUT

```
[1] HomeLab_5G
  BSSID       : AA:BB:CC:11:22:33
  Signal      : 82%
  Channel     : 36
  Security    : WPA2-Personal / CCMP
  Score       : 78/100
  Assessment  : Moderately Secure

[2] Cafe_Free_WiFi
  Security    : Open
  Score       : 15/100
  Assessment  : High Risk
  Warnings    :
    - Open network detected
```

---

## 🔐SECURITY & PRIVACY NOTICE 

* This tool performs **passive analysis only**
* No packet injection or intrusive actions are performed
* Users should **only analyze networks they own or are authorized to assess**

---

## LIMITATIONS

* Windows requires **Location Services enabled** for WiFi scanning
* Virtual machines may not detect WiFi interfaces without hardware passthrough
* Detection of rogue access points is **heuristic-based**, not definitive

---

## FUTURE IMPROVEMENTS

* Go-based high-performance scanning module
* Real-time monitoring mode
* Advanced anomaly detection using ML
* GUI dashboard
* Integration with threat intelligence sources

---

## AUTHOR

**Shiva Guru**
Cybersecurity Enthusiast | Detection Engineering | OSINT

---

## ⭐ Contribute / Support

If you found this useful, consider starring ⭐ the repository!
