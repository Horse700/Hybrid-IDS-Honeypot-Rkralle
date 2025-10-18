# Hybrid IDS + Honeypot (Robert Kralle)

## Overview
A hybrid security automation project combining a **Python-based Honeypot** and **Simple Intrusion Detection System (SIDS)**.  
Developed for **CYB333: Security Automation** at **National University**.

This project demonstrates:
- Real-time logging of suspicious connections.
- Automated alerts for burst activity or scan detection.
- Integration between honeypot and IDS modules.

---

## Project Details
- **Author:** Robert Kralle  
- **Course:** CYB333 Security Automation  
- **Instructor:** Professor Todd D. Raines  
- **Due Date:** October 26th, 2025  
- **Language:** Python 3

---

## Setup Instructions
### 1. Clone this repository:
```bash
git clone https://github.com/Horse700/Hybrid-IDS-Honeypot-Rkralle.git
cd Hybrid-IDS-Honeypot-Rkralle

## Run Instructions

### 1. Activate Virtual Environment
Before running the project, activate the virtual environment:

**Windows (PowerShell):**
```powershell
venv\Scripts\Activate.ps1

## 2. Install Dependencies
Once your virtual environment is active, install the required dependencies:

```bash
pip install -r requirements.txt

## 3. Run the Honeypot
Start the honeypot listener to capture incoming traffic:
```bash
python honeypot.py

Logs are written to data/honeypot.py

**Example Log Output:**
2025-10-17T14:45:00.116822,127.0.0.1,60145,8080,83,GET /test1 HTTP/1.1
2025-10-17T14:45:00.166792,127.0.0.1,60146,8080,83,GET /test2 HTTP/1.1

## 4. Run the Intrusion Detection System (IDS)
Open a second terminal and run:
```bash
python sids.py

Alerts are written to data/alerts.log

**Example Alert Output:**
2025-10-17T14:45:00.730847 ALERT Burst connections by 127.0.0.1. Hits in 10s >= 10

The IDS continuously monitors network activity based on honeypot logs and triggers alerts when the number of connections from a single IP exceeds the defined threshold. All alerts are stored in `data/alerts.log` for later review.

---

## 5. Simulate Activity (Windows)
Run this in **cmd.exe** (not PowerShell) to simulate multiple HTTP connections and trigger IDS alerts:
```cmd
for /L %i in (1,1,12) do curl -s http://127.0.0.1:8080/test%i >NUL

---

## 6. Deactivate Virtual Enviroment
When finished, deactivate the virtual enviroment:
```bash
deactivate