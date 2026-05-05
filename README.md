# 🛡️ Network Traffic Monitoring & Intrusion Detection System

A real-time network intrusion detection system built with Python, Scapy, and Machine Learning.

## 🔍 How It Works

Live network packets are captured → parsed → converted to features → scored by an Isolation Forest ML model → displayed on a live dashboard.

## 🧩 Modules

| Module | Description |
|--------|-------------|
| 1 | Project setup & environment |
| 2 | Live packet capture (Scapy) |
| 3 | Packet parser |
| 4 | Feature engineering |
| 5 | ML model training (Isolation Forest) |
| 6 | Real-time detection engine |
| 7 | Alert & logging system |
| 8 | Flask REST API + SocketIO |
| 9 | Live web dashboard |

## 🚀 How To Run

### 1. Clone the repo
```bash
git clone https://github.com/jakshdoit/network-ids.git
cd network-ids
```

### 2. Create and activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Train the model
```bash
venv/bin/python3 src/models/train_model.py
```

### 4. Start the API server
```bash
sudo venv/bin/python3 src/api/app.py
```

### 5. Open the dashboard
```bash
open dashboard/index.html
```

## 🛠️ Tech Stack

- **Python 3** — core language
- **Scapy** — packet capture & parsing
- **Scikit-learn** — Isolation Forest ML model
- **Flask + SocketIO** — REST API & real-time streaming
- **HTML/CSS/JS** — live dashboard

## ⚙️ Requirements

- macOS (tested on M1)
- Python 3.9+
- sudo access (for packet capture)
