import re
import os
import requests
import sys
from urllib.parse import urlparse

def zap_started(zap, target):
    # KROK 0: Konfiguracja
    try:
        with open('/zap/wrk/security_level.txt', 'r') as f:
            target_level = f.read().strip()
    except FileNotFoundError:
        target_level = os.environ.get('SECURITY_LEVEL', 'low')
        
    print(f"--- [HOOK] Cel: Ustawienie poziomu bezpieczeństwa na: {target_level.upper()} ---")

    # Proxy ZAP (Dynamiczne)
    try:
        zap_url = zap.base
        parsed = urlparse(zap_url)
        port = parsed.port if parsed.port else 80
        proxy_url = f"http://127.0.0.1:{port}"
        # print(f"[HOOK] Proxy ZAP: {proxy_url}") 
    except:
        proxy_url = "http://127.0.0.1:8080"

    proxies = {'http': proxy_url, 'https': proxy_url}
    s = requests.Session()
    s.proxies.update(proxies)
    s.verify = False 

    # KROK 1: Logowanie
    print("[HOOK] Krok 1: Logowanie (z naglowkiem Referer)...")
    login_url = target + 'login.php'
    
    try:
        res_get = s.get(login_url, timeout=10)
        token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res_get.text)
        
        if not token_match:
            print("[HOOK] FATAL: Brak tokena CSRF.")
            return

        user_token = token_match.group(1)
        
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        
        # --- POPRAWKA: Dodajemy Referer ---
        headers = {
            'Referer': login_url,
            'User-Agent': 'ZAP-Hook-Agent'
        }
        
        res_post = s.post(login_url, data=login_data, headers=headers, allow_redirects=True)
        
        if "login.php" in res_post.url:
            print(f"[HOOK] ERROR: Logowanie nieudane. Zostalismy na {res_post.url}")
            # Szukamy komunikatu błędu w HTML
            if "Login failed" in res_post.text:
                print("[HOOK] Powod: Niepoprawne haslo/login.")
            elif "CSRF" in res_post.text:
                print("[HOOK] Powod: Blad CSRF.")
            else:
                 # Wypisz kawałek strony dla debugowania
                 print(f"[DEBUG] Fragment strony: {res_post.text[:300]}")
        else:
            print(f"[HOOK] Logowanie SUKCES! (Jesteśmy na {res_post.url})")

    except Exception as e:
        print(f"[HOOK] Blad: {e}")
        return

    # Pobieranie ciasteczka (Bezpiecznie)
    phpsessid = None
    for cookie in s.cookies:
        if cookie.name == 'PHPSESSID':
            phpsessid = cookie.value
    
    if phpsessid:
        print(f"[HOOK] Zdobyto PHPSESSID: {phpsessid}")
    else:
        print("[HOOK] FATAL: Brak ciasteczka PHPSESSID!")

    # KROK 2: Zmiana poziomu
    print(f"[HOOK] Krok 2: Ustawianie poziomu {target_level}...")
    security_url = target + 'security.php'
    try:
        res_sec = s.get(security_url)
        token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res_sec.text)
        
        if token_match:
            sec_token = token_match.group(1)
            sec_data = {
                'security': target_level,
                'seclev_submit': 'Submit',
                'user_token': sec_token
            }
            # Tutaj też warto dodać Referer
            s.post(security_url, data=sec_data, headers={'Referer': security_url})
            print(f"[HOOK] Zmieniono poziom.")
    except Exception as e:
        print(f"[HOOK] Blad zmiany poziomu: {e}")

    # KROK 3: Przekazanie do ZAP
    if phpsessid:
        cookie_value = f"PHPSESSID={phpsessid}; security={target_level}"
        print(f"[HOOK] KONFIGURACJA ZAP: {cookie_value}")

        try:
            zap.replacer.remove_rule(description="Force Auth")
        except:
            pass

        zap.replacer.add_rule(
            description="Force Auth",
            enabled=True,
            matchtype="REQ_HEADER",
            matchregex=False,
            matchstring="Cookie",
            replacement=cookie_value
        )
    
    print("--- [HOOK] Setup zakończony. ---")