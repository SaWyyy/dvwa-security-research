import re
import os
import requests
import sys

def zap_started(zap, target):
    # Pobieramy poziom z ENV
    target_level = os.environ.get('SECURITY_LEVEL', 'low')
    print(f"--- [HOOK] Cel: Ustawienie poziomu bezpieczeństwa na: {target_level.upper()} ---")

    proxy_url = zap.base.split('/JSON/')[0]
    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }
    print(f"[HOOK] Używam proxy ZAP: {proxy_url}")

    s = requests.Session()
    s.proxies.update(proxies)
    s.verify = False 

    # ------------------------------------------------------------------
    # KROK 1: Pobranie tokena CSRF
    # ------------------------------------------------------------------
    print("[HOOK] Krok 1: Pobieranie strony logowania...")
    login_url = target + 'login.php'
    
    try:
        res = s.get(login_url)
    except Exception as e:
        print(f"[HOOK] ERROR: Nie udało się połączyć: {e}")
        sys.exit(1)

    token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res.text)
    if not token_match:
        print("[HOOK] ERROR: Brak tokena logowania w HTML.")
        return
    user_token = token_match.group(1)
    print(f"[HOOK] Znaleziono token logowania: {user_token}")

    # ------------------------------------------------------------------
    # KROK 2: Logowanie (POST)
    # ------------------------------------------------------------------
    print("[HOOK] Krok 2: Logowanie...")
    login_payload = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': user_token
    }
    
    res_login = s.post(login_url, data=login_payload)
    
    if "Welcome to Damn Vulnerable Web App" not in res_login.text and "Location" not in res_login.history:
         print("[HOOK] OSTRZEŻENIE: Logowanie mogło się nie udać (nie widzę powitania).")

    # ------------------------------------------------------------------
    # KROK 3: Zmiana poziomu Security (POST)
    # ------------------------------------------------------------------
    print(f"[HOOK] Krok 3: Zmiana poziomu na {target_level}...")
    security_url = target + 'security.php'
    
    res_sec_page = s.get(security_url)
    token_match_sec = re.search(r"name='user_token' value='([a-f0-9]+)'", res_sec_page.text)
    
    if token_match_sec:
        sec_token = token_match_sec.group(1)
        
        sec_payload = {
            'security': target_level,
            'seclev_submit': 'Submit',
            'user_token': sec_token
        }
        
        s.post(security_url, data=sec_payload)
        print(f"[HOOK] SUKCES: Wysłano żądanie zmiany poziomu na {target_level}.")
    else:
        print("[HOOK] ERROR: Nie udało się pobrać tokena dla strony security.")

    print("--- [HOOK] Setup zakończony. ---")