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

    # Ustalanie adresu proxy ZAP (potrzebne tylko do konfiguracji API na końcu)
    try:
        zap_url = zap.base
        parsed = urlparse(zap_url)
        port = parsed.port if parsed.port else 80
        # Adres API ZAP-a
        zap_proxy_url = f"http://127.0.0.1:{port}"
    except:
        zap_proxy_url = "http://127.0.0.1:8080"

    # ------------------------------------------------------------------
    # POPRAWKA GLÓWNA: Logowanie BEZ PROXY (Direct Connection)
    # ------------------------------------------------------------------
    # Zachowujemy się dokładnie tak jak setup_db.py, który działał.
    # Omijamy ZAP-a w fazie logowania, żeby nie gubić ciasteczek.
    s = requests.Session()
    s.trust_env = False # Ignoruj zmienne systemowe proxy
    s.proxies = {}      # Pusty słownik proxy = połączenie bezpośrednie
    
    # Target w Dockerze to localhost (dzięki --network=host)
    # Upewniamy się, że używamy tego samego hosta co w setup_db.py
    if "localhost" not in target and "127.0.0.1" not in target:
        # Jeśli target jest dziwny, zostawiamy go, ale dla pewności:
        print(f"[HOOK] Target to: {target}")

    # KROK 1: Logowanie
    print("[HOOK] Krok 1: Logowanie BEZPOSREDNIE (Bypass ZAP)...")
    login_url = target + 'login.php'
    
    try:
        # 1. Token CSRF
        res_get = s.get(login_url, timeout=10)
        token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res_get.text)
        
        if not token_match:
            print("[HOOK] FATAL: Brak tokena CSRF.")
            return

        user_token = token_match.group(1)
        
        # 2. Logowanie
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        
        headers = {
            'Referer': login_url,
            'User-Agent': 'ZAP-Hook-Agent'
        }
        
        # Logujemy się
        res_post = s.post(login_url, data=login_data, headers=headers, allow_redirects=True)
        
        # Weryfikacja
        if "login.php" in res_post.url:
            print(f"[HOOK] ERROR: Logowanie nieudane. Zostalismy na {res_post.url}")
            # Mały debug
            if "Login failed" in res_post.text: print("   -> Bledne haslo/login")
            if "CSRF" in res_post.text: print("   -> Blad CSRF")
        else:
            print(f"[HOOK] Logowanie SUKCES! (Jesteśmy na {res_post.url})")

    except Exception as e:
        print(f"[HOOK] Blad krytyczny logowania: {e}")
        return

    # Pobieranie ciasteczka z sesji Pythona
    phpsessid = None
    for cookie in s.cookies:
        if cookie.name == 'PHPSESSID':
            phpsessid = cookie.value
    
    if phpsessid:
        print(f"[HOOK] Zdobyto PHPSESSID: {phpsessid}")
    else:
        print("[HOOK] FATAL: Brak ciasteczka PHPSESSID! (Logowanie nie utworzylo sesji?)")

    # KROK 2: Zmiana poziomu (Też bezpośrednio)
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
            s.post(security_url, data=sec_data, headers={'Referer': security_url})
            print(f"[HOOK] Zmieniono poziom na {target_level}.")
    except Exception as e:
        print(f"[HOOK] Blad zmiany poziomu: {e}")

    # KROK 3: Przekazanie sesji do ZAP
    # Teraz łączymy się z API ZAP-a, żeby przekazać mu to ciasteczko, które zdobyliśmy bezpośrednio
    if phpsessid:
        cookie_value = f"PHPSESSID={phpsessid}; security={target_level}"
        print(f"[HOOK] KONFIGURACJA ZAP: Wstrzykuje ciasteczka: {cookie_value}")

        # Uwaga: Tutaj musimy użyć proxy/API ZAP-a, więc nie używamy naszej sesji 's' (która jest direct)
        # tylko prostego requests.get do API
        try:
            # Usuwamy stare reguły
            requests.get(f"{zap_proxy_url}/JSON/replacer/action/removeRule/?description=Force+Auth")
            
            # Dodajemy nową regułę
            # Musimy zakodować parametry URL, ale requests zrobi to za nas w params
            params = {
                'description': 'Force Auth',
                'enabled': 'True',
                'matchType': 'REQ_HEADER',
                'matchRegex': 'False',
                'matchString': 'Cookie',
                'replacement': cookie_value
            }
            res_api = requests.get(f"{zap_proxy_url}/JSON/replacer/action/addRule/", params=params)
            
            if res_api.status_code == 200:
                print("[HOOK] ZAP API: Reguła Replacer dodana pomyslnie.")
            else:
                print(f"[HOOK] ZAP API Error: {res_api.text}")
                
        except Exception as e:
            print(f"[HOOK] Nie udalo sie skonfigurowac ZAP API: {e}")
    
    print("--- [HOOK] Setup zakończony. ---")