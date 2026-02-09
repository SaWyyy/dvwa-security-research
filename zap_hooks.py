import re
import os
import requests
import sys
from urllib.parse import urlparse

def zap_started(zap, target):
    try:
        # Plik będzie w katalogu /zap/wrk/ (zmapowanym z workspace)
        with open('/zap/wrk/security_level.txt', 'r') as f:
            target_level = f.read().strip()
    except FileNotFoundError:
        # Fallback, jeśli plik nie istnieje (np. testy lokalne)
        target_level = os.environ.get('SECURITY_LEVEL', 'low')
        
    print(f"--- [HOOK] Cel: Ustawienie poziomu bezpieczeństwa na: {target_level.upper()} ---")

    try:
        zap_url = zap.base
        print(f"[HOOK] ZAP raportuje swój adres jako: {zap_url}")
        
        parsed_url = urlparse(zap_url)
        port = parsed_url.port
        
        if not port:
            port = 80
            
        proxy_url = f"http://127.0.0.1:{port}"
        print(f"[HOOK] Skonstruowano działający adres proxy: {proxy_url}")
        
    except Exception as e:
        print(f"[HOOK] FATAL ERROR: Nie udało się ustalić portu ZAP: {e}")
        sys.exit(1)

    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }

    # Używamy sesji
    s = requests.Session()
    s.proxies.update(proxies)
    s.verify = False 

    # ------------------------------------------------------------------
    # KROK 1: Pobranie tokena CSRF
    # ------------------------------------------------------------------
    print("[HOOK] Krok 1: Pobieranie strony logowania...")
    login_url = target + 'login.php'
    
    try:
        # Timeout ważny, żeby nie wisiało w nieskończoność
        res = s.get(login_url, timeout=10)
    except Exception as e:
        print(f"[HOOK] ERROR: Połączenie przez proxy nieudane: {e}")
        return

    token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res.text)
    if not token_match:
        print("[HOOK] ERROR: Brak tokena logowania w HTML. DVWA nie odpowiada poprawnie.")
        # Wypisz kawałek odpowiedzi do debugowania
        print(f"[DEBUG] Fragment HTML: {res.text[:200]}")
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
    
    if "Location" in res_login.history or "Welcome" in res_login.text:
         print("[HOOK] Logowanie wygląda na poprawne.")
    else:
         print("[HOOK] OSTRZEŻENIE: Nie widzę potwierdzenia zalogowania.")

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