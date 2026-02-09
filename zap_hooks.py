import re
import os
import requests
import sys
from urllib.parse import urlparse

def zap_started(zap, target):
    # ------------------------------------------------------------------
    # KROK 0: Odczyt konfiguracji (plik lub ENV)
    # ------------------------------------------------------------------
    try:
        with open('/zap/wrk/security_level.txt', 'r') as f:
            target_level = f.read().strip()
    except FileNotFoundError:
        target_level = os.environ.get('SECURITY_LEVEL', 'low')
        
    print(f"--- [HOOK] Cel: Ustawienie poziomu bezpieczeństwa na: {target_level.upper()} ---")

    try:
        zap_url = zap.base
        parsed = urlparse(zap_url)
        port = parsed.port if parsed.port else 80
        proxy_url = f"http://127.0.0.1:{port}"
        print(f"[HOOK] Proxy ZAP: {proxy_url}")
    except Exception as e:
        print(f"[HOOK] ERROR: Nie udało się ustalić proxy: {e}")
        sys.exit(1)

    proxies = {'http': proxy_url, 'https': proxy_url}
    
    s = requests.Session()
    s.proxies.update(proxies)
    s.verify = False 

    # ------------------------------------------------------------------
    # KROK 1: Logowanie i zdobycie ciasteczka PHPSESSID
    # ------------------------------------------------------------------
    print("[HOOK] Krok 1: Pobieranie tokena i logowanie...")
    login_url = target + 'login.php'
    
    try:
        res_get = s.get(login_url, timeout=10)
        token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res_get.text)
        
        if not token_match:
            print("[HOOK] FATAL: Nie znaleziono tokena CSRF na stronie logowania.")
            return

        user_token = token_match.group(1)
        
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        
        res_post = s.post(login_url, data=login_data, allow_redirects=True)
        
        if "login.php" in res_post.url:
            print(f"[HOOK] OSTRZEŻENIE: Wciąż jesteśmy na {res_post.url}. Logowanie mogło się nie udać.")
        else:
            print(f"[HOOK] Logowanie w Pythonie: SUKCES (Jesteśmy na {res_post.url})")

    except Exception as e:
        print(f"[HOOK] Błąd sieciowy podczas logowania: {e}")
        return

    # ------------------------------------------------------------------
    # NAPRAWA BŁĘDU CookieConflictError
    # ------------------------------------------------------------------
    phpsessid = None
    for cookie in s.cookies:
        if cookie.name == 'PHPSESSID':
            phpsessid = cookie.value
    
    if not phpsessid:
        print("[HOOK] FATAL: Brak ciasteczka PHPSESSID po logowaniu!")
    else:
        print(f"[HOOK] Zdobyto PHPSESSID: {phpsessid}")

    # ------------------------------------------------------------------
    # KROK 2: Zmiana poziomu (dla pewności przez POST)
    # ------------------------------------------------------------------
    print(f"[HOOK] Krok 2: Ustawianie poziomu {target_level}...")
    security_url = target + 'security.php'
    
    try:
        res_sec = s.get(security_url)
        token_match_sec = re.search(r"name='user_token' value='([a-f0-9]+)'", res_sec.text)
        
        if token_match_sec:
            sec_token = token_match_sec.group(1)
            sec_data = {
                'security': target_level,
                'seclev_submit': 'Submit',
                'user_token': sec_token
            }
            res_change = s.post(security_url, data=sec_data)
            if res_change.status_code == 200:
                print(f"[HOOK] Wysłano żądanie zmiany poziomu.")
        else:
            print("[HOOK] Nie udało się pobrać tokena dla security.php (może brak autoryzacji?)")
            
    except Exception as e:
        print(f"[HOOK] Błąd przy zmianie poziomu: {e}")

    # ------------------------------------------------------------------
    # KROK 3: PRZEKAZANIE SESJI DO ZAP
    # ------------------------------------------------------------------
    if phpsessid:
        cookie_value = f"PHPSESSID={phpsessid}; security={target_level}"
        print(f"[HOOK] KONFIGURACJA ZAP: Wymuszam ciasteczka: {cookie_value}")

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