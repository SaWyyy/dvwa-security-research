import re
import os
import requests
import sys

def zap_started(zap, target):
    # KROK 0: Konfiguracja
    try:
        with open('/zap/wrk/security_level.txt', 'r') as f:
            target_level = f.read().strip()
    except FileNotFoundError:
        target_level = os.environ.get('SECURITY_LEVEL', 'low')
        
    print(f"--- [HOOK] Cel: Ustawienie poziomu bezpieczeństwa na: {target_level.upper()} ---")

    # ------------------------------------------------------------------
    # KROK 1: Logowanie BEZPOSREDNIE (Bypass ZAP)
    # ------------------------------------------------------------------
    # To działa, więc tego nie ruszamy!
    s = requests.Session()
    s.trust_env = False 
    s.proxies = {}      
    
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
        
        res_post = s.post(login_url, data=login_data, headers=headers, allow_redirects=True)
        
        if "login.php" in res_post.url:
            print(f"[HOOK] ERROR: Logowanie nieudane. Zostalismy na {res_post.url}")
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
        print("[HOOK] FATAL: Brak ciasteczka PHPSESSID!")

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

    # ------------------------------------------------------------------
    # KROK 3: Przekazanie sesji do ZAP (POPRAWIONE)
    # ------------------------------------------------------------------
    # Zamiast requests.get i zgadywania portu, używamy obiektu `zap`
    if phpsessid:
        cookie_value = f"PHPSESSID={phpsessid}; security={target_level}"
        print(f"[HOOK] KONFIGURACJA ZAP: Wstrzykuje ciasteczka: {cookie_value}")

        try:
            # Usuwamy stare reguły (ignorujemy błąd jeśli reguły brak)
            zap.replacer.remove_rule(description="Force Auth")
        except:
            pass

        try:
            # Dodajemy nową regułę używając wbudowanego klienta ZAP
            # To automatycznie użyje dobrego portu i API key
            res = zap.replacer.add_rule(
                description="Force Auth",
                enabled="true",
                matchtype="REQ_HEADER",
                matchregex="false",
                matchstring="Cookie",
                replacement=cookie_value
            )
            print(f"[HOOK] ZAP API Sukces: Reguła dodana.")
        except Exception as e:
            print(f"[HOOK] ZAP API Error: {e}")
    
    print("--- [HOOK] Setup zakończony. ---")