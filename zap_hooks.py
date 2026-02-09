import re
import os
import requests
import sys

def zap_started(zap, target):
    # Pobieramy poziom z ENV
    target_level = os.environ.get('SECURITY_LEVEL', 'low')
    print(f"--- [HOOK] Cel: Ustawienie poziomu bezpieczeństwa na: {target_level.upper()} ---")

    zap_port = os.environ.get('ZAP_PORT')
    
    if not zap_port:
        # Fallback: jeśli zmienna nie istnieje, próbujemy domyślny 8080
        print("[HOOK] OSTRZEŻENIE: Nie znaleziono ZAP_PORT w ENV. Przyjmuję 8080.")
        zap_port = "8080"
        
    proxy_url = f"http://127.0.0.1:{zap_port}"
    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }
    print(f"[HOOK] Używam proxy ZAP: {proxy_url}")

    # Używamy sesji, żeby ciasteczka (cookies) przechodziły między zapytaniami
    s = requests.Session()
    s.proxies.update(proxies)
    s.verify = False 

    # ------------------------------------------------------------------
    # KROK 1: Pobranie tokena CSRF
    # ------------------------------------------------------------------
    print("[HOOK] Krok 1: Pobieranie strony logowania...")
    login_url = target + 'login.php'
    
    try:
        res = s.get(login_url, timeout=10)
    except Exception as e:
        print(f"[HOOK] ERROR: Nie udało się połączyć przez proxy: {e}")
        # Nie zabijamy procesu sys.exit(1), żeby ZAP mógł spróbować skanować mimo to
        return

    token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res.text)
    if not token_match:
        print("[HOOK] ERROR: Brak tokena logowania w HTML. DVWA może nie działać poprawnie.")
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
    
    # Sprawdzenie czy jesteśmy zalogowani (szukamy tekstu lub przekierowania)
    if "Location" in res_login.history or "Welcome" in res_login.text:
         print("[HOOK] Logowanie wygląda na poprawne.")
    else:
         print("[HOOK] OSTRZEŻENIE: Możliwy błąd logowania (brak potwierdzenia w odpowiedzi).")

    # ------------------------------------------------------------------
    # KROK 3: Zmiana poziomu Security (POST)
    # ------------------------------------------------------------------
    print(f"[HOOK] Krok 3: Zmiana poziomu na {target_level}...")
    security_url = target + 'security.php'
    
    # Ponowne pobranie tokena z wnętrza aplikacji
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
        print("[HOOK] ERROR: Nie udało się pobrać tokena dla strony security (może brak logowania?).")

    print("--- [HOOK] Setup zakończony. ---")