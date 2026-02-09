import re
import time

def zap_started(zap, target):
    print(f"--- [HOOK] Starting authentication setup for {target} ---")

    print("[HOOK] Krok 1: Pobieranie strony logowania po token...")
    login_url = target + 'login.php'
    res_login_page = zap.urlopen(login_url)

    token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res_login_page)
    
    if not token_match:
        print("[HOOK] ERROR: Nie znaleziono user_token! Logowanie niemożliwe.")
        return
        
    user_token = token_match.group(1)
    print(f"[HOOK] Znaleziono token: {user_token}")

    print("[HOOK] Krok 2: Wysyłanie danych logowania...")
    login_data = f"username=admin&password=password&Login=Login&user_token={user_token}"
    zap.urlopen(login_url, postData=login_data)
  
    print("[HOOK] Krok 3: Ustawianie poziomu bezpieczeństwa na LOW...")

    security_url = target + 'security.php'
    res_sec_page = zap.urlopen(security_url)
    token_match_sec = re.search(r"name='user_token' value='([a-f0-9]+)'", res_sec_page)
    
    if token_match_sec:
        sec_token = token_match_sec.group(1)
        sec_data = f"security=low&seclev_submit=Submit&user_token={sec_token}"
        zap.urlopen(security_url, postData=sec_data)
        print("[HOOK] Poziom bezpieczeństwa ustawiony na LOW.")
    else:
        print("[HOOK] Nie udało się wysłać formularza security, próbuję obejścia...")

    print("--- [HOOK] Setup zakończony. ZAP rozpoczyna skanowanie ---")