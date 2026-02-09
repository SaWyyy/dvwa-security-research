import re
import os
import sys

def zap_started(zap, target):
    target_level = os.environ.get('SECURITY_LEVEL', 'low')
    
    print(f"--- [HOOK] Cel: Ustawienie poziomu bezpieczeństwa na: {target_level.upper()} ---")

    print("[HOOK] Krok 1: Pobieranie strony logowania...")
    login_url = target + '/login.php'
    res_login_page = zap.urlopen(login_url)
    token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", res_login_page)
    
    if not token_match:
        print("[HOOK] ERROR: Brak tokena logowania.")
        return
    user_token = token_match.group(1)

    print("[HOOK] Krok 2: Logowanie...")
    zap.urlopen(login_url, postData=f"username=admin&password=password&Login=Login&user_token={user_token}")

    print(f"[HOOK] Krok 3: Zmiana poziomu na {target_level}...")
    security_url = target + '/security.php'
    res_sec_page = zap.urlopen(security_url)
    token_match_sec = re.search(r"name='user_token' value='([a-f0-9]+)'", res_sec_page)
    
    if token_match_sec:
        sec_token = token_match_sec.group(1)
        sec_data = f"security={target_level}&seclev_submit=Submit&user_token={sec_token}"
        zap.urlopen(security_url, postData=sec_data)
        print(f"[HOOK] SUKCES: Poziom ustawiony na {target_level}.")
    else:
        print("[HOOK] ERROR: Nie udało się pobrać tokena dla zmiany security.")