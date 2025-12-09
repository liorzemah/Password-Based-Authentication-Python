import requests
import json
import time
import os
import psutil
import pyotp
import hashlib
import bcrypt
from datetime import datetime
from argon2 import PasswordHasher

SERVER_URL = "http://127.0.0.1:5000"
ATTACK_ENDPOINT = f"{SERVER_URL}/login"

with open("data/users.json", "r") as f:
    passwords_data = json.load(f)

CAPTCHA_TOKEN_INDEX = 3
TOTP_PROTECTION_INDEX = 4
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

argon_pass_hasher = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1)

def get_captcha_token(protection_flags):
    if len(protection_flags) > CAPTCHA_TOKEN_INDEX and protection_flags[CAPTCHA_TOKEN_INDEX] == '1':
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

def benchmark_hashing(hash_mode, password_list):
    """ 
    pure local benchmark to compare algorithm speed without HTTP overhead
    """
    total_hashes = 0
    start = time.time()
    cpu_samples = []
    mem_samples = []
    proc = psutil.Process(os.getpid())

    if hash_mode == "sha256":
        for pwd in password_list:
            hashlib.sha256(pwd.encode()).hexdigest()
            cpu_samples.append(psutil.cpu_percent(interval=None))
            mem_samples.append(proc.memory_info().rss)

    elif hash_mode == "bcrypt":
        for pwd in password_list:
            # realistic bcrypt use: generate a salt per-hash
            bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=12))
            cpu_samples.append(psutil.cpu_percent(interval=None))
            mem_samples.append(proc.memory_info().rss)

    elif hash_mode == "argon2":
        for pwd in password_list:
            argon_pass_hasher.hash(pwd)
            cpu_samples.append(psutil.cpu_percent(interval=None))
            mem_samples.append(proc.memory_info().rss)


    total_time = time.time() - start
    avg_ms = (total_time / total_hashes) * 1000 if total_hashes > 0 else 0
    hps = total_hashes / total_time if total_time > 0 else 0
    # compute cpu/memory stats
    avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else None
    avg_mem = (sum(mem_samples) / len(mem_samples)) / (1024 * 1024) if mem_samples else None
    peak_mem = max(mem_samples) / (1024 * 1024) if mem_samples else None
    return total_time, avg_ms, hps, avg_cpu, avg_mem, peak_mem


def run_attack(attack_type, targets_data, password_list, protection_flags, local_mode=False):
    
    target_users = [t['username'] for t in targets_data]
    if attack_type == "Brute-Force":
        hash_mode = targets_data[0]['hash_mode'] if targets_data else "unknown"
    else:
        hash_mode = "Mixed/Multiple"
    
    print(f"\n--- Starting {attack_type} Attack ---")
    print(f"Target Users: {', '.join(target_users)}, Hash Mode: {hash_mode}, Protections: {protection_flags}")
    # If caller requested local benchmarking (no HTTP), run hashing locally
    if local_mode:
        print("Running in local benchmark mode (no HTTP). This measures raw hash cost.")
        total_time_hashes, avg_ms, hps, avg_cpu_b, avg_mem_b, peak_mem_b = benchmark_hashing(hash_mode, password_list)
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result_log = {
            "timestamp_readable": time_str,
            "attack_type": attack_type,
            "targets": target_users,
            "hash_mode": hash_mode,
            "protections_active": protection_flags,
            "local_benchmark": True,
            "total_hashes": len(password_list),
            "total_hash_time_s": f"{total_time_hashes:.4f} s",
            "average_hash_time_ms": f"{avg_ms:.2f}",
            "hashes_per_second": f"{hps:.2f}",
            "avg_cpu_percent": f"{avg_cpu_b:.2f}" if avg_cpu_b is not None else None,
            "avg_memory_mb": f"{avg_mem_b:.2f}" if avg_mem_b is not None else None,
            "peak_memory_mb": f"{peak_mem_b:.2f}" if peak_mem_b is not None else None,
            "success_status": "N/A"
        }
        return result_log
    
    start_time = time.time()
    attempts = 0
    success_time = None
    success_found = False
    successful_password = None
    # CPU/memory sampling during remote attack
    cpu_samples = []
    mem_samples = []
    proc = psutil.Process(os.getpid())

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
            # sample cpu/memory right after each attempt
            cpu_samples.append(psutil.cpu_percent(interval=None))
            mem_samples.append(proc.memory_info().rss)
            
            if response.status_code == 200:
                
                if response_data.get("totp_required") and len(protection_flags) > TOTP_PROTECTION_INDEX and protection_flags[TOTP_PROTECTION_INDEX] == '1':
                    
                    if verify_totp(username, password, captcha_token):
                        print(f"!!! SUCCESS !!! Password Found: '{password}' for {username} (TOTP Verified)")
                        success_time = time.time()
                        success_found = True
                        successful_password = password
                        break
                    else:
                        pass
                
                else:
                    print(f"!!! SUCCESS !!! Password Found: '{password}' for {username}")
                    success_time = time.time()
                    success_found = True
                    successful_password = password
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
    average_latency_ms = (total_time / attempts) * 1000 if attempts > 0 else 0

    successful_password_category = "N/A"
    if success_found and successful_password:
        if successful_password in WEAK_PASSWORDS:
            successful_password_category = "Weak"
        elif successful_password in MEDIUM_PASSWORDS:
            successful_password_category = "Medium"
        elif successful_password in STRONG_PASSWORDS:
            successful_password_category = "Strong"
    
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # compute cpu/memory stats for remote mode
    avg_cpu = sum(cpu_samples) / len(cpu_samples)
    avg_mem = (sum(mem_samples) / len(mem_samples)) / (1024 * 1024) 
    peak_mem = max(mem_samples) / (1024 * 1024)

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
        "success_status": "Success" if success_found else "Failed to find (or Blocked)",
        "average_latency_ms": f"{average_latency_ms:.2f}",
        "successful_password_category": successful_password_category,
        "avg_cpu_percent": f"{avg_cpu:.2f}" if avg_cpu is not None else None,
        "avg_memory_mb": f"{avg_mem:.2f}" if avg_mem is not None else None,
        "peak_memory_mb": f"{peak_mem:.2f}" if peak_mem is not None else None
    }
    
    return result_log