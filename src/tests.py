import subprocess
import time
import os
import json
import requests
from tabulate import tabulate

import statistics
import math
import re

from attack_generator import run_attack, SERVER_URL, POTENTIAL_PASSWORDS, WEAK_PASSWORDS
from attack_generator import REGISTERED_USERS_MAP

ALL_RESULTS = []
ATTACK_SUMMARY_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "attack_summary_results.json")

WEB_SERVER_FILE = "src/web_server.py" 
SETUP_USERS_FILE = "src/setup_users.py" 

CONFIGS_TO_TEST = {
    "BF_Basic_SHA256": {
        "attack_type": "Brute-Force",
        "targets_data": [{"username": "user_20", "hash_mode": "sha256"}],
        "password_list": POTENTIAL_PASSWORDS,
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"},
        "local_mode": True
    },
    "BF_Basic_Argon2": {
        "attack_type": "Brute-Force",
        "targets_data": [{"username": "user_20", "hash_mode": "argon2"}],
        "password_list": POTENTIAL_PASSWORDS,
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"},
        "local_mode": True
    },
    "BF_Basic_Bcrypt": {
        "attack_type": "Brute-Force",
        "targets_data": [{"username": "user_20", "hash_mode": "bcrypt"}],
        "password_list": POTENTIAL_PASSWORDS,
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"},
        "local_mode": True
    },
    "BF_with_Rate_Limiting": {
        "attack_type": "Brute-Force",
        "targets_data": [{"username": "user_17", "hash_mode": "bcrypt"}],
        "password_list": POTENTIAL_PASSWORDS,
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "1", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"}
    },
    "BF_with_Account_Lockout": {
        "attack_type": "Brute-Force",
        "targets_data": [{"username": "user_18", "hash_mode": "bcrypt"}],
        "password_list": POTENTIAL_PASSWORDS,
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "1", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"}
    },
    "BF_with_Pepper": {
        "attack_type": "Brute-Force",
        "targets_data": [{"username": "user_19", "hash_mode": "bcrypt"}],
        "password_list": POTENTIAL_PASSWORDS,
        "env": {"ENABLE_PEPPER": "1", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"}
    },
    "BF_with_TOTP": {
        "attack_type": "Brute-Force",
        "targets_data": [{"username": "user_09", "hash_mode": "sha256"}],
        "password_list": POTENTIAL_PASSWORDS,
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "1", "ENABLE_SALT": "1"}
    },
    "BF_without_Salt": {
        "attack_type": "Brute-Force",
        "targets_data": [{"username": "user_08", "hash_mode": "sha256"}],
        "password_list": POTENTIAL_PASSWORDS,
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "0"}
    },
    "PS_Basic": {
        "attack_type": "Password-Spraying",
        "targets_data": REGISTERED_USERS_MAP.values(),
        "password_list": WEAK_PASSWORDS[:1],
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"}
    },
    "PS_with_Account_Lockout": {
        "attack_type": "Password-Spraying",
        "targets_data": REGISTERED_USERS_MAP.values(),
        "password_list": WEAK_PASSWORDS[:2],
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "0", "ENABLE_LOCKOUT": "1", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"}
    },
    "PS_with_Rate_Limiting": {
        "attack_type": "Password-Spraying",
        "targets_data": REGISTERED_USERS_MAP.values(),
        "password_list": WEAK_PASSWORDS[:2],
        "env": {"ENABLE_PEPPER": "0", "ENABLE_RATE_LIMITING": "1", "ENABLE_LOCKOUT": "0", "ENABLE_CAPTCHA": "0", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"}
    },
    "PS_Multi_Password": {
        "attack_type": "Password-Spraying",
        "targets_data": REGISTERED_USERS_MAP.values(),
        "password_list": WEAK_PASSWORDS[-1:],
        "env": {"ENABLE_PEPPER": "1", "ENABLE_RATE_LIMITING": "1", "ENABLE_LOCKOUT": "1", "ENABLE_CAPTCHA": "1", "ENABLE_TOTP": "0", "ENABLE_SALT": "1"}
    }
}


def run_setup_users():
    print("--- Running setup_users.py to register users ---")
    
    try:
        subprocess.check_call(["python3", SETUP_USERS_FILE], env=os.environ.copy())
        print("--- setup_users.py completed successfully ---")
        with open("data/registered_users_data.json", "r") as f:
            data = json.load(f)
        REGISTERED_USERS_MAP.update({user['username']: user for user in data['users']})
        CONFIGS_TO_TEST["PS_Basic"]["targets_data"] = REGISTERED_USERS_MAP.values()
        CONFIGS_TO_TEST["PS_with_Account_Lockout"]["targets_data"] = REGISTERED_USERS_MAP.values()
        CONFIGS_TO_TEST["PS_with_Rate_Limiting"]["targets_data"] = REGISTERED_USERS_MAP.values()
        CONFIGS_TO_TEST["PS_Multi_Password"]["targets_data"] = REGISTERED_USERS_MAP.values()
        return True
    except subprocess.CalledProcessError as e:
        print(f"!!! ERROR: setup_users.py failed with code {e.returncode}")
        return False

def set_and_run_test(test_name, config):
    global ALL_RESULTS
    
    current_env = os.environ.copy()
    current_env.update(config["env"])
    
    protection_flags = "".join(config["env"].values())

    print(f"\n========================================================")
    print(f"       STARTING TEST: {test_name} (Flags: {protection_flags})")
    print(f"========================================================")

    server_process = subprocess.Popen(["python3", WEB_SERVER_FILE], env=current_env)
    
    time.sleep(3) 
    
    if not run_setup_users():
        server_process.terminate()
        server_process.wait()
        return

    try:
        if config["attack_type"] == "Brute-Force":
             result = run_attack(
                config["attack_type"],
                config["targets_data"],
                config["password_list"],
                protection_flags,
                config.get("local_mode", False)
            )
        elif config["attack_type"] == "Password-Spraying":
             result = run_attack(
                config["attack_type"],
                list(config["targets_data"]), 
                config["password_list"],
                protection_flags,
                config.get("local_mode", False)
            )

        if result:
            result['test_name'] = test_name
            active_protections = [
                name.replace("ENABLE_", "")
                for name, enabled in config["env"].items()
                if enabled == "1"
            ]
            result["protections_active"] = active_protections
            ALL_RESULTS.append(result)

    except Exception as e:
        print(f"!!! Error during attack execution for {test_name}: {e}")
        
    print(f"\n--- Stopping server process ({server_process.pid}) ---")
    server_process.terminate()
    server_process.wait()
    print("Server stopped.")
    
    for key in config["env"].keys():
        if key in os.environ:
            del os.environ[key]

def save_tests_summary():
    # Compute duration analysis and embed it into the single summary JSON file.
    try:
        stats = generate_attack_duration_stats(ALL_RESULTS)

        # Write a single JSON file containing results + analysis to preserve a single artifact
        combined = {
            'results': ALL_RESULTS,
            'attack_duration_analysis': stats
        }
        with open(ATTACK_SUMMARY_FILE, 'w') as f:
            json.dump(combined, f, indent=4)

        print(f"\nCombined JSON summary + duration analysis saved to {ATTACK_SUMMARY_FILE}")
    except Exception as e:
        # Fallback: just write results array if analysis fails
        with open(ATTACK_SUMMARY_FILE, "w") as f:
            json.dump(ALL_RESULTS, f, indent=4)
        print(f"\nRaw JSON summary saved to {ATTACK_SUMMARY_FILE} (analysis failed: {e})")


def parse_seconds(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        regex_search = re.search(r"([0-9]*\.?[0-9]+)", value)
        if regex_search:
            try:
                return float(regex_search.group(1))
            except ValueError:
                return None
    return None


def generate_attack_duration_stats(all_results):
    durations = []
    for result in all_results:
        duration = None
        for stat in ("time_to_completion_s", "total_hash_time_s", "time_to_first_success_s"):
            if stat in result:
                duration = parse_seconds(result[stat])
                if duration is not None:
                    break
        result['attack_duration_sec'] = duration
        if duration is not None:
            durations.append(duration)

    durations_sorted = sorted(durations)
    count = len(durations_sorted)
    avarage = statistics.mean(durations_sorted)
    med = statistics.median(durations_sorted)
    minimum = durations_sorted[0]
    maximum = durations_sorted[-1]
    stdev = statistics.stdev(durations_sorted) if count > 1 else 0.0

    analysis = {
        'count': count,
        'average_attack_time_s': avarage,
        'median_attack_time_s': med,
        'min_attack_time_s': minimum,
        'max_attack_time_s': maximum,
        'stdev_attack_time_s': stdev,
        'durations_sorted_s': durations_sorted,
    }

    return analysis

if __name__ == "__main__":
    try:
        requests.get(SERVER_URL, timeout=1)
        print("WARNING: The server appears to be running. Please stop it manually before running tests.py.")
        exit(1)
    except requests.exceptions.ConnectionError:
        pass 
    
    for test_name, config in CONFIGS_TO_TEST.items():
        set_and_run_test(test_name, config)

    save_tests_summary() 
    
    print("\n\nAll tests completed. Check 'attempts.log' and 'attack_summary_results.json' for data.")