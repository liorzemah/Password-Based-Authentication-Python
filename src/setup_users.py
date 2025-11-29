import requests
import json
import itertools

SERVER_URL = "http://127.0.0.1:5000"

with open("data/users.json", "r") as f:
    DATA = json.load(f)


def test_server_connection():
    try:
        requests.get(SERVER_URL)
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Could not connect to the server at {SERVER_URL}. Please ensure 'web_server.py' is running.")
        exit(1)

def generate_user_configs():

    all_passwords = (
        DATA["weak_passwords"] +
        DATA["medium_passwords"] +
        DATA["strong_passwords"]
    )

    HASH_ALGORITHMS = ["sha256", "bcrypt", "argon2"]

    user_configs = list(zip(all_passwords, itertools.cycle(HASH_ALGORITHMS * 10)))

    return user_configs

def main():

    test_server_connection()

    user_configs = generate_user_configs()

    registered_users_data = {} 
    registered_users_data["group_seed"] = DATA["group_seed"]
    registered_users_data["users"] = []

    print(f"Starting user registration (30 users)...")

    for i, (password, algo) in enumerate(user_configs):
        username = f"user_{i:02d}"
        
        if i < 10:
            strength = "weak"
        elif i < 20:
            strength = "medium"
        else:
            strength = "strong"

        register_payload = {
            "username": username,
            "password": password,
            "algo": algo
        }

        try:
            response = requests.post(f"{SERVER_URL}/register", json=register_payload)
            response_data = response.json()

            if response.status_code == 200:
                
                registered_users_data["users"].append({
                    "username": username,
                    "password": password,
                    "hash_mode": algo,
                    "strength": strength,
                    "totp_secret": response_data.get("totp_secret", "")
                })

            else:
                print(f"Failed to register {username}. Status: {response.status_code}, Error: {response_data.get('error', 'Unknown error')}")

        except Exception as e:
            print(f"An unexpected error occurred during registration for {username}: {e}")
            break

    with open("data/registered_users_data.json", "w") as f:
        json.dump(registered_users_data, f, indent=4)
    
    print("Finished setup users.")

if __name__ == "__main__":
    main()