from flask import Flask, request as Request, jsonify as Jsonify
from argon2 import PasswordHasher, exceptions as ArgonExceptions
import json
import hashlib
import bcrypt
import pyotp
import secrets
import os
import time


app = Flask(__name__)

# basic config
GROUP_SEED = "GROUP_SEED_SAMPLE"  # need to replace with our IDs
ENABLE_PEPPER = os.environ.get("ENABLE_PEPPER", "true").lower() == "true"
ENABLE_SALT = os.environ.get("ENABLE_SALT", "true").lower() == "true"
PEPPER = secrets.token_hex(16) if ENABLE_PEPPER else ""
ENABLE_RATE_LIMITING = os.environ.get("ENABLE_RATE_LIMITING", "true").lower() == "true"
ENABLE_LOCKOUT = os.environ.get("ENABLE_LOCKOUT", "true").lower() == "true"
ENABLE_CAPTCHA = os.environ.get("ENABLE_CAPTCHA", "true").lower() == "true"
ENABLE_TOTP = os.environ.get("ENABLE_TOTP", "true").lower() == "true"

# runtime db - erased after server restart
users = {}
login_attempts = {}  # {username: [timestamps]}
lockout_info = {}    # {username: {"count": int, "locked_until": float}}
captcha_tokens = set()

# definitions
RATE_LIMIT_WINDOW = 60  # in seconds
RATE_LIMIT_MAX_ATTEMPTS = 5
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 300  # in seconds
ATTEMPTS_LOG_FILE = "attempts.log"

argon_pass_hasher = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1)

def get_protection_flags(username):
    user = users.get(username)
    algo = user["algo"] if user else ""

    return "{}{}{}{}{}{}".format(
    int(ENABLE_RATE_LIMITING),
    int(ENABLE_LOCKOUT),
    int(ENABLE_CAPTCHA),
    int(ENABLE_TOTP and username in users),
    int(ENABLE_PEPPER),
    int(ENABLE_SALT or algo == "argon2") # salt always enable in case of argon2 (api prevent salt manipulation)
)

def log_attempt_json(username, hash_mode, result, start_time):
    latency = int((time.time() - start_time) * 1000)
    log_entry = {
    "timestamp": int(time.time() * 1000),
    "group_seed": GROUP_SEED,
    "username": username,
    "hash_mode": hash_mode,
    "protection_flags": get_protection_flags(username),
    "result": result,
    "latency_ms": latency
    }
    with open(ATTEMPTS_LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def hash_password_sha256(password, salt):
    return hashlib.sha256((password + salt + PEPPER).encode()).hexdigest()

def hash_password_bcrypt(password):
    salt = bcrypt.gensalt(rounds=12) if ENABLE_SALT else b''
    return bcrypt.hashpw((password + PEPPER).encode(), salt).decode()

def hash_password_argon2(password):
    return argon_pass_hasher.hash(password + PEPPER)

def verify_password(username, password):
    user = users.get(username)
    if not user:
        return False
    algo = user["algo"]
    stored_hash = user["password"]
    salt = user.get("salt", "") if ENABLE_SALT else ""
    try:
        if algo == "sha256":
            return stored_hash == hash_password_sha256(password, salt)
        elif algo == "bcrypt":
            return bcrypt.checkpw((password + PEPPER).encode(), stored_hash.encode())
        elif algo == "argon2":
            argon_pass_hasher.verify(stored_hash, password + PEPPER)
            return True
    except (ValueError, ArgonExceptions.VerifyMismatchError):
        return False
    return False

def is_rate_limited(username):
    now = time.time()
    attempts = login_attempts.get(username, [])
    attempts = [ts for ts in attempts if now - ts < RATE_LIMIT_WINDOW]
    login_attempts[username] = attempts
    return len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS

def is_locked_out(username):
    info = lockout_info.get(username)
    if not info:
        return False
    if time.time() < info.get("locked_until", 0):
        return True
    return False

def record_failed_attempt(username):
    if not ENABLE_LOCKOUT:
        return
    info = lockout_info.setdefault(username, {"count": 0, "locked_until": 0})
    info["count"] += 1
    if info["count"] >= LOCKOUT_THRESHOLD:
        info["locked_until"] = time.time() + LOCKOUT_DURATION
        info["count"] = 0

def reset_lockout(username):
    if not ENABLE_LOCKOUT:
        return
    if username in lockout_info:
        lockout_info[username]["count"] = 0
        lockout_info[username]["locked_until"] = 0

@app.route("/register", methods=["POST"])
def register():
    data = Request.get_json()
    username = data.get("username")
    password = data.get("password")
    algo = data.get("algo", "sha256")

    if username in users:
        return Jsonify({"error": "User already exists"}), 400

    salt = secrets.token_hex(8) if ENABLE_SALT else ""
    if algo == "sha256":
        hashed = hash_password_sha256(password, salt)
    elif algo == "bcrypt":
        hashed = hash_password_bcrypt(password)
    elif algo == "argon2":
        hashed = hash_password_argon2(password)
    else:
        return Jsonify({"error": "Invalid algorithm"}), 400

    totp_secret = pyotp.random_base32()

    users[username] = {
        "password": hashed,
        "salt": salt, # only for sha256
        "algo": algo,
        "totp_secret": totp_secret
    }
    return Jsonify({"message": f"User {username} registered successfully.", "totp_secret": totp_secret})

@app.route("/login", methods=["POST"])
def login():
    start_time = time.time()
    data = Request.get_json()
    username = data.get("username")
    password = data.get("password")
    captcha_token = data.get("captcha_token")
    user = users.get(username)
    algo = user["algo"] if user else "unknown"

    if ENABLE_CAPTCHA and captcha_token not in captcha_tokens:
        log_attempt_json(username, algo, "captcha_required", start_time)
        return Jsonify({"error": "Invalid or missing CAPTCHA token"}), 400

    if ENABLE_RATE_LIMITING and is_rate_limited(username):
        log_attempt_json(username, algo, "rate_limited", start_time)
        return Jsonify({"error": "Too many login attempts. Try again later."}), 429

    if ENABLE_LOCKOUT and is_locked_out(username):
        log_attempt_json(username, algo, "locked", start_time)
        return Jsonify({"error": "Account is temporarily locked."}), 403

    login_attempts.setdefault(username, []).append(time.time())

    if verify_password(username, password):
        reset_lockout(username)
        if captcha_token in captcha_tokens:
            captcha_tokens.remove(captcha_token)

        if ENABLE_TOTP:
            log_attempt_json(username, algo, "totp_required", start_time)
            return Jsonify({"message": "TOTP required", "totp_required": True})

        log_attempt_json(username, algo, "success", start_time)
        return Jsonify({"message": "Login successful"})
    else:
        record_failed_attempt(username)
        log_attempt_json(username, algo, "fail", start_time)
        return Jsonify({"error": "Invalid credentials"}), 401

@app.route("/login_totp", methods=["POST"])
def login_totp():
    start_time = time.time()
    data = Request.get_json()
    username = data.get("username")
    password = data.get("password")
    otp = data.get("otp")
    captcha_token = data.get("captcha_token")
    user = users.get(username)
    algo = user["algo"] if user else "unknown"

    if ENABLE_CAPTCHA and captcha_token not in captcha_tokens:
        log_attempt_json(username, algo, "captcha_required", start_time)
        return Jsonify({"error": "Invalid or missing CAPTCHA token"}), 400

    if ENABLE_RATE_LIMITING and is_rate_limited(username):
        log_attempt_json(username, algo, "rate_limited", start_time)
        return Jsonify({"error": "Too many login attempts. Try again later."}), 429

    if ENABLE_LOCKOUT and is_locked_out(username):
        log_attempt_json(username, algo, "locked", start_time)
        return Jsonify({"error": "Account is temporarily locked."}), 403

    login_attempts.setdefault(username, []).append(time.time())

    if not user:
        log_attempt_json(username, algo, "fail", start_time)
        return Jsonify({"error": "User not found"}), 404

    if not verify_password(username, password):
        record_failed_attempt(username)
        log_attempt_json(username, algo, "fail", start_time)
        return Jsonify({"error": "Invalid credentials"}), 401

    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(otp):
        record_failed_attempt(username)
        log_attempt_json(username, algo, "fail", start_time)
        return Jsonify({"error": "Invalid TOTP"}), 401

    reset_lockout(username)
    if captcha_token in captcha_tokens:
        captcha_tokens.remove(captcha_token)

    log_attempt_json(username, algo, "success", start_time)
    return Jsonify({"message": "TOTP login successful"})

@app.route("/admin/get_captcha_token", methods=["GET"])
def get_captcha_token():
    captcha_token = secrets.token_urlsafe(16)
    captcha_tokens.add(captcha_token)
    return Jsonify({"captcha_token": captcha_token})

if __name__ == "__main__":
    app.run(debug=False)
