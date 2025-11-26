import pyotp

if __name__ == "__main__":
    print(pyotp.TOTP("LPZ2SZ6TAWIHEHHBHHTM7BJ6Y5XFG7TY").now())
