# Password-Based-Authentication-Python

Authors:
Omer Reshef, ID number - 314651266
Lior Zemah, ID number - 207381435

GROUP_SEED xor value - 513626425

### Project Files

* `src/tests.py`: **The main script** - automatic execution of all tests.
* `src/attack_generator.py`: The client logic used to execute Brute-Force and Password-Spraying attacks.
* `src/web_server.py`: The secure Flask REST API server.
* `src/setup_users.py`: Helper script to register the 30 test accounts before each test run.
* `users.json`: Defines the `GROUP_SEED` and test passwords.

### Dependencies

```bash
pip install flask requests bcrypt argon2-cffi pyotp tabulate
```

### How to use

Go to the main direction and just execute `python3 src/tests.py`.
Then you can take a look at the results in the `logs` directory.
In `logs/attempts.log` you can see all the login attempts to the web server.
In `logs/attack_summary_results.json` you can see the result of each attack attempts.

### Pay attention
This code is only for a research and not used against real servers / users!