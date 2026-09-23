PASSWORD STRENGTH ANALYZER
==========================

Project:
A Python desktop application that evaluates the strength of user-entered
passwords and suggests stronger alternatives.

FEATURES
--------
1. Checks password length.
2. Checks lowercase, uppercase, digits and special characters.
3. Detects common passwords.
4. Detects obvious sequences such as "abc", "123" and "qwerty".
5. Detects repeated characters such as "aaa".
6. Gives a score from 0 to 100.
7. Classifies passwords as Very Weak, Weak, Moderate, Strong or Very Strong.
8. Estimates password entropy.
9. Generates cryptographically secure password alternatives using Python's
   secrets module.
10. Optional SQLite password-history feature to detect reuse.

HOW TO RUN
----------
Requirements:
- Python 3.10+ recommended
- No third-party packages required

Run:

    python main.py

HOW PASSWORD HISTORY WORKS
--------------------------
When a username and password are saved, the program does NOT save the plaintext
password. It stores an HMAC-SHA256 fingerprint in password_history.db.

A random local secret is created automatically in:

    .reuse_secret

The secret should remain private. The fingerprint mechanism is used only for
demonstrating password-reuse detection. In a real authentication system, use a
dedicated password hashing algorithm such as Argon2id, bcrypt or scrypt for
password storage.

FILES CREATED AT RUNTIME
------------------------
password_history.db  - SQLite database
.reuse_secret        - local secret used to fingerprint passwords

LEARNING OUTCOMES
-----------------
- Password length and character diversity
- Weak patterns and common-password risks
- Password entropy
- Secure random generation using `secrets`
- HMAC-SHA256 fingerprints
- SQLite database basics
- Password reuse detection

SAMPLE TESTS
------------
Try these examples:

1. 123456
   Expected: Very Weak

2. Password123
   Expected: Weak/Moderate depending on checks

3. T9!mQ2#xL7@pR4$z
   Expected: Strong or Very Strong

SECURITY NOTE
-------------
Never print, log, or store real users' passwords in plaintext. This project is
for educational analysis only.
