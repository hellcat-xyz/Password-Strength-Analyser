import hashlib
import hmac
import math
import os
import re
import secrets
import sqlite3
import string
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "password_history.db"
SECRET_PATH = APP_DIR / ".reuse_secret"

COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "abc123", "admin", "admin123",
    "letmein", "welcome", "iloveyou", "monkey", "dragon",
    "football", "login", "passw0rd", "111111", "000000"
}


def get_reuse_secret() -> bytes:
    """Create/load a local secret used only to fingerprint passwords for reuse checks."""
    if SECRET_PATH.exists():
        return SECRET_PATH.read_bytes()

    secret = secrets.token_bytes(32)
    SECRET_PATH.write_bytes(secret)
    try:
        os.chmod(SECRET_PATH, 0o600)
    except OSError:
        pass
    return secret


def password_fingerprint(password: str) -> str:
    """
    HMAC-SHA256 fingerprint for password-reuse detection.
    This is NOT intended to replace a proper password hash for authentication.
    """
    return hmac.new(get_reuse_secret(), password.encode("utf-8"), hashlib.sha256).hexdigest()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_history_user ON password_history(username)"
        )


def password_was_used(username: str, password: str) -> bool:
    if not username.strip():
        return False

    fp = password_fingerprint(password)
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM password_history
            WHERE lower(username) = lower(?) AND fingerprint = ?
            LIMIT 1
            """,
            (username.strip(), fp),
        ).fetchone()
    return row is not None


def save_password_history(username: str, password: str) -> None:
    username = username.strip()
    if not username or not password:
        return

    fp = password_fingerprint(password)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO password_history(username, fingerprint)
            VALUES (?, ?)
            """,
            (username, fp),
        )


def has_sequence(password: str) -> bool:
    p = password.lower()
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "0123456789",
        "9876543210",
        "qwertyuiop",
        "poiuytrewq",
    ]
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i + 3] in p:
                return True
    return False


def estimate_entropy(password: str) -> float:
    if not password:
        return 0.0

    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"\d", password):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset += 33

    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)


def analyze_password(password: str, username: str = "") -> dict:
    checks = {
        "At least 8 characters": len(password) >= 8,
        "At least 12 characters (recommended)": len(password) >= 12,
        "Contains lowercase letters": bool(re.search(r"[a-z]", password)),
        "Contains uppercase letters": bool(re.search(r"[A-Z]", password)),
        "Contains numbers": bool(re.search(r"\d", password)),
        "Contains special characters": bool(re.search(r"[^A-Za-z0-9]", password)),
        "Avoids obvious sequences": not has_sequence(password),
        "Avoids long repeated characters": not bool(re.search(r"(.)\1\1", password)),
        "Not a common password": password.lower() not in COMMON_PASSWORDS,
    }

    reused = password_was_used(username, password) if username.strip() and password else False

    score = 0
    score += 10 if len(password) >= 8 else 0
    score += 15 if len(password) >= 12 else 0
    score += 10 if len(password) >= 16 else 0
    score += 10 if checks["Contains lowercase letters"] else 0
    score += 10 if checks["Contains uppercase letters"] else 0
    score += 10 if checks["Contains numbers"] else 0
    score += 15 if checks["Contains special characters"] else 0
    score += 10 if checks["Avoids obvious sequences"] else 0
    score += 5 if checks["Avoids long repeated characters"] else 0
    score += 5 if checks["Not a common password"] else 0

    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 20)
    if has_sequence(password):
        score = max(0, score - 10)
    if reused:
        score = max(0, score - 25)

    score = max(0, min(100, score))

    if score < 30:
        strength = "Very Weak"
    elif score < 50:
        strength = "Weak"
    elif score < 70:
        strength = "Moderate"
    elif score < 85:
        strength = "Strong"
    else:
        strength = "Very Strong"

    feedback = []
    if len(password) < 12:
        feedback.append("Use at least 12 characters; 16+ is even better.")
    if not checks["Contains uppercase letters"]:
        feedback.append("Add at least one uppercase letter.")
    if not checks["Contains lowercase letters"]:
        feedback.append("Add at least one lowercase letter.")
    if not checks["Contains numbers"]:
        feedback.append("Add at least one number.")
    if not checks["Contains special characters"]:
        feedback.append("Add at least one special character.")
    if not checks["Avoids obvious sequences"]:
        feedback.append("Avoid sequences such as abc, 123, qwerty, or their reverse.")
    if not checks["Avoids long repeated characters"]:
        feedback.append("Avoid repeating the same character three or more times.")
    if not checks["Not a common password"]:
        feedback.append("This password is too common. Choose something unrelated and unique.")
    if reused:
        feedback.append("This password was previously used for this username. Choose a new one.")
    if not feedback and password:
        feedback.append("Good password structure. Keep it unique to this account.")

    return {
        "score": score,
        "strength": strength,
        "entropy": estimate_entropy(password),
        "checks": checks,
        "reused": reused,
        "feedback": feedback,
    }


def generate_password(length: int = 16) -> str:
    lowercase = secrets.choice(string.ascii_lowercase)
    uppercase = secrets.choice(string.ascii_uppercase)
    digit = secrets.choice(string.digits)
    symbol = secrets.choice("!@#$%^&*()-_=+")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"

    chars = [lowercase, uppercase, digit, symbol]
    chars.extend(secrets.choice(alphabet) for _ in range(max(0, length - 4)))

    # Fisher-Yates style shuffle using the secrets module.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


class PasswordAnalyzerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Password Strength Analyzer")
        root.geometry("760x700")
        root.minsize(700, 620)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        container = ttk.Frame(root, padding=18)
        container.pack(fill="both", expand=True)

        title = ttk.Label(
            container,
            text="Password Strength Analyzer",
            font=("Segoe UI", 20, "bold"),
        )
        title.pack(anchor="w")

        subtitle = ttk.Label(
            container,
            text="Evaluate password length, complexity, uniqueness and reuse.",
            font=("Segoe UI", 10),
        )
        subtitle.pack(anchor="w", pady=(2, 16))

        form = ttk.Frame(container)
        form.pack(fill="x")

        ttk.Label(form, text="Username (optional, used for password-history checks):").pack(anchor="w")
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var).pack(fill="x", pady=(4, 12))

        ttk.Label(form, text="Password:").pack(anchor="w")
        pw_row = ttk.Frame(form)
        pw_row.pack(fill="x", pady=(4, 10))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(pw_row, textvariable=self.password_var, show="•")
        self.password_entry.pack(side="left", fill="x", expand=True)

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            pw_row,
            text="Show",
            variable=self.show_var,
            command=self.toggle_password_visibility,
        ).pack(side="left", padx=(10, 0))

        button_row = ttk.Frame(container)
        button_row.pack(fill="x", pady=(4, 14))

        ttk.Button(button_row, text="Analyze Password", command=self.analyze).pack(side="left")
        ttk.Button(button_row, text="Generate Strong Password", command=self.generate).pack(
            side="left", padx=8
        )
        ttk.Button(button_row, text="Save to History", command=self.save_history).pack(side="left")

        result_box = ttk.LabelFrame(container, text="Analysis", padding=12)
        result_box.pack(fill="both", expand=True)

        self.strength_label = ttk.Label(
            result_box, text="Strength: —", font=("Segoe UI", 14, "bold")
        )
        self.strength_label.pack(anchor="w")

        self.score_label = ttk.Label(result_box, text="Score: — / 100")
        self.score_label.pack(anchor="w", pady=(4, 0))

        self.entropy_label = ttk.Label(result_box, text="Estimated entropy: — bits")
        self.entropy_label.pack(anchor="w", pady=(2, 10))

        self.progress = ttk.Progressbar(result_box, maximum=100, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 12))

        self.output = tk.Text(
            result_box,
            height=18,
            wrap="word",
            font=("Consolas", 10),
            state="disabled",
        )
        self.output.pack(fill="both", expand=True)

        self.suggestion_label = ttk.Label(
            container,
            text="Tip: use a password manager and use a different password for every account.",
            font=("Segoe UI", 9),
        )
        self.suggestion_label.pack(anchor="w", pady=(10, 0))

    def toggle_password_visibility(self):
        self.password_entry.config(show="" if self.show_var.get() else "•")

    def analyze(self):
        password = self.password_var.get()
        username = self.username_var.get()

        if not password:
            messagebox.showwarning("Missing password", "Please enter a password first.")
            return

        result = analyze_password(password, username)
        self.progress["value"] = result["score"]
        self.strength_label.config(text=f"Strength: {result['strength']}")
        self.score_label.config(text=f"Score: {result['score']} / 100")
        self.entropy_label.config(text=f"Estimated entropy: {result['entropy']:.1f} bits")

        lines = ["CHECKS"]
        for name, passed in result["checks"].items():
            lines.append(f"{'✓' if passed else '✗'} {name}")

        if username.strip():
            lines.append(
                f"{'✗' if result['reused'] else '✓'} "
                f"{'Password was reused' if result['reused'] else 'No matching old password found'}"
            )

        lines.append("\nRECOMMENDATIONS")
        for item in result["feedback"]:
            lines.append(f"• {item}")

        lines.append("\nSTRONGER ALTERNATIVES")
        for _ in range(3):
            lines.append(f"• {generate_password(16)}")

        self.output.config(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", "\n".join(lines))
        self.output.config(state="disabled")

    def generate(self):
        self.password_var.set(generate_password(16))
        self.analyze()

    def save_history(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not username:
            messagebox.showwarning(
                "Username required",
                "Enter a username before saving password history.",
            )
            return
        if not password:
            messagebox.showwarning("Missing password", "Enter a password first.")
            return

        if password_was_used(username, password):
            messagebox.showwarning(
                "Password reuse detected",
                "This password is already present in this user's history.",
            )
            return

        save_password_history(username, password)
        messagebox.showinfo(
            "Saved",
            "A secure HMAC fingerprint was saved for reuse checking. "
            "The plaintext password was not stored.",
        )
        self.analyze()


if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    PasswordAnalyzerApp(root)
    root.mainloop()
