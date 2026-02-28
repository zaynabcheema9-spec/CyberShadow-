import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib
import requests
import math
import secrets
import string

class CyberAnalyzerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NUST Cyber-Security Suite v1.0")
        self.root.geometry("500x600")
        self.root.configure(bg="#2c3e50")  # Dark professional blue

        # Title
        tk.Label(root, text="DEEP-HASH ANALYZER", font=("Helvetica", 18, "bold"), 
                 bg="#2c3e50", fg="#ecf0f1").pack(pady=20)

        # Input Area
        tk.Label(root, text="Enter Password to Analyze:", font=("Helvetica", 10), 
                 bg="#2c3e50", fg="#bdc3c7").pack()
        self.password_entry = tk.Entry(root, show="*", width=30, font=("Helvetica", 12))
        self.password_entry.pack(pady=10)

        # Buttons
        self.analyze_btn = tk.Button(root, text="Analyze Security", command=self.process, 
                                     bg="#27ae60", fg="white", font=("Helvetica", 10, "bold"), width=20)
        self.analyze_btn.pack(pady=10)

        # Results Area
        self.result_box = scrolledtext.ScrolledText(root, width=50, height=15, font=("Consolas", 10))
        self.result_box.pack(pady=20)

    def get_entropy(self, pw):
        if not pw: return 0
        char_counts = [pw.count(c) / len(pw) for c in set(pw)]
        entropy = - sum(p * math.log2(p) for p in char_counts)
        return round(entropy * len(pw), 2)

    def check_breach(self, pw):
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            return res.text.count(suffix)
        except: return "Offline"

    def process(self):
        pw = self.password_entry.get()
        if not pw:
            messagebox.showwarning("Input Error", "Please enter a password!")
            return

        entropy = self.get_entropy(pw)
        leaks = self.check_breach(pw)
        
        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, f"--- ANALYSIS REPORT ---\n")
        self.result_box.insert(tk.END, f"Entropy Score: {entropy} bits\n")
        
        if leaks == "Offline":
            self.result_box.insert(tk.END, "Breach Check: API Offline\n")
        else:
            status = "❌ BREACHED" if leaks > 0 else "✅ SECURE"
            self.result_box.insert(tk.END, f"Breach Status: {status} ({leaks} times)\n")

        if entropy < 50 or (isinstance(leaks, int) and leaks > 0):
            alphabet = string.ascii_letters + string.digits + string.punctuation
            new_pw = ''.join(secrets.choice(alphabet) for _ in range(16))
            self.result_box.insert(tk.END, f"\n[!] RECOMMENDATION: WEAK\n")
            self.result_box.insert(tk.END, f"Suggested: {new_pw}\n")
        else:
            self.result_box.insert(tk.END, f"\n[+] RECOMMENDATION: STRONG\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberAnalyzerUI(root)
    root.mainloop()