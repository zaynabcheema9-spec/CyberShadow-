import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib
import requests
import math
import secrets
import string

class CyberDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("NUST Cyber-Security Suite v1.0")
        self.root.geometry("600x700")
        
        # Style Configuration
        style = ttk.Style()
        style.configure("TNotebook", background="#2c3e50")
        style.configure("TFrame", background="#f4f7f6")

        # Create Tab Control
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=1, fill="both")

        # --- TAB 1: PASSWORD ANALYZER ---
        self.pass_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.pass_tab, text=" Password Analyzer ")
        self.setup_pass_tab()

        # --- TAB 2: WEB RECON TOOL ---
        self.recon_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.recon_tab, text=" Shadow-Map Recon ")
        self.setup_recon_tab()

    def setup_pass_tab(self):
        frame = tk.Frame(self.pass_tab, bg="#f4f7f6")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        tk.Label(frame, text="Credential Security", font=("Arial", 14, "bold"), bg="#f4f7f6").grid(row=0, column=0, pady=10)
        
        self.pass_entry = tk.Entry(frame, show="*", width=30, font=("Arial", 12))
        self.pass_entry.grid(row=1, column=0, pady=5)
        
        tk.Button(frame, text="Analyze Password", command=self.analyze_password, bg="#3498db", fg="white").grid(row=2, column=0, pady=10)
        
        self.pass_output = scrolledtext.ScrolledText(frame, width=50, height=15)
        self.pass_output.grid(row=3, column=0, pady=10)

    def setup_recon_tab(self):
        frame = tk.Frame(self.recon_tab, bg="#f4f7f6")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        tk.Label(frame, text="Web Infrastructure Recon", font=("Arial", 14, "bold"), bg="#f4f7f6").grid(row=0, column=0, pady=10)
        
        self.url_entry = tk.Entry(frame, width=30, font=("Arial", 12))
        self.url_entry.insert(0, "https://google.com")
        self.url_entry.grid(row=1, column=0, pady=5)
        
        tk.Button(frame, text="Start Web Recon", command=self.run_recon, bg="#e67e22", fg="white").grid(row=2, column=0, pady=10)
        
        self.recon_output = scrolledtext.ScrolledText(frame, width=50, height=15)
        self.recon_output.grid(row=3, column=0, pady=10)

    # --- LOGIC FUNCTIONS ---
    def analyze_password(self):
        pw = self.pass_entry.get()
        if not pw: return
        
        # Entropy & Breach Logic
        char_counts = [pw.count(c) / len(pw) for c in set(pw)]
        entropy = round(-sum(p * math.log2(p) for p in char_counts) * len(pw), 2)
        
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            leaks = res.text.count(suffix)
        except: leaks = "Error"

        self.pass_output.delete(1.0, tk.END)
        self.pass_output.insert(tk.END, f"STATUS REPORT:\n{'='*20}\n")
        self.pass_output.insert(tk.END, f"Entropy: {entropy} bits\n")
        self.pass_output.insert(tk.END, f"Known Leaks: {leaks}\n")
        
        if entropy < 50 or (isinstance(leaks, int) and leaks > 0):
            alphabet = string.ascii_letters + string.digits + string.punctuation
            new_pw = ''.join(secrets.choice(alphabet) for _ in range(16))
            self.pass_output.insert(tk.END, f"\n[!] ALERT: WEAK PASSWORD\nSuggested: {new_pw}")

    def run_recon(self):
        url = self.url_entry.get()
        if not url.startswith('http'): url = 'https://' + url
        
        self.recon_output.delete(1.0, tk.END)
        self.recon_output.insert(tk.END, f"SCANNING: {url}\n{'='*20}\n")
        
        try:
            res = requests.get(url, timeout=5)
            server = res.headers.get('Server', 'Protected/Hidden')
            self.recon_output.insert(tk.END, f"Server: {server}\n")
            
            # Header Check
            missing = []
            for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]:
                if h not in res.headers: missing.append(h)
            
            if missing:
                self.recon_output.insert(tk.END, f"\n[!] MISSING HEADERS:\n")
                for m in missing: self.recon_output.insert(tk.END, f"- {m}\n")
            else:
                self.recon_output.insert(tk.END, f"\n[+] Security Headers OK")
                
        except Exception as e:
            self.recon_output.insert(tk.END, f"Error: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberDashboard(root)
    root.mainloop()
    # Add this inside your __init__ method after self.notebook.pack()
self.status_var = tk.StringVar(value="Ready to Scan")
self.status_bar = tk.Label(root, textvariable=self.status_var, bd=1, 
                           relief=tk.SUNKEN, anchor=tk.W, bg="#bdc3c7")
self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

# Update your run_recon function to change the status
def run_recon(self):
    url = self.url_entry.get()
    self.status_var.set(f"Scanning {url}...")
    self.root.update_idletasks() # Refresh UI
    
    # ... (rest of your existing recon code)
    
    self.status_var.set("Scan Complete")