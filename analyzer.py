import hashlib
import requests
import math
import secrets  # For secure random generation
import string

class DeepHashAnalyzer:
    def __init__(self, password):
        self.password = password
        self.sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()

    def get_entropy(self):
        if not self.password: return 0
        char_counts = [self.password.count(c) / len(self.password) for c in set(self.password)]
        entropy = - sum(p * math.log2(p) for p in char_counts)
        return round(entropy * len(self.password), 2)

    def check_pwned(self):
        prefix, suffix = self.sha1_hash[:5], self.sha1_hash[5:]
        try:
            res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            return res.text.count(suffix)
        except: return "Offline"

    @staticmethod
    def generate_strong_password(length=16):
        """Unique Feature: Generates a high-entropy secure password."""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def run_report(self):
        entropy = self.get_entropy()
        leaks = self.check_pwned()
        
        print(f"\n--- ANALYSIS RESULTS ---")
        print(f"Entropy: {entropy} bits")
        print(f"Leaks found: {leaks}")

        if entropy < 50 or (isinstance(leaks, int) and leaks > 0):
            print("\n[!] SUGGESTION: This password is risky.")
            new_pw = self.generate_strong_password()
            print(f"Try this secure one instead: {new_pw}")
            # Show entropy of the new password for comparison
            new_entropy = DeepHashAnalyzer(new_pw).get_entropy()
            print(f"New Password Entropy: {new_entropy} bits (Much Safer!)")
        else:
            print("\n[+] This password looks solid!")

if __name__ == "__main__":
    user_pw = input("Enter a password to analyze: ")
    app = DeepHashAnalyzer(user_pw)
    app.run_report()
    input("\nPress Enter to exit...")