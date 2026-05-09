Password Strength Analyzer & Security Tool

A professional-grade Python application developed to evaluate password security, provide cryptographic feedback, and prevent credential reuse through local database integration.

🛡️ Key Features
* **Entropy Analysis:** Evaluates password strength based on length, character diversity (uppercase, lowercase, numbers, and special characters).
* **Cryptographic Hashing:** Implements **SHA-256 hashing** to securely store and verify password history without retaining plain-text credentials.
* **Database Integration:** Uses **SQLite3** to maintain a persistent database of previously used passwords, preventing credential reuse.
* **Smart Suggestions:** Automatically generates cryptographically secure password alternatives using the `secrets` module for weak passwords.

🚀 How to Run
1. Ensure you have Python 3.x installed.
2. Open the project folder in VS Code.
3. Run the script using the command:
   python analyzer.py