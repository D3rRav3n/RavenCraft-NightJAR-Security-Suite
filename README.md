# NightJAR Security Suite ⚙️

**NightJAR** is a powerful, all-in-one desktop application designed to fortify your digital life. Built with a "measure nine times, cut once" philosophy, it offers professional-grade security in a single, portable tool.

-----

## Features

### Password Generator Tab

  * **Cryptographically Secure Generation**: Create strong passwords, passphrases, and PINs with the click of a button.
  * **Secure File Operations**: Encrypt any text into a password-protected file or securely and irreversibly delete sensitive files from your system.

### Password Manager Tab

  * **Encrypted Vault**: Store all your credentials in a single, encrypted file (`passwords.dat`) that is protected by a strong master password.
  * **Advanced Security Audit**: Scan your entire vault to detect duplicate or compromised passwords from known data breaches using a privacy-preserving protocol.
  * **Built-in TOTP/MFA**: Store your two-factor authentication secrets directly in the vault to generate one-time passwords on demand.
  * **Clipboard Security**: Passwords copied to your clipboard are automatically cleared after 30 seconds to prevent accidental exposure.

-----

## Installation

### Dependencies

Install the required Python libraries using the provided `requirements.txt` file:

```bash
pip install -r requirements.txt
```

### Standalone Executable

For a portable version, you can convert the script into a standalone executable using **PyInstaller**. This creates a single file that runs on any Windows machine without needing Python installed.

```bash
pyinstaller --noconsole --onefile "NightJar-SecuritySuite.py "
```

The executable will be located in the `dist/` folder.
