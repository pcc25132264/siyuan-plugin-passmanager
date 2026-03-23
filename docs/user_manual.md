# Siyuan Password Manager Plugin
## User Manual
Welcome to the Password Manager plugin for Siyuan Note.

### Setup
1. Enable the plugin in Settings -> Plugins.
2. Click the lock icon in the top right corner.
3. Set up your Master Password. This password encrypts all your data and CANNOT be recovered if lost.

### Features
- **AES-256 Encryption**: All data is encrypted using PBKDF2 derived keys and AES-GCM encryption. Data is safely isolated within Siyuan's data folder.
- **Auto Lock**: The vault automatically locks after 5 minutes of inactivity or when the window loses focus.
- **Password Generator**: Generate strong passwords with custom length and character sets.
- **Groups**: Organize your passwords by grouping them.
- **Search**: Quickly find passwords by title or username.

### Usage
- To add a password, unlock the vault and click "Add Entry".
- Use the quick copy buttons next to each entry to copy usernames and passwords securely without revealing them on screen.
- You can change the auto-lock settings by manually editing the configuration file.

*Note: Import/Export features will be fully integrated in the next minor update.*
