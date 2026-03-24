# Siyuan Password Manager Plugin

A professional-grade password manager plugin for Siyuan Note, featuring industry-standard encryption, secure password generation, encrypted text management, and intelligent auto-lock mechanisms to protect your sensitive information.

> **⚠️ Disclaimer**: This plugin is provided "as is" without any warranties. The developers and contributors are **not responsible** for any data loss, security breaches, or damages arising from the use of this plugin. Users are solely responsible for maintaining backups of their data and ensuring the security of their master passwords. Use at your own risk.

## What's New in v1.0.2

- Fixed encrypted code block display after reopening notes: plaintext/ciphertext overlap no longer appears.
- Improved crypto block recognition to handle language label edge cases with spaces/casing.
- Added new lock controls in settings: Never Auto-Lock, Idle Timeout, and Lock on Window Blur.
- Improved encrypted block UX with cleaner locked/unlocked overlay rendering.

## Why This Plugin?

The idea for this plugin originated from a real-world security concern: Siyuan Note's Git Sync plugin commits sensitive information in the `data` directory to GitHub, which can expose private data to security risks. To address this, I developed this password manager plugin with strong encryption to ensure that sensitive credentials and private texts are securely protected and isolated from regular note data, preventing accidental leaks through version control systems.

## Key Features

- **Advanced Security**: Utilizes AES-256-GCM encryption with PBKDF2 key derivation for maximum security.
- **Dual Management System**: Seamlessly switch between managing Passwords and Encrypted Texts using a tabbed interface.
- **Category Management**: Group-based data storage for better organization, including customizable and default categories (Work, Finance, Social, Life, etc.).
- **User-Friendly Interface**: Intuitive design with quick-copy buttons, show/hide password toggles, search functionality, and sortable columns.
- **Intelligent Auto-Lock**: Automatically locks on idle or window blur to prevent unauthorized access.
- **Random Password Generator**: Create strong, unique passwords with customizable parameters when adding entries.
- **Import & Export**: Support exporting data to JSON for backup, and exporting to regular or encrypted Markdown notes directly into your Siyuan workspace.
- **Transparent Decryption**: View your unique encryption Salt and Node.js manual decryption examples directly in the plugin settings to guarantee future access to your data.
- **Master Password Recovery**: Optional feature to use your Siyuan login password as a fallback to recover your master password.
- **Cross-Platform Compatibility**: Works seamlessly across all Siyuan Note supported platforms (Desktop and Mobile UI adaptations).

## Installation

### From Marketplace
1. Open Siyuan Note
2. Go to **Settings > Plugins > Marketplace**
3. Search for "Password Manager"
4. Click **Install** and then **Enable** the plugin

### Manual Installation
1. Download the latest release from the plugin's repository
2. Extract the files to `data/plugins/siyuan-plugin-passmanager`
3. Restart Siyuan Note
4. Go to **Settings > Plugins** and enable the plugin

## Usage

### Initial Setup
1. After enabling the plugin, click on the Lock icon in the top right toolbar (or use `Shift+Cmd+P` / `Shift+Ctrl+P`).
2. Set a master password. (You can optionally provide your Siyuan password as a recovery method).
3. Confirm your master password to initialize the secure vault.

### Adding Passwords
1. Open the vault and ensure you are on the "Passwords" tab.
2. Click the "Add Entry" button.
3. Enter the title, username, password, URL, and select a category.
4. Use the "Generate" button to quickly create a strong random password.
5. Click "Save" to securely store the password.

### Managing Encrypted Texts
1. Switch to the "Encrypted Texts" tab.
2. Click the "Add Text" button.
3. Enter a title, select a category, and paste your sensitive text content.
4. Click "Save". The text content will be encrypted securely.

### Exporting Data
1. **Export JSON**: Exports your entire vault (passwords and encrypted texts) to a local JSON file for backup.
2. **Export Unencrypted Note**: Creates a Markdown note in a "PassManager" notebook with all your entries in plain text.
3. **Export Encrypted Note**: Creates a Markdown note where passwords and encrypted text contents are replaced with their actual encrypted cipher strings.

### Settings & Auto-lock
- Access plugin settings via Siyuan's standard plugin settings menu.
- You can toggle "Always Require Unlock". If disabled, the vault will save your master password locally (less secure) to auto-unlock.
- You can change your master password from the settings menu.
- **Manual Decryption Settings**: In the plugin settings, you can view the encryption algorithm details, your unique Salt, and a Node.js script example that shows how to manually decrypt your `vault-data.json` if you ever need to access your data outside the plugin.

## Security Notes

- **Master Password**: Your master password is never stored anywhere in plain text (unless you explicitly disable "Always Require Unlock"). It is only used to derive the encryption key.
- **Encryption**: All passwords and encrypted text contents are encrypted using AES-256-GCM, a military-grade encryption standard.
- **Data Storage**: Encrypted data is safely stored in `data/storage/petal/siyuan-plugin-passmanager/vault-data.json`.
- **Privacy**: No data is sent to any external servers.
- **Backup**: Regularly backup your Siyuan Note data directory to prevent data loss.

## Troubleshooting

### Forgot Master Password
- If you forget your master password and didn't set up the Siyuan Password recovery option during setup, there is **no way** to recover your encrypted data.
- Always remember your master password or keep it in a secure place.

### Plugin Not Loading
- Ensure you're using a compatible version of Siyuan Note (v3.0.0+).
- Check the developer console for any error messages.
- Try reinstalling the plugin.

## License

This plugin is released under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue on the plugin's repository.

## Support

If you encounter any issues or have questions, please open an issue on the plugin's repository or contact the maintainers.
