# Siyuan Password Manager Plugin

A professional-grade password manager plugin for Siyuan Note, featuring industry-standard encryption, secure password generation, and intelligent auto-lock mechanisms to protect your sensitive information.

> **⚠️ Disclaimer**: This plugin is provided "as is" without any warranties. The developers and contributors are **not responsible** for any data loss, security breaches, or damages arising from the use of this plugin. Users are solely responsible for maintaining backups of their data and ensuring the security of their master passwords. Use at your own risk.

## Key Features

- **Advanced Security**: Utilizes AES-256-GCM encryption with PBKDF2 key derivation for maximum security
- **Organized Management**: Group-based password storage for better organization and quick access
- **User-Friendly Interface**: Intuitive design with quick-copy buttons and search functionality
- **Intelligent Auto-Lock**: Automatically locks on idle or window blur to prevent unauthorized access
- **Secure Data Storage**: Encrypted data is safely stored in `data/storage/petal/siyuan-plugin-passmanager`
- **Random Password Generator**: Create strong, unique passwords with customizable parameters
- **Cross-Platform Compatibility**: Works seamlessly across all Siyuan Note supported platforms

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
1. After enabling the plugin, click on the password manager icon in the sidebar
2. Set a master password (remember this, as it cannot be recovered)
3. Confirm your master password

### Adding Passwords
1. Click the "Add" button
2. Enter the website/app name, username, password
3. Optionally add notes and assign to a group
4. Click "Save" to securely store the password

### Generating Passwords
1. Click the "Generate" button
2. Adjust the password length and character types
3. Click "Copy" to copy the generated password to clipboard

### Auto-Lock Settings
- The plugin automatically locks after 5 minutes of inactivity
- It also locks when the Siyuan Note window loses focus
- You can adjust the auto-lock timeout in the plugin settings

## Development

### Project Structure
- `src/crypto.js`: Handles the Web Crypto API for encryption/decryption
- `src/autolock.js`: Manages idle state detection and auto-lock functionality
- `src/storage.js`: Handles secure data storage and retrieval
- `src/ui.js`: Implements the user interface components
- `tests/test_crypto.js`: Test cases for crypto functionality

### Building the Plugin
1. Clone the repository
2. Run `npm install` to install dependencies
3. Run `npm run build` to build the plugin
4. The built files will be in the `dist` directory

## Security Notes

- **Master Password**: Your master password is never stored anywhere - it's only used to derive the encryption key
- **Encryption**: All passwords are encrypted using AES-256-GCM, a military-grade encryption standard
- **Data Storage**: Encrypted data is stored locally in your Siyuan Note data directory
- **Privacy**: No data is sent to any external servers
- **Backup**: Regularly backup your Siyuan Note data directory to prevent data loss

## Troubleshooting

### Forgot Master Password
- If you forget your master password, there is no way to recover your encrypted data
- Always remember your master password or keep it in a secure place

### Plugin Not Loading
- Ensure you're using the latest version of Siyuan Note
- Check the browser console for any error messages
- Try reinstalling the plugin

## License

This plugin is released under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue on the plugin's repository.

## Support

If you encounter any issues or have questions, please open an issue on the plugin's repository or contact the maintainers.
