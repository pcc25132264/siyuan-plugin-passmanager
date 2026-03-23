# Siyuan Password Manager Plugin

A professional-grade password manager plugin for Siyuan Note, featuring AES-256 encryption, password generation, and an auto-lock mechanism.

## Features
- **Security**: AES-256-GCM encryption with PBKDF2 key derivation.
- **Organization**: Group-based password management.
- **Convenience**: Password generator and quick-copy buttons.
- **Privacy**: Auto-lock on idle or window blur.
- **Data Isolation**: Encrypted data is safely stored in `data/storage/petal/siyuan-plugin-passmanager`.

## Installation
1. Go to Settings > Plugins > Marketplace.
2. Search for "Password Manager".
3. Install and enable the plugin.

## Development
- `CryptoManager`: Handles the Web Crypto API for encryption.
- `AutoLockManager`: Listens for idle state.
- Test cases: See `tests/test_crypto.js`.
