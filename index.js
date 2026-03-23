(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined'
        ? module.exports = factory(require('siyuan'))
        : typeof define === 'function' && define.amd
            ? define(['siyuan'], factory)
            : (global = typeof globalThis !== 'undefined' ? globalThis : global || self,
               global.PassManagerPlugin = factory(global.siyuan));
}(this, function (siyuan) {
    'use strict';

    class CryptoManager {
        constructor() {
            this.key = null;
        }

        buf2hex(buffer) {
            return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
        }

        hex2buf(hexString) {
            if (!hexString) return new Uint8Array();
            return new Uint8Array(hexString.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
        }

        async deriveKey(password, saltStr) {
            const encoder = new TextEncoder();
            const passwordKey = await crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            
            let salt;
            if (saltStr) {
                if (saltStr.includes(',')) {
                    salt = new Uint8Array(saltStr.split(',').map(Number));
                } else {
                    salt = this.hex2buf(saltStr);
                }
            } else {
                salt = crypto.getRandomValues(new Uint8Array(16));
            }
            
            this.key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                passwordKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            return this.buf2hex(salt);
        }

        async encrypt(data) {
            if (!this.key) throw new Error('Not initialized');
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encoder = new TextEncoder();
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                this.key,
                encoder.encode(JSON.stringify(data))
            );
            return {
                iv: this.buf2hex(iv),
                data: this.buf2hex(encrypted)
            };
        }

        async decrypt(encryptedData, ivStr) {
            if (!this.key) throw new Error('Not initialized');
            
            let iv, data;
            if (ivStr && ivStr.includes(',')) {
                iv = new Uint8Array(ivStr.split(',').map(Number));
                data = new Uint8Array(encryptedData.split(',').map(Number));
            } else {
                iv = this.hex2buf(ivStr);
                data = this.hex2buf(encryptedData);
            }

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                this.key,
                data
            );
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(decrypted));
        }

        async encryptTextWithPassword(text, password, hexSalt) {
            const encoder = new TextEncoder();
            const passwordKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
            const salt = this.hex2buf(hexSalt);
            const tempKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
                passwordKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, tempKey, encoder.encode(text));
            return { iv: this.buf2hex(iv), data: this.buf2hex(encrypted) };
        }

        async decryptTextWithPassword(encryptedObj, password, hexSalt) {
            const encoder = new TextEncoder();
            const passwordKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
            const salt = this.hex2buf(hexSalt);
            const tempKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
                passwordKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: this.hex2buf(encryptedObj.iv) },
                tempKey,
                this.hex2buf(encryptedObj.data)
            );
            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        }
        
        lock() {
            this.key = null;
        }
        
        isLocked() {
            return this.key === null;
        }
    }

    class PasswordGenerator {
        static generate(length = 16, useNumbers = true, useSymbols = true, useUpper = true) {
            let charset = 'abcdefghijklmnopqrstuvwxyz';
            if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            if (useNumbers) charset += '0123456789';
            if (useSymbols) charset += '!@#$%^&*()_+~`|}{[]:;?><,./-=';
            
            let password = '';
            const randomValues = new Uint32Array(length);
            crypto.getRandomValues(randomValues);
            
            for (let i = 0; i < length; i++) {
                password += charset[randomValues[i] % charset.length];
            }
            return password;
        }
    }

    class AutoLockManager {
        constructor(plugin, timeoutMinutes = 5, lockOnBlur = true) {
            this.plugin = plugin;
            this.timeout = timeoutMinutes * 60 * 1000;
            this.lockOnBlur = lockOnBlur;
            this.timer = null;
            this.resetTimer = this.resetTimer.bind(this);
            this.handleBlur = this.handleBlur.bind(this);
            this.start();
        }

        start() {
            window.addEventListener('mousemove', this.resetTimer);
            window.addEventListener('keydown', this.resetTimer);
            if (this.lockOnBlur) {
                window.addEventListener('blur', this.handleBlur);
            }
            this.resetTimer();
        }

        stop() {
            window.removeEventListener('mousemove', this.resetTimer);
            window.removeEventListener('keydown', this.resetTimer);
            window.removeEventListener('blur', this.handleBlur);
            if (this.timer) clearTimeout(this.timer);
        }

        resetTimer() {
            if (this.timer) clearTimeout(this.timer);
            this.timer = setTimeout(() => {
                this.plugin.lockVault();
            }, this.timeout);
        }

        handleBlur() {
            if (this.plugin.isExporting) return;
            this.plugin.lockVault();
        }
    }

    class PassManagerPlugin extends siyuan.Plugin {
        constructor(options) {
            super(options);
            this.crypto = new CryptoManager();
            this.vaultData = { entries: [], categories: [], encryptedTexts: [] };
            this.salt = null;
            this.locked = true;
            this.autoLock = null;
            this.pluginConfig = {
                requireUnlock: true,
                savedPassword: ''
            };
            this.currentTab = 'passwords'; // 'passwords' or 'texts'
        }

        async onload() {
            // Check if it's mobile environment
            this.isMobile = window.siyuan && window.siyuan.config && window.siyuan.config.system && window.siyuan.config.system.os === 'ios' || window.siyuan.config.system.os === 'android' || document.getElementById('sidebar');

            const topBarElement = this.addTopBar({
                icon: 'iconLock',
                title: this.i18n.pluginName,
                position: 'right',
                callback: () => {
                    this.openVault();
                }
            });

            // Load config
            const pluginConfig = await this.loadData('plugin-config.json');
            if (pluginConfig) {
                this.pluginConfig = { ...this.pluginConfig, ...pluginConfig };
            }

            // Load salt and recovery data if exists
            const config = await this.loadData('vault-config.json');
            if (config && config.salt) {
                this.salt = config.salt;
            }
            if (config && config.recoveryData) {
                this.recoveryData = config.recoveryData;
            }
            
            this.addCommand({
                langKey: 'openVault',
                hotkey: '⇧⌘P',
                callback: () => {
                    this.openVault();
                }
            });

            this.setupSettings();
        }

        setupSettings() {
            this.setting = new siyuan.Setting({
                confirmCallback: async () => {
                    await this.saveData('plugin-config.json', this.pluginConfig);
                    // If user toggled 'requireUnlock' to true, we must clear the saved password
                    if (this.pluginConfig.requireUnlock) {
                        this.pluginConfig.savedPassword = '';
                        await this.saveData('plugin-config.json', this.pluginConfig);
                    }
                }
            });

            this.setting.addItem({
                title: this.i18n.settingRequireUnlockTitle || 'Always Require Unlock',
                description: this.i18n.settingRequireUnlockDesc || 'If disabled, the master password will be saved in plaintext locally.',
                createActionElement: () => {
                    const checkbox = document.createElement('input');
                    checkbox.type = 'checkbox';
                    checkbox.className = 'b3-switch fn__flex-center';
                    checkbox.checked = this.pluginConfig.requireUnlock;
                    checkbox.addEventListener('change', () => {
                        this.pluginConfig.requireUnlock = checkbox.checked;
                    });
                    return checkbox;
                },
            });

            this.setting.addItem({
                title: this.i18n.settingCryptoInfoTitle || 'Crypto Information',
                description: this.i18n.settingCryptoInfoDesc || 'Current encryption algorithm and Vault Salt value',
                createActionElement: () => {
                    const div = document.createElement('div');
                    div.style.display = 'flex';
                    div.style.flexDirection = 'column';
                    div.style.gap = '8px';
                    div.style.alignItems = 'flex-end';
                    div.style.fontSize = '12px';
                    div.style.color = 'var(--b3-theme-on-surface)';

                    const algoText = this.i18n.algoName || 'Algorithm';
                    const saltText = this.i18n.saltValue || 'Salt';
                    
                    div.innerHTML = `
                        <div><strong>${algoText}:</strong> AES-256-GCM / PBKDF2</div>
                        <div><strong>${saltText}:</strong> ${this.salt ? this.salt.substring(0, 32) + '...' : 'Not Initialized'}</div>
                    `;
                    return div;
                }
            });

            this.setting.addItem({
                title: this.i18n.changePassword || 'Change Master Password',
                description: this.i18n.changePasswordDesc || 'Re-encrypt the vault and set a new master password',
                createActionElement: () => {
                    const btn = document.createElement('button');
                    btn.className = 'b3-button b3-button--outline';
                    btn.textContent = this.i18n.changePassword || 'Change';
                    btn.addEventListener('click', () => {
                        this.showChangePasswordDialog();
                    });
                    return btn;
                }
            });
        }

        onunload() {
            if (this.autoLock) {
                this.autoLock.stop();
            }
            this.lockVault();
        }

        async openVault() {
            if (this.locked) {
                if (!this.pluginConfig.requireUnlock && this.pluginConfig.savedPassword && this.salt) {
                    try {
                        await this.crypto.deriveKey(this.pluginConfig.savedPassword, this.salt);
                        await this.loadVault();
                        this.showMainDialog();
                    } catch (e) {
                        siyuan.showMessage(this.i18n.unlockFailed, 3000, 'error');
                        this.showUnlockDialog();
                    }
                } else {
                    this.showUnlockDialog();
                }
            } else {
                this.showMainDialog();
            }
        }

        lockVault() {
            this.crypto.lock();
            this.locked = true;
            this.vaultData = { entries: [], categories: [] };
            if (this.mainDialog) {
                this.mainDialog.destroy();
                this.mainDialog = null;
            }
        }

        async saveVault() {
            if (this.locked) return;
            try {
                const encrypted = await this.crypto.encrypt(this.vaultData);
                await this.saveData('vault-data.json', encrypted);
                siyuan.showMessage(this.i18n.save + ' OK');
            } catch (e) {
                console.error(e);
                siyuan.showMessage('Save failed', 6000, 'error');
            }
        }

        showChangePasswordDialog() {
            const dialog = new siyuan.Dialog({
                title: this.i18n.changePassword || 'Change Master Password',
                content: `
                    <div class="passmanager-dialog-form" style="padding: 16px;">
                        <input type="password" class="passmanager-input b3-text-field" id="pm-old-pwd" placeholder="${this.i18n.oldPassword || 'Old Password'}">
                        <input type="password" class="passmanager-input b3-text-field" id="pm-new-pwd" placeholder="${this.i18n.newPassword || 'New Password'}">
                        <input type="password" class="passmanager-input b3-text-field" id="pm-new-pwd-confirm" placeholder="${this.i18n.confirmNewPassword || 'Confirm New Password'}">
                        <input type="password" class="passmanager-input b3-text-field" id="pm-siyuan-pwd" placeholder="${this.i18n.siyuanLoginPassword || 'Siyuan Password'}" title="${this.i18n.recoveryInputDesc}">
                        <div style="font-size: 12px; color: var(--b3-theme-on-surface-light);">${this.i18n.recoveryInputDesc || 'Optional: Used to recover master password'}</div>
                        <div style="display: flex; justify-content: flex-end; margin-top: 16px;">
                            <button class="b3-button" id="pm-change-pwd-btn">${this.i18n.save || 'Save'}</button>
                        </div>
                    </div>
                `,
                width: '400px'
            });

            dialog.element.querySelector('#pm-change-pwd-btn').addEventListener('click', async () => {
                const oldPwd = dialog.element.querySelector('#pm-old-pwd').value;
                const newPwd = dialog.element.querySelector('#pm-new-pwd').value;
                const confirmPwd = dialog.element.querySelector('#pm-new-pwd-confirm').value;
                const siyuanPwd = dialog.element.querySelector('#pm-siyuan-pwd').value;

                if (!oldPwd || !newPwd || !confirmPwd) return;

                if (newPwd !== confirmPwd) {
                    siyuan.showMessage(this.i18n.passwordMismatch, 3000, 'error');
                    return;
                }

                try {
                    // verify old password
                    const testCrypto = new CryptoManager();
                    await testCrypto.deriveKey(oldPwd, this.salt);
                    const testConfig = await this.loadData('vault-data.json');
                    if (testConfig && testConfig.data) {
                        await testCrypto.decrypt(testConfig.data, testConfig.iv);
                    }
                    
                    // it worked, now re-encrypt with new password
                    this.salt = await this.crypto.deriveKey(newPwd);
                    const configData = { salt: this.salt };
                    
                    if (siyuanPwd) {
                        try {
                            const recoveryData = await this.crypto.encryptTextWithPassword(newPwd, siyuanPwd, this.salt);
                            configData.recoveryData = recoveryData;
                            this.recoveryData = recoveryData;
                        } catch (e) {
                            console.error('Failed to create recovery data', e);
                        }
                    }

                    await this.saveData('vault-config.json', configData);
                    await this.saveVault(); // re-save vault with new key

                    if (!this.pluginConfig.requireUnlock) {
                        this.pluginConfig.savedPassword = newPwd;
                        await this.saveData('plugin-config.json', this.pluginConfig);
                    }

                    siyuan.showMessage(this.i18n.passwordChangeSuccess || 'Success');
                    dialog.destroy();
                } catch (e) {
                    siyuan.showMessage(this.i18n.passwordChangeFailed || 'Old password incorrect', 3000, 'error');
                }
            });
        }

        async loadVault() {
            try {
                const encrypted = await this.loadData('vault-data.json');
                if (encrypted && encrypted.data && encrypted.iv) {
                    this.vaultData = await this.crypto.decrypt(encrypted.data, encrypted.iv);
                } else {
                    this.vaultData = { entries: [], categories: [], encryptedTexts: [] };
                }

                // Ensure categories array exists
                if (!this.vaultData.categories) {
                    this.vaultData.categories = [];
                }

                // Add default categories if they don't exist
                const defaultCats = [
                    { id: 'default_work', name: this.i18n.defaultCatWork || 'Work' },
                    { id: 'default_finance', name: this.i18n.defaultCatFinance || 'Finance' },
                    { id: 'default_social', name: this.i18n.defaultCatSocial || 'Social' },
                    { id: 'default_life', name: this.i18n.defaultCatLife || 'Life' },
                    { id: 'default', name: this.i18n.defaultCatOther || 'Uncategorized' }
                ];

                defaultCats.forEach(defCat => {
                    if (!this.vaultData.categories.find(c => c.id === defCat.id)) {
                        this.vaultData.categories.push(defCat);
                    }
                });
                
                // Data migration for legacy 'group' field to 'categoryId'
                const groups = new Set(this.vaultData.entries.map(e => e.group).filter(Boolean));
                groups.forEach(g => {
                    // Skip if it matches one of our defaults
                    const isDefault = [
                        this.i18n.defaultCatWork, this.i18n.defaultCatFinance, 
                        this.i18n.defaultCatSocial, this.i18n.defaultCatLife, 
                        this.i18n.defaultCatOther, this.i18n.defaultGroup
                    ].includes(g);
                    
                    if (!isDefault) {
                        const existingCat = this.vaultData.categories.find(c => c.name === g);
                        if (!existingCat) {
                            this.vaultData.categories.push({ id: 'cat_' + Date.now() + '_' + Math.floor(Math.random()*1000), name: g });
                        }
                    }
                });
                
                this.vaultData.entries.forEach(e => {
                    if (e.group) {
                        const cat = this.vaultData.categories.find(c => c.name === e.group);
                        e.categoryId = cat ? cat.id : 'default';
                        delete e.group;
                    } else if (!e.categoryId) {
                        e.categoryId = 'default';
                    }
                });

                if (!this.vaultData.encryptedTexts) {
                    this.vaultData.encryptedTexts = [];
                }

                this.locked = false;
                
                if (!this.autoLock) {
                    this.autoLock = new AutoLockManager(this, 5, true);
                }
            } catch (e) {
                console.error(e);
                throw new Error(this.i18n.unlockFailed);
            }
        }

        showUnlockDialog() {
            const isSetup = !this.salt;
            const dialog = new siyuan.Dialog({
                title: isSetup ? this.i18n.setupMasterPassword : this.i18n.unlockTitle,
                content: `
                    <div class="passmanager-dialog-form" style="padding: 16px;">
                        <input type="password" class="passmanager-input b3-text-field" id="pm-master-pwd" placeholder="${this.i18n.masterPassword}">
                        ${isSetup ? `
                            <input type="password" class="passmanager-input b3-text-field" id="pm-master-pwd-confirm" placeholder="${this.i18n.confirmPassword}">
                            <input type="password" class="passmanager-input b3-text-field" id="pm-siyuan-pwd" placeholder="${this.i18n.siyuanLoginPassword || 'Siyuan Password'}" title="${this.i18n.recoveryInputDesc}">
                            <div style="font-size: 12px; color: var(--b3-theme-on-surface-light);">${this.i18n.recoveryInputDesc || 'Optional: Used to recover master password'}</div>
                        ` : ''}
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px;">
                            <div>
                                ${!isSetup ? `<a href="javascript:void(0)" id="pm-forgot-pwd" style="color: var(--b3-theme-primary); font-size: 12px;">${this.i18n.forgotPassword || 'Forgot Password?'}</a>` : ''}
                            </div>
                            <button class="passmanager-btn b3-button" id="pm-unlock-btn">${isSetup ? this.i18n.createVault : this.i18n.unlock}</button>
                        </div>
                    </div>
                `,
                width: '400px'
            });

            if (!isSetup) {
                dialog.element.querySelector('#pm-forgot-pwd').addEventListener('click', () => {
                    const promptDialog = new siyuan.Dialog({
                        title: this.i18n.siyuanLoginPassword || 'Enter Siyuan Login Password',
                        content: `
                            <div class="passmanager-dialog-form" style="padding: 16px;">
                                <input type="password" class="passmanager-input b3-text-field" id="pm-prompt-pwd" placeholder="${this.i18n.siyuanLoginPassword || 'Siyuan Password'}">
                                <div style="display: flex; justify-content: flex-end; margin-top: 16px;">
                                    <button class="b3-button" id="pm-prompt-submit">${this.i18n.confirm || 'Confirm'}</button>
                                </div>
                            </div>
                        `,
                        width: '300px'
                    });

                    promptDialog.element.querySelector('#pm-prompt-submit').addEventListener('click', async () => {
                        const siyuanPwd = promptDialog.element.querySelector('#pm-prompt-pwd').value;
                        promptDialog.destroy();

                        if (siyuanPwd && this.recoveryData) {
                            try {
                                const masterPwd = await this.crypto.decryptTextWithPassword(this.recoveryData, siyuanPwd, this.salt);
                                siyuan.showMessage(`${this.i18n.recoverySuccess || 'Recovery success! Master password:'} ${masterPwd}`, 10000);
                                dialog.element.querySelector('#pm-master-pwd').value = masterPwd;
                            } catch (e) {
                                siyuan.showMessage(this.i18n.recoveryFailed || 'Recovery failed', 3000, 'error');
                            }
                        } else {
                            if (!this.recoveryData) {
                                siyuan.showMessage(this.i18n.recoveryFailed || 'Recovery not set up', 3000, 'error');
                            }
                        }
                    });
                });
            }

            const btn = dialog.element.querySelector('#pm-unlock-btn');
            btn.addEventListener('click', async () => {
                const pwd = dialog.element.querySelector('#pm-master-pwd').value;
                if (!pwd) return;
                
                if (isSetup) {
                    const confirmPwd = dialog.element.querySelector('#pm-master-pwd-confirm').value;
                    const siyuanPwd = dialog.element.querySelector('#pm-siyuan-pwd').value;
                    if (pwd !== confirmPwd) {
                        siyuan.showMessage(this.i18n.passwordMismatch, 3000, 'error');
                        return;
                    }
                    this.salt = await this.crypto.deriveKey(pwd);
                    
                    const configData = { salt: this.salt };
                    
                    if (siyuanPwd) {
                        try {
                            const recoveryData = await this.crypto.encryptTextWithPassword(pwd, siyuanPwd, this.salt);
                            configData.recoveryData = recoveryData;
                            this.recoveryData = recoveryData;
                        } catch (e) {
                            console.error('Failed to create recovery data', e);
                        }
                    }

                    await this.saveData('vault-config.json', configData);
                    
                    if (!this.pluginConfig.requireUnlock) {
                        this.pluginConfig.savedPassword = pwd;
                        await this.saveData('plugin-config.json', this.pluginConfig);
                    }
                    
                    this.locked = false;
                    this.vaultData = { 
                        entries: [], 
                        categories: [
                            { id: 'default_work', name: this.i18n.defaultCatWork || 'Work' },
                            { id: 'default_finance', name: this.i18n.defaultCatFinance || 'Finance' },
                            { id: 'default_social', name: this.i18n.defaultCatSocial || 'Social' },
                            { id: 'default_life', name: this.i18n.defaultCatLife || 'Life' },
                            { id: 'default', name: this.i18n.defaultCatOther || 'Uncategorized' }
                        ],
                        encryptedTexts: [] 
                    };
                    await this.saveVault();
                    dialog.destroy();
                    this.showMainDialog();
                } else {
                    try {
                        await this.crypto.deriveKey(pwd, this.salt);
                        await this.loadVault();
                        
                        if (!this.pluginConfig.requireUnlock) {
                            this.pluginConfig.savedPassword = pwd;
                            await this.saveData('plugin-config.json', this.pluginConfig);
                        }
                        
                        dialog.destroy();
                        this.showMainDialog();
                    } catch (e) {
                        siyuan.showMessage(e.message, 3000, 'error');
                    }
                }
            });
        }

        showMainDialog() {
            if (this.mainDialog) {
                this.mainDialog.destroy();
            }
            
            const categoryOptions = `<option value="">${this.i18n.allCategories || 'All Categories'}</option>` + 
                this.vaultData.categories.map(c => `<option value="${c.id}">${c.name}</option>`).join('');

            this.mainDialog = new siyuan.Dialog({
                title: this.i18n.pluginName,
                content: `
                    <div class="passmanager-container">
                        <div class="passmanager-header">
                            <div class="passmanager-tabs" style="display: flex; gap: 8px; margin-right: auto;">
                                <button class="b3-button pm-tab-btn" data-tab="passwords">${this.i18n.passwordsTab || 'Passwords'}</button>
                                <button class="b3-button b3-button--outline pm-tab-btn" data-tab="texts">${this.i18n.encryptedTextsTab || 'Encrypted Texts'}</button>
                            </div>
                            <select id="pm-filter-category" class="passmanager-select b3-select">
                                ${categoryOptions}
                            </select>
                            <input type="text" class="passmanager-search b3-text-field" id="pm-search" placeholder="${this.i18n.searchPlaceholder}">
                            <div class="passmanager-toolbar">
                                <button class="passmanager-btn-secondary b3-button b3-button--outline" id="pm-export-json-btn">${this.i18n.exportJson || 'Export JSON'}</button>
                                <button class="passmanager-btn-secondary b3-button b3-button--outline" id="pm-export-note-unencrypted-btn">${this.i18n.exportUnencryptedNote || 'Export Unencrypted Note'}</button>
                                <button class="passmanager-btn-secondary b3-button b3-button--outline" id="pm-export-note-encrypted-btn">${this.i18n.exportEncryptedNote || 'Export Encrypted Note'}</button>
                                <button class="passmanager-btn-secondary b3-button b3-button--outline" id="pm-cat-btn">${this.i18n.manageCategories || 'Manage Categories'}</button>
                                <button class="passmanager-btn b3-button" id="pm-add-btn">${this.i18n.addEntry}</button>
                                <button class="passmanager-btn-secondary b3-button b3-button--cancel" id="pm-lock-btn">${this.i18n.lock}</button>
                            </div>
                        </div>
                        <div class="passmanager-list">
                            <div class="passmanager-table-wrapper">
                                <table class="passmanager-table" id="pm-table-passwords">
                                    <thead>
                                        <tr>
                                            <th>${this.i18n.category || 'Category'}</th>
                                            <th>${this.i18n.title}</th>
                                            <th id="pm-sort-username" style="cursor: pointer; user-select: none;">
                                                ${this.i18n.username} <span id="pm-sort-icon"></span>
                                            </th>
                                            <th>${this.i18n.password || 'Password'}</th>
                                            <th>URL</th>
                                            <th>${this.i18n.notes || 'Notes'}</th>
                                            <th style="width: 120px;">${this.i18n.actions || 'Actions'}</th>
                                        </tr>
                                    </thead>
                                    <tbody id="pm-list"></tbody>
                                </table>
                                <table class="passmanager-table" id="pm-table-texts" style="display: none;">
                                    <thead>
                                        <tr>
                                            <th>${this.i18n.category || 'Category'}</th>
                                            <th>${this.i18n.title}</th>
                                            <th>${this.i18n.encryptedTextContent || 'Encrypted Text Content'}</th>
                                            <th>${this.i18n.notes || 'Notes'}</th>
                                            <th style="width: 120px;">${this.i18n.actions || 'Actions'}</th>
                                        </tr>
                                    </thead>
                                    <tbody id="pm-texts-list"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `,
                width: this.isMobile ? '100vw' : '90vw',
                height: this.isMobile ? '100vh' : '90vh'
            });

            // Tabs
            const tabBtns = this.mainDialog.element.querySelectorAll('.pm-tab-btn');
            tabBtns.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const tab = e.target.getAttribute('data-tab');
                    this.currentTab = tab;
                    tabBtns.forEach(b => {
                        if (b.getAttribute('data-tab') === tab) {
                            b.classList.remove('b3-button--outline');
                        } else {
                            b.classList.add('b3-button--outline');
                        }
                    });
                    
                    if (tab === 'passwords') {
                        this.mainDialog.element.querySelector('#pm-table-passwords').style.display = 'table';
                        this.mainDialog.element.querySelector('#pm-table-texts').style.display = 'none';
                    } else {
                        this.mainDialog.element.querySelector('#pm-table-passwords').style.display = 'none';
                        this.mainDialog.element.querySelector('#pm-table-texts').style.display = 'table';
                    }
                    
                    this.renderList();
                });
            });

            // Set initial tab state
            if (this.currentTab === 'texts') {
                this.mainDialog.element.querySelector('[data-tab="texts"]').click();
            }

            const searchInput = this.mainDialog.element.querySelector('#pm-search');
            searchInput.addEventListener('input', () => this.renderList());

            const categoryFilter = this.mainDialog.element.querySelector('#pm-filter-category');
            categoryFilter.addEventListener('change', () => this.renderList());

            const catBtn = this.mainDialog.element.querySelector('#pm-cat-btn');
            catBtn.addEventListener('click', () => {
                this.showCategoryManagerDialog();
            });

            const addBtn = this.mainDialog.element.querySelector('#pm-add-btn');
            addBtn.addEventListener('click', () => {
                if (this.currentTab === 'texts') {
                    this.showTextDialog();
                } else {
                    this.showEntryDialog();
                }
            });

            const lockBtn = this.mainDialog.element.querySelector('#pm-lock-btn');
            lockBtn.addEventListener('click', () => {
                this.lockVault();
                siyuan.showMessage(this.i18n.vaultLocked);
            });
            
            const exportJsonBtn = this.mainDialog.element.querySelector('#pm-export-json-btn');
            exportJsonBtn.addEventListener('click', () => this.exportToJson());
            
            const exportNoteUnencryptedBtn = this.mainDialog.element.querySelector('#pm-export-note-unencrypted-btn');
            exportNoteUnencryptedBtn.addEventListener('click', () => this.exportToNote(false));
            
            const exportNoteEncryptedBtn = this.mainDialog.element.querySelector('#pm-export-note-encrypted-btn');
            exportNoteEncryptedBtn.addEventListener('click', () => this.exportToNote(true));

            this.usernameSortOrder = null;
            const sortUsernameBtn = this.mainDialog.element.querySelector('#pm-sort-username');
            sortUsernameBtn.addEventListener('click', () => {
                if (this.usernameSortOrder === null) {
                    this.usernameSortOrder = 'asc';
                } else if (this.usernameSortOrder === 'asc') {
                    this.usernameSortOrder = 'desc';
                } else {
                    this.usernameSortOrder = null;
                }
                this.renderList();
            });

            this.renderList();
        }

        renderList() {
            if (!this.mainDialog) return;
            const searchInput = this.mainDialog.element.querySelector('#pm-search');
            const categoryFilter = this.mainDialog.element.querySelector('#pm-filter-category');
            const query = searchInput ? searchInput.value.toLowerCase() : '';
            const catId = categoryFilter ? categoryFilter.value : '';

            if (this.currentTab === 'passwords') {
                this.renderPasswordsList(query, catId);
            } else {
                this.renderTextsList(query, catId);
            }
        }

        renderPasswordsList(query, catId) {
            const listEl = this.mainDialog.element.querySelector('#pm-list');
            const sortIcon = this.mainDialog.element.querySelector('#pm-sort-icon');
            
            if (sortIcon) {
                if (this.usernameSortOrder === 'asc') sortIcon.textContent = '↑';
                else if (this.usernameSortOrder === 'desc') sortIcon.textContent = '↓';
                else sortIcon.textContent = '';
            }

            listEl.innerHTML = '';
            
            let entries = this.vaultData.entries.filter(e => {
                const matchQuery = (e.title || '').toLowerCase().includes(query) || 
                                   (e.username || '').toLowerCase().includes(query) ||
                                   (e.url || '').toLowerCase().includes(query);
                const matchCat = catId ? e.categoryId === catId : true;
                return matchQuery && matchCat;
            });

            if (this.usernameSortOrder) {
                entries.sort((a, b) => {
                    const uA = (a.username || '').toLowerCase();
                    const uB = (b.username || '').toLowerCase();
                    if (uA < uB) return this.usernameSortOrder === 'asc' ? -1 : 1;
                    if (uA > uB) return this.usernameSortOrder === 'asc' ? 1 : -1;
                    return 0;
                });
            }

            entries.forEach((entry, index) => {
                const tr = document.createElement('tr');
                const catName = this.vaultData.categories.find(c => c.id === entry.categoryId)?.name || this.i18n.uncategorized || 'Uncategorized';
                
                const createCopyBtn = (text, title) => {
                    if (!text) return '';
                    return `<button class="b3-button b3-button--text b3-button--small pm-copy-btn" data-text="${text}" title="${this.i18n.copy || 'Copy'} ${title}">
                        <svg class="b3-button__icon"><use xlink:href="#iconCopy"></use></svg>
                    </button>`;
                };

                const urlDisplay = entry.url ? `<a href="${entry.url}" target="_blank" class="pm-url-link">${entry.url}</a>` : '';

                tr.innerHTML = `
                    <td><div class="pm-td-content"><span class="pm-category-text">${catName}</span></div></td>
                    <td><div class="pm-td-content" title="${entry.title || ''}">${entry.title || 'Untitled'}</div></td>
                    <td>
                        <div class="pm-td-content pm-td-with-copy">
                            <span class="pm-text-ellipsis" title="${entry.username || ''}">${entry.username || '-'}</span>
                            ${createCopyBtn(entry.username, this.i18n.username)}
                        </div>
                    </td>
                    <td>
                        <div class="pm-td-content pm-td-with-copy">
                            <span class="pm-text-ellipsis">********</span>
                            ${createCopyBtn(entry.password, this.i18n.password)}
                        </div>
                    </td>
                    <td>
                        <div class="pm-td-content pm-td-with-copy">
                            <span class="pm-text-ellipsis" title="${entry.url || ''}">${urlDisplay || '-'}</span>
                            ${createCopyBtn(entry.url, 'URL')}
                        </div>
                    </td>
                    <td><div class="pm-td-content pm-notes-ellipsis" title="${entry.notes || ''}">${entry.notes || '-'}</div></td>
                    <td>
                        <div class="passmanager-item-actions">
                            <button class="b3-button b3-button--text pm-edit" title="Edit" data-idx="${index}">
                                <svg class="b3-button__icon"><use xlink:href="#iconEdit"></use></svg>
                            </button>
                            <button class="b3-button b3-button--text b3-button--error pm-del" title="Delete" data-idx="${index}">
                                <svg class="b3-button__icon"><use xlink:href="#iconTrashcan"></use></svg>
                            </button>
                        </div>
                    </td>
                `;
                
                // Add copy event listeners
                tr.querySelectorAll('.pm-copy-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const text = btn.getAttribute('data-text');
                        navigator.clipboard.writeText(text).then(() => {
                            siyuan.showMessage(`${this.i18n.copySuccess || 'Copied'}`, 2000);
                        });
                    });
                });
                
                tr.querySelector('.pm-edit').addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.showEntryDialog(entry);
                });

                tr.querySelector('.pm-del').addEventListener('click', async (e) => {
                    e.stopPropagation();
                    if (confirm(this.i18n.confirmDelete)) {
                        this.vaultData.entries = this.vaultData.entries.filter(v => v.id !== entry.id);
                        await this.saveVault();
                        this.renderList();
                    }
                });

                tr.addEventListener('dblclick', () => {
                    this.showEntryDialog(entry);
                });

                listEl.appendChild(tr);
            });
        }

        renderTextsList(query, catId) {
            const listEl = this.mainDialog.element.querySelector('#pm-texts-list');
            listEl.innerHTML = '';
            
            let texts = (this.vaultData.encryptedTexts || []).filter(e => {
                const matchQuery = (e.title || '').toLowerCase().includes(query) || 
                                   (e.encryptedTextContent || e.text || '').toLowerCase().includes(query);
                const matchCat = catId ? e.categoryId === catId : true;
                return matchQuery && matchCat;
            });

            texts.forEach((entry, index) => {
                const tr = document.createElement('tr');
                const catName = this.vaultData.categories.find(c => c.id === entry.categoryId)?.name || this.i18n.uncategorized || 'Uncategorized';
                
                const createCopyBtn = (text, title) => {
                    if (!text) return '';
                    return `<button class="b3-button b3-button--text b3-button--small pm-copy-btn" data-text="${text}" title="${this.i18n.copy || 'Copy'} ${title}">
                        <svg class="b3-button__icon"><use xlink:href="#iconCopy"></use></svg>
                    </button>`;
                };

                tr.innerHTML = `
                    <td><div class="pm-td-content"><span class="pm-category-text">${catName}</span></div></td>
                    <td><div class="pm-td-content" title="${entry.title || ''}">${entry.title || 'Untitled'}</div></td>
                    <td>
                        <div class="pm-td-content pm-td-with-copy">
                            <span class="pm-text-ellipsis">********</span>
                            ${createCopyBtn(entry.encryptedTextContent || entry.text, this.i18n.encryptedTextContent || 'Encrypted Text Content')}
                        </div>
                    </td>
                    <td><div class="pm-td-content pm-notes-ellipsis" title="${entry.notes || ''}">${entry.notes || '-'}</div></td>
                    <td>
                        <div class="passmanager-item-actions">
                            <button class="b3-button b3-button--text pm-edit" title="Edit" data-idx="${index}">
                                <svg class="b3-button__icon"><use xlink:href="#iconEdit"></use></svg>
                            </button>
                            <button class="b3-button b3-button--text b3-button--error pm-del" title="Delete" data-idx="${index}">
                                <svg class="b3-button__icon"><use xlink:href="#iconTrashcan"></use></svg>
                            </button>
                        </div>
                    </td>
                `;
                
                tr.querySelectorAll('.pm-copy-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const text = btn.getAttribute('data-text');
                        navigator.clipboard.writeText(text).then(() => {
                            siyuan.showMessage(`${this.i18n.copySuccess || 'Copied'}`, 2000);
                        });
                    });
                });
                
                tr.querySelector('.pm-edit').addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.showTextDialog(entry);
                });

                tr.querySelector('.pm-del').addEventListener('click', async (e) => {
                    e.stopPropagation();
                    if (confirm(this.i18n.confirmDelete)) {
                        this.vaultData.encryptedTexts = this.vaultData.encryptedTexts.filter(v => v.id !== entry.id);
                        await this.saveVault();
                        this.renderList();
                    }
                });

                tr.addEventListener('dblclick', () => {
                    this.showTextDialog(entry);
                });

                listEl.appendChild(tr);
            });
        }

        showEntryDialog(entry = null) {
            const isEdit = !!entry;
            const categoryOptions = this.vaultData.categories.map(c => 
                `<option value="${c.id}" ${entry?.categoryId === c.id ? 'selected' : ''}>${c.name}</option>`
            ).join('');

            const formatDate = (ts) => {
                if (!ts) return '-';
                const d = new Date(ts);
                return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
            };

            const dialog = new siyuan.Dialog({
                title: isEdit ? this.i18n.editEntry : this.i18n.addEntry,
                content: `
                    <div class="passmanager-dialog-form" style="padding: 16px;">
                        <input type="text" class="passmanager-input b3-text-field" id="pm-entry-title" placeholder="${this.i18n.title}" value="${entry?.title || ''}">
                        <input type="text" class="passmanager-input b3-text-field" id="pm-entry-username" placeholder="${this.i18n.username}" value="${entry?.username || ''}">
                        
                        <div style="display: flex; gap: 8px;">
                            <input type="password" class="passmanager-input b3-text-field" id="pm-entry-password" placeholder="${this.i18n.password}" value="${entry?.password || ''}">
                            <button class="b3-button b3-button--outline" id="pm-gen-btn">${this.i18n.generatePassword}</button>
                        </div>
                        
                        <input type="text" class="passmanager-input b3-text-field" id="pm-entry-url" placeholder="${this.i18n.url}" value="${entry?.url || ''}">
                        
                        <select class="passmanager-input b3-select" id="pm-entry-category">
                            ${categoryOptions}
                        </select>
                        
                        <textarea class="passmanager-input b3-text-field" id="pm-entry-notes" placeholder="${this.i18n.notes}">${entry?.notes || ''}</textarea>
                        
                        ${isEdit ? `
                            <div style="font-size: 12px; color: var(--b3-theme-on-surface-light); margin-top: 8px;">
                                <div>${this.i18n.createdAt || 'Created'}: ${formatDate(entry.createdAt)}</div>
                                <div>${this.i18n.updatedAt || 'Updated'}: ${formatDate(entry.updatedAt)}</div>
                            </div>
                        ` : ''}

                        <div style="display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px;">
                            ${isEdit ? `<button class="b3-button b3-button--error" id="pm-del-btn">${this.i18n.delete}</button>` : ''}
                            <button class="b3-button b3-button--cancel" id="pm-cancel-btn">${this.i18n.cancel}</button>
                            <button class="b3-button" id="pm-save-btn">${this.i18n.save}</button>
                        </div>
                    </div>
                `,
                width: '500px'
            });

            dialog.element.querySelector('#pm-gen-btn').addEventListener('click', () => {
                const pwd = PasswordGenerator.generate();
                const pwdInput = dialog.element.querySelector('#pm-entry-password');
                pwdInput.value = pwd;
                pwdInput.type = 'text'; // show generated password temporarily
            });

            dialog.element.querySelector('#pm-cancel-btn').addEventListener('click', () => {
                dialog.destroy();
            });

            if (isEdit) {
                dialog.element.querySelector('#pm-del-btn').addEventListener('click', async () => {
                    if (confirm(this.i18n.confirmDelete)) {
                        this.vaultData.entries = this.vaultData.entries.filter(e => e !== entry);
                        await this.saveVault();
                        dialog.destroy();
                        this.renderList();
                    }
                });
            }

            dialog.element.querySelector('#pm-save-btn').addEventListener('click', async () => {
                const now = Date.now();
                const newEntry = {
                    id: entry?.id || now.toString(),
                    title: dialog.element.querySelector('#pm-entry-title').value,
                    username: dialog.element.querySelector('#pm-entry-username').value,
                    password: dialog.element.querySelector('#pm-entry-password').value,
                    url: dialog.element.querySelector('#pm-entry-url').value,
                    categoryId: dialog.element.querySelector('#pm-entry-category').value,
                    notes: dialog.element.querySelector('#pm-entry-notes').value,
                    createdAt: entry?.createdAt || now,
                    updatedAt: now
                };

                if (isEdit) {
                    const idx = this.vaultData.entries.indexOf(entry);
                    if (idx > -1) {
                        this.vaultData.entries[idx] = newEntry;
                    }
                } else {
                    this.vaultData.entries.push(newEntry);
                }

                await this.saveVault();
                dialog.destroy();
                this.renderList();
            });
        }

        showTextDialog(entry = null) {
            const isEdit = !!entry;
            const categoryOptions = this.vaultData.categories.map(c => 
                `<option value="${c.id}" ${entry?.categoryId === c.id ? 'selected' : ''}>${c.name}</option>`
            ).join('');

            const formatDate = (ts) => {
                if (!ts) return '-';
                const d = new Date(ts);
                return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
            };

            const dialog = new siyuan.Dialog({
                title: isEdit ? (this.i18n.editText || 'Edit Text') : (this.i18n.addText || 'Add Text'),
                content: `
                    <div class="passmanager-dialog-form" style="padding: 16px;">
                        <input type="text" class="passmanager-input b3-text-field" id="pm-text-title" placeholder="${this.i18n.title}" value="${entry?.title || ''}">
                        
                        <select class="passmanager-input b3-select" id="pm-text-category">
                            ${categoryOptions}
                        </select>
                        
                        <textarea class="passmanager-input b3-text-field" id="pm-text-content" placeholder="${this.i18n.encryptedTextContent || 'Encrypted Text Content'}" style="min-height: 120px;">${entry?.encryptedTextContent || entry?.text || ''}</textarea>
                        
                        <textarea class="passmanager-input b3-text-field" id="pm-text-notes" placeholder="${this.i18n.notes}">${entry?.notes || ''}</textarea>
                        
                        ${isEdit ? `
                            <div style="font-size: 12px; color: var(--b3-theme-on-surface-light); margin-top: 8px;">
                                <div>${this.i18n.createdAt || 'Created'}: ${formatDate(entry.createdAt)}</div>
                                <div>${this.i18n.updatedAt || 'Updated'}: ${formatDate(entry.updatedAt)}</div>
                            </div>
                        ` : ''}

                        <div style="display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px;">
                            ${isEdit ? `<button class="b3-button b3-button--error" id="pm-del-btn">${this.i18n.delete}</button>` : ''}
                            <button class="b3-button b3-button--cancel" id="pm-cancel-btn">${this.i18n.cancel}</button>
                            <button class="b3-button" id="pm-save-btn">${this.i18n.save}</button>
                        </div>
                    </div>
                `,
                width: '500px'
            });

            dialog.element.querySelector('#pm-cancel-btn').addEventListener('click', () => {
                dialog.destroy();
            });

            if (isEdit) {
                dialog.element.querySelector('#pm-del-btn').addEventListener('click', async () => {
                    if (confirm(this.i18n.confirmDelete)) {
                        this.vaultData.encryptedTexts = this.vaultData.encryptedTexts.filter(e => e !== entry);
                        await this.saveVault();
                        dialog.destroy();
                        this.renderList();
                    }
                });
            }

            dialog.element.querySelector('#pm-save-btn').addEventListener('click', async () => {
                const now = Date.now();
                const newEntry = {
                    id: entry?.id || now.toString(),
                    title: dialog.element.querySelector('#pm-text-title').value,
                    encryptedTextContent: dialog.element.querySelector('#pm-text-content').value,
                    categoryId: dialog.element.querySelector('#pm-text-category').value,
                    notes: dialog.element.querySelector('#pm-text-notes').value,
                    createdAt: entry?.createdAt || now,
                    updatedAt: now
                };

                if (!this.vaultData.encryptedTexts) {
                    this.vaultData.encryptedTexts = [];
                }

                if (isEdit) {
                    const idx = this.vaultData.encryptedTexts.indexOf(entry);
                    if (idx > -1) {
                        this.vaultData.encryptedTexts[idx] = newEntry;
                    }
                } else {
                    this.vaultData.encryptedTexts.push(newEntry);
                }

                await this.saveVault();
                dialog.destroy();
                this.renderList();
            });
        }

        exportToJson() {
            try {
                this.isExporting = true;
                const exportData = {
                    entries: this.vaultData.entries.map(e => ({...e})),
                    categories: this.vaultData.categories.map(c => ({...c})),
                    encryptedTexts: (this.vaultData.encryptedTexts || []).map(e => ({...e}))
                };
                const dataStr = JSON.stringify(exportData, null, 2);
                const blob = new Blob([dataStr], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `passmanager-export-${Date.now()}.json`;
                a.addEventListener('click', (e) => e.stopPropagation());
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                siyuan.showMessage(this.i18n.exportSuccess || 'Export successful');
                
                // We do NOT call this.renderList() here because it's not needed
                // and might cause issues if UI state is weird during file picker
                
                // Increase timeout to 30 seconds to prevent lockVault from firing
                // if the user takes a long time in the save file dialog
                if (this.exportTimer) clearTimeout(this.exportTimer);
                this.exportTimer = setTimeout(() => {
                    this.isExporting = false;
                }, 30000);
            } catch (e) {
                console.error('Export JSON failed', e);
                siyuan.showMessage('Export JSON failed', 3000, 'error');
                this.isExporting = false;
            }
        }

        async exportToNote(encrypt = false) {
            try {
                this.isExporting = true;
                let markdown = '# PassManager Export\n\n';
                
                markdown += '## Passwords\n\n';
                for (const entry of this.vaultData.entries) {
                    const catName = this.vaultData.categories.find(c => c.id === entry.categoryId)?.name || 'Uncategorized';
                    markdown += `### [${catName}] ${entry.title || 'Untitled'}\n\n`;
                    if (entry.username) markdown += `- **Username:** ${entry.username}\n`;
                    if (entry.password) {
                        let pwdDisplay = entry.password;
                        if (encrypt) {
                            const encRes = await this.crypto.encrypt(entry.password);
                            pwdDisplay = `${encRes.iv}:${encRes.data}`;
                        }
                        markdown += `- **Password:** ${pwdDisplay}\n`;
                    }
                    if (entry.url) markdown += `- **URL:** ${entry.url}\n`;
                    if (entry.notes) markdown += `- **Notes:** ${entry.notes}\n`;
                    markdown += '\n';
                }
                
                if (this.vaultData.encryptedTexts && this.vaultData.encryptedTexts.length > 0) {
                    markdown += '## Encrypted Texts\n\n';
                    for (const entry of this.vaultData.encryptedTexts) {
                        const catName = this.vaultData.categories.find(c => c.id === entry.categoryId)?.name || 'Uncategorized';
                        markdown += `### [${catName}] ${entry.title || 'Untitled'}\n\n`;
                        
                        let textDisplay = entry.encryptedTextContent || entry.text || '';
                        if (encrypt && textDisplay) {
                            const encRes = await this.crypto.encrypt(textDisplay);
                            textDisplay = `${encRes.iv}:${encRes.data}`;
                        }
                        
                        markdown += `- **${this.i18n.encryptedTextContent || 'Encrypted Text Content'}:**\n\n\`\`\`text\n${textDisplay}\n\`\`\`\n\n`;
                        if (entry.notes) markdown += `- **Notes:** ${entry.notes}\n\n`;
                    }
                }
                
                // Get or create PassManager notebook
                let notebooks = [];
                try {
                    const lsNotebooks = await siyuan.fetchSyncPost('/api/notebook/lsNotebooks', {});
                    notebooks = lsNotebooks.data.notebooks || [];
                } catch (e) {
                    console.error('Failed to list notebooks', e);
                }
                
                const nbName = this.i18n.passManagerNotebook || 'PassManager';
                let targetNb = notebooks.find(n => n.name === nbName);
                
                if (!targetNb) {
                    try {
                        const createNbRes = await siyuan.fetchSyncPost('/api/notebook/createNotebook', {
                            name: nbName
                        });
                        if (createNbRes.code === 0) {
                            targetNb = createNbRes.data.notebook;
                        } else {
                            throw new Error(createNbRes.msg);
                        }
                    } catch (e) {
                        console.error('Failed to create notebook', e);
                        throw new Error('Failed to create PassManager notebook');
                    }
                }
                
                const res = await siyuan.fetchSyncPost('/api/filetree/createDocWithMd', {
                    notebook: targetNb.id,
                    path: `/PassManager-Export-${Date.now()}`,
                    markdown: markdown
                });
                
                if (res.code === 0) {
                    siyuan.showMessage(this.i18n.exportNoteSuccess || 'Successfully exported to note');
                } else {
                    throw new Error(res.msg);
                }
                
                if (this.exportTimer) clearTimeout(this.exportTimer);
                this.exportTimer = setTimeout(() => {
                    this.isExporting = false;
                }, 5000);
            } catch (e) {
                console.error('Export to Note failed', e);
                siyuan.showMessage(this.i18n.exportNoteFailed || 'Failed to export to note', 3000, 'error');
                this.isExporting = false;
            }
        }

        showCategoryManagerDialog() {
            const dialog = new siyuan.Dialog({
                title: this.i18n.manageCategories || 'Manage Categories',
                content: `
                    <div class="passmanager-dialog-form" style="padding: 16px;">
                        <div style="display: flex; gap: 8px;">
                            <input type="text" class="passmanager-input b3-text-field" id="pm-cat-input" placeholder="${this.i18n.categoryName || 'Category Name'}">
                            <button class="b3-button" id="pm-cat-add-btn">${this.i18n.addCategory || 'Add Category'}</button>
                        </div>
                        <div class="pm-cat-list" id="pm-cat-list"></div>
                    </div>
                `,
                width: '400px'
            });

            const renderCatList = () => {
                const listEl = dialog.element.querySelector('#pm-cat-list');
                listEl.innerHTML = '';
                this.vaultData.categories.forEach(cat => {
                    const item = document.createElement('div');
                    item.className = 'pm-cat-item';
                    
                    const isDefault = cat.id === 'default';
                    
                    item.innerHTML = `
                        <span>${cat.name}</span>
                        ${!isDefault ? `<button class="b3-button b3-button--text b3-button--error pm-cat-del-btn" data-id="${cat.id}">🗑️</button>` : ''}
                    `;
                    
                    if (!isDefault) {
                        item.querySelector('.pm-cat-del-btn').addEventListener('click', async () => {
                            // Check if category is in use
                            const inUse = this.vaultData.entries.some(e => e.categoryId === cat.id);
                            if (inUse) {
                                siyuan.showMessage(this.i18n.categoryInUse || 'Category is in use!', 3000, 'error');
                                return;
                            }
                            if (confirm(this.i18n.categoryDeleteConfirm || 'Delete this category?')) {
                                this.vaultData.categories = this.vaultData.categories.filter(c => c.id !== cat.id);
                                await this.saveVault();
                                renderCatList();
                                // Refresh main dialog if it's open
                                if (this.mainDialog) {
                                    this.showMainDialog();
                                }
                            }
                        });
                    }
                    
                    listEl.appendChild(item);
                });
            };

            renderCatList();

            dialog.element.querySelector('#pm-cat-add-btn').addEventListener('click', async () => {
                const input = dialog.element.querySelector('#pm-cat-input');
                const name = input.value.trim();
                if (!name) return;

                this.vaultData.categories.push({
                    id: 'cat_' + Date.now(),
                    name: name
                });

                await this.saveVault();
                input.value = '';
                renderCatList();
                
                // Refresh main dialog if it's open
                if (this.mainDialog) {
                    this.showMainDialog();
                }
            });
        }
    }

    return PassManagerPlugin;
}));