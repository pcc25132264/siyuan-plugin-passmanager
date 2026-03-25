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
        constructor(plugin) {
            this.plugin = plugin;
            this.timer = null;
            this.resetTimer = this.resetTimer.bind(this);
            this.handleBlur = this.handleBlur.bind(this);
        }

        start() {
            this.stop(); // Remove any existing listeners and timer
            
            const config = this.plugin.pluginConfig || {};
            const neverLock = config.neverLock !== false; // default true
            
            if (neverLock) return; // Do not start lock mechanisms
            
            this.timeout = (config.autoLockTimeout || 5) * 60 * 1000;
            this.lockOnBlur = config.lockOnBlur || false;

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

    class CryptoBlockManager {
        constructor(plugin) {
            this.plugin = plugin;
            this.processedBlocks = new WeakSet();
            
            this.plugin.eventBus.on("loaded-protyle-static", this.handleProtyleLoad.bind(this));
            this.plugin.eventBus.on("loaded-protyle-dynamic", this.handleProtyleLoad.bind(this));
            this.plugin.eventBus.on("ws-main", this.handleWsMain.bind(this));
        }
        
        handleProtyleLoad({ detail }) {
            const blocks = detail.protyle.element.querySelectorAll('[data-type="NodeCodeBlock"]');
            blocks.forEach(b => this.processBlock(b));
        }
        
        handleWsMain({ detail }) {
            if (detail.cmd === "transactions") {
                requestAnimationFrame(() => {
                    const blocks = document.querySelectorAll('[data-type="NodeCodeBlock"]:not([data-crypto-processed])');
                    blocks.forEach(b => {
                        const lang = b.querySelector('.protyle-action__language');
                        if (lang && lang.textContent.trim().toLowerCase() === 'crypto') {
                            this.processBlock(b);
                        }
                    });
                });
            }
        }
        
        async processBlock(blockElement) {
            const langDiv = blockElement.querySelector('.protyle-action__language');
            if (!langDiv || langDiv.textContent.trim().toLowerCase() !== 'crypto') return;
            
            if (this.processedBlocks.has(blockElement)) return;
            this.processedBlocks.add(blockElement);
            blockElement.dataset.cryptoProcessed = "true";
            
            this.renderBlock(blockElement);
        }
        
        async renderBlock(blockElement) {
            const actionDiv = blockElement.querySelector('.protyle-action');
            const contentDiv = blockElement.querySelector('.protyle-content') || blockElement.querySelector('[contenteditable="true"]');
            if (!actionDiv && !contentDiv) return;
            
            // Remove existing overlay if any
            let overlay = blockElement.querySelector('.pm-crypto-overlay');
            if (overlay) overlay.remove();
            
            overlay = document.createElement('div');
            overlay.className = 'pm-crypto-overlay';
            overlay.contentEditable = "false";
            overlay.style.padding = '12px 16px';
            overlay.style.margin = '4px 0';
            overlay.style.border = '1px solid var(--b3-theme-primary-lighter)';
            overlay.style.borderRadius = '6px';
            overlay.style.backgroundColor = 'var(--b3-theme-primary-lightest)';
            overlay.style.color = 'var(--b3-theme-on-background)';
            overlay.style.cursor = 'pointer';
            overlay.style.transition = 'all 0.2s ease';
            overlay.style.boxShadow = '0 1px 3px rgba(0,0,0,0.02)';
            
            overlay.addEventListener('mouseenter', () => {
                overlay.style.borderColor = 'var(--b3-theme-primary)';
                overlay.style.boxShadow = '0 2px 6px rgba(0,0,0,0.05)';
            });
            overlay.addEventListener('mouseleave', () => {
                overlay.style.borderColor = 'var(--b3-theme-primary-lighter)';
                overlay.style.boxShadow = '0 1px 3px rgba(0,0,0,0.02)';
            });
            
            if (this.plugin.locked) {
                overlay.innerHTML = `<div style="display: flex; align-items: center; gap: 8px; justify-content: center; color: var(--b3-theme-on-surface-light); padding: 8px 0;">
                    <svg style="width: 18px; height: 18px;"><use xlink:href="#iconLock"></use></svg>
                    <span>${this.plugin.i18n.vaultLockedPlaceholder || '🔒 密码库已锁定。点击解锁以查看内容。'}</span>
                </div>`;
                overlay.addEventListener('click', () => {
                    this.plugin.openVault();
                });
            } else {
                try {
                    let textDiv = blockElement.querySelector('[contenteditable="true"]');
                    let rawText = textDiv ? textDiv.textContent : '';
                    rawText = rawText.replace(/\u200B/g, '').trim();
                    
                    if (!rawText) {
                        overlay.innerHTML = `<div style="color: var(--b3-theme-on-surface-light); display: flex; align-items: center; gap: 6px;">
                            <svg style="width: 14px; height: 14px;"><use xlink:href="#iconLock"></use></svg>
                            ${this.plugin.i18n.encryptedBlockPlaceholder || '这是一个加密块。点击编辑...'}
                        </div>`;
                    } else {
                        const parsed = JSON.parse(rawText);
                        const decrypted = await this.plugin.crypto.decrypt(parsed.data, parsed.iv);
                        const safeDiv = document.createElement('div');
                        safeDiv.style.whiteSpace = 'pre-wrap';
                        safeDiv.style.wordBreak = 'break-word';
                        safeDiv.style.lineHeight = '1.6';
                        
                        let displayText = decrypted.content || decrypted;
                        // Strip Siyuan Block IAL attributes like {: id="xxx" updated="xxx"}
                        displayText = displayText.replace(/(?:\n\s*)?\{:[^}]+\}\s*$/, '');
                        
                        safeDiv.textContent = displayText;
                        
                        const headerDiv = document.createElement('div');
                        headerDiv.style.display = 'flex';
                        headerDiv.style.alignItems = 'center';
                        headerDiv.style.gap = '6px';
                        headerDiv.style.marginBottom = '8px';
                        headerDiv.style.paddingBottom = '8px';
                        headerDiv.style.borderBottom = '1px dashed var(--b3-theme-primary-lighter)';
                        headerDiv.style.color = 'var(--b3-theme-primary)';
                        headerDiv.style.fontSize = '12px';
                        headerDiv.style.fontWeight = 'bold';
                        headerDiv.innerHTML = `<svg style="width: 14px; height: 14px;"><use xlink:href="#iconUnlock"></use></svg><span>${this.plugin.i18n.decryptedContent || '解密内容'}</span>`;
                        
                        const container = document.createElement('div');
                        container.appendChild(headerDiv);
                        container.appendChild(safeDiv);
                        
                        overlay.appendChild(container);
                    }
                } catch (e) {
                    console.error("Failed to decrypt block", e);
                    overlay.innerHTML = `<div style="color: var(--b3-theme-error); display: flex; align-items: center; gap: 6px;">
                        <svg style="width: 14px; height: 14px;"><use xlink:href="#iconInfo"></use></svg>
                        解密失败。密码不正确或数据已损坏。
                    </div>`;
                }
                
                overlay.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.openEditDialog(blockElement);
                });
            }
            
            blockElement.appendChild(overlay);
        }
        
        async openEditDialog(blockElement) {
            if (this.plugin.locked) {
                siyuan.showMessage(this.plugin.i18n.vaultLockedPlaceholder || "Vault locked", 3000, "error");
                this.plugin.openVault();
                return;
            }
            
            const textDiv = blockElement.querySelector('[contenteditable="true"]');
            let rawText = textDiv ? textDiv.textContent : '';
            rawText = rawText.replace(/\u200B/g, '').trim();
            
            let currentText = '';
            if (rawText) {
                try {
                    const parsed = JSON.parse(rawText);
                    const decrypted = await this.plugin.crypto.decrypt(parsed.data, parsed.iv);
                    currentText = decrypted.content || decrypted;
                    // Strip Siyuan Block IAL attributes for editing
                    currentText = currentText.replace(/(?:\n\s*)?\{:[^}]+\}\s*$/, '');
                } catch(e) {}
            }
            
            const dialog = new siyuan.Dialog({
                title: this.plugin.i18n.editEntry || 'Edit Encrypted Block',
                content: `
                    <div style="padding: 16px; display: flex; flex-direction: column; gap: 16px; height: 100%;">
                        <textarea class="b3-text-field" style="flex: 1; resize: none; min-height: 200px;" id="pm-crypto-textarea"></textarea>
                        <div style="display: flex; justify-content: flex-end; gap: 8px;">
                            <button class="b3-button b3-button--cancel" id="pm-crypto-cancel">${this.plugin.i18n.cancel || 'Cancel'}</button>
                            <button class="b3-button" id="pm-crypto-save">${this.plugin.i18n.save || 'Save'}</button>
                        </div>
                    </div>
                `,
                width: '600px',
                height: '400px'
            });
            
            const textarea = dialog.element.querySelector('#pm-crypto-textarea');
            textarea.value = currentText;
            
            dialog.element.querySelector('#pm-crypto-cancel').addEventListener('click', () => dialog.destroy());
            
            dialog.element.querySelector('#pm-crypto-save').addEventListener('click', async () => {
                const newText = textarea.value;
                try {
                    const encrypted = await this.plugin.crypto.encrypt({ content: newText });
                    const jsonStr = JSON.stringify(encrypted);
                    
                    const id = blockElement.getAttribute('data-node-id');
                    const markdown = "```crypto\n" + jsonStr + "\n```";
                    
                    await siyuan.fetchSyncPost('/api/block/updateBlock', {
                        dataType: "markdown",
                        data: markdown,
                        id: id
                    });
                    
                    dialog.destroy();
                } catch (e) {
                    console.error(e);
                    siyuan.showMessage("Failed to save encrypted block", 3000, "error");
                }
            });
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
            this.cryptoBlockManager = new CryptoBlockManager(this);
        }

        async onload() {
            const os = window?.siyuan?.config?.system?.os;
            this.isMobile = os === 'ios' || os === 'android' || !!document.getElementById('sidebar');

            this.protyleSlash = [{
                filter: ["encrypt block", "加密块", "jiamikuai", "crypto"],
                html: `<div class="b3-list-item__first"><svg class="b3-list-item__graphic"><use xlink:href="#iconLock"></use></svg><span class="b3-list-item__text">${this.i18n.addEncryptedBlock || '添加加密块'}</span></div>`,
                id: "insert-encrypted-block",
                callback: (protyle) => {
                    protyle.insert("```crypto\n\n```");
                }
            }];
            
            this.eventBus.on("click-blockicon", ({ detail }) => {
                const blockElements = detail.blockElements;
                if (!blockElements || blockElements.length === 0) return;
                
                const blockElement = blockElements[0];
                const type = blockElement.getAttribute("data-type");
                const isCrypto = blockElement.dataset.cryptoProcessed === "true" || 
                                 (type === "NodeCodeBlock" && blockElement.querySelector('.protyle-action__language')?.textContent === 'crypto');
                
                if (isCrypto) {
                    detail.menu.addItem({
                        icon: "iconUnlock",
                        label: this.i18n.decryptThisBlock || "Decrypt This Block",
                        click: () => this.decryptBlock(blockElement)
                    });
                } else {
                    detail.menu.addItem({
                        icon: "iconLock",
                        label: this.i18n.encryptThisBlock || "Encrypt This Block",
                        click: () => this.encryptBlock(blockElement)
                    });
                }
            });

            const topBarElement = this.addTopBar({
                icon: 'iconLock',
                title: this.i18n.pluginName,
                position: 'right',
                callback: () => {
                    this.openPreferredEntry();
                }
            });

            if (this.isMobile) {
                this.addDock({
                    config: {
                        position: "RightTop",
                        size: {
                            width: 400,
                            height: 600
                        },
                        icon: "iconLock",
                        title: this.i18n.pluginName || "PassManager",
                        show: true
                    },
                    data: {},
                    type: "mobile-entry",
                    init: (custom) => {
                        this.tabElement = custom.element;
                        this.renderTabContent();
                        this.refreshCryptoBlocks();
                    },
                    update: () => {
                        if (this.tabElement) {
                            this.renderTabContent();
                        }
                    },
                    destroy: () => {
                        this.tabElement = null;
                    }
                });
            }

            const plugin = this;
            this.addTab({
                type: 'passmanager-tab',
                init() {
                    plugin.tabElement = this.element;
                    plugin.renderTabContent();
                },
                destroy() {
                    plugin.tabElement = null;
                }
            });

            // Load config
        const pluginConfig = await this.loadData('plugin-config.json');
        
        // Initialize default configuration
        this.pluginConfig = {
            requireUnlock: true,
            savedPassword: '',
            neverLock: true,
            autoLockTimeout: 5,
            lockOnBlur: false
        };
        
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
                langText: this.i18n.pluginName || 'Password Manager',
                hotkey: '⇧⌘P',
                callback: () => {
                    this.openPreferredEntry();
                }
            });

            this.setupSettings();
            
            // Try auto-unlock if configured
            if (!this.pluginConfig.requireUnlock && this.pluginConfig.savedPassword && this.salt) {
                try {
                    await this.crypto.deriveKey(this.pluginConfig.savedPassword, this.salt);
                    await this.loadVault();
                    this.refreshCryptoBlocks();
                } catch (e) {
                    console.error("Auto-unlock failed", e);
                }
            }
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
                title: this.i18n.settingNeverLockTitle || 'Never Auto-Lock',
                description: this.i18n.settingNeverLockDesc || 'Keep the vault unlocked indefinitely.',
                createActionElement: () => {
                    const checkbox = document.createElement('input');
                    checkbox.type = 'checkbox';
                    checkbox.className = 'b3-switch fn__flex-center';
                    checkbox.checked = this.pluginConfig.neverLock !== false; // default true
                    checkbox.addEventListener('change', () => {
                        this.pluginConfig.neverLock = checkbox.checked;
                        if (this.autoLock) this.autoLock.start(); // re-eval
                    });
                    return checkbox;
                },
            });

            this.setting.addItem({
                title: this.i18n.settingAutoLockTimeoutTitle || 'Auto-Lock Timeout (mins)',
                description: this.i18n.settingAutoLockTimeoutDesc || 'Time in minutes before locking due to inactivity.',
                createActionElement: () => {
                    const input = document.createElement('input');
                    input.type = 'number';
                    input.className = 'b3-text-field fn__size200';
                    input.min = '1';
                    input.value = this.pluginConfig.autoLockTimeout || 5;
                    input.addEventListener('change', () => {
                        this.pluginConfig.autoLockTimeout = parseInt(input.value, 10) || 5;
                        if (this.autoLock) this.autoLock.start(); // re-eval
                    });
                    return input;
                },
            });

            this.setting.addItem({
                title: this.i18n.settingLockOnBlurTitle || 'Lock on Window Blur',
                description: this.i18n.settingLockOnBlurDesc || 'Lock immediately when Siyuan loses focus.',
                createActionElement: () => {
                    const checkbox = document.createElement('input');
                    checkbox.type = 'checkbox';
                    checkbox.className = 'b3-switch fn__flex-center';
                    checkbox.checked = this.pluginConfig.lockOnBlur || false;
                    checkbox.addEventListener('change', () => {
                        this.pluginConfig.lockOnBlur = checkbox.checked;
                        if (this.autoLock) this.autoLock.start(); // re-eval
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
                    const exampleText = this.i18n.decryptionExample || 'Node.js Decryption Example:';
                    
                    div.innerHTML = `
                        <div><strong>${algoText}:</strong> AES-256-GCM / PBKDF2 (100000 iterations, SHA-256)</div>
                        <div><strong>${saltText}:</strong> <span style="user-select: all; font-family: monospace;">${this.salt ? this.salt : 'Not Initialized'}</span></div>
                        <div style="margin-top: 8px; text-align: left; background: var(--b3-theme-surface-lighter); padding: 8px; border-radius: 4px; max-width: 500px; overflow-x: auto;">
                            <strong>${exampleText}</strong>
                            <pre style="margin: 4px 0 0 0; white-space: pre-wrap; font-family: monospace; font-size: 11px;">
const crypto = require('crypto');
const fs = require('fs');

const password = 'your-master-password';
const saltHex = '${this.salt || 'YOUR_SALT_HEX'}';
const salt = Buffer.from(saltHex, 'hex');

// Read vault-data.json
const vaultJson = JSON.parse(fs.readFileSync('vault-data.json', 'utf8'));
const iv = Buffer.from(vaultJson.iv, 'hex');
const encryptedData = Buffer.from(vaultJson.data, 'hex');

// PBKDF2 Key Derivation
const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

// AES-256-GCM Decryption
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
const authTag = encryptedData.subarray(encryptedData.length - 16);
const data = encryptedData.subarray(0, encryptedData.length - 16);
decipher.setAuthTag(authTag);

let decrypted = decipher.update(data, null, 'utf8');
decrypted += decipher.final('utf8');

console.log(JSON.parse(decrypted));
                            </pre>
                        </div>
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
            if (this.mainDialog) {
                this.mainDialog.destroy();
                this.mainDialog = null;
            }
            if (this.autoLock) {
                this.autoLock.stop();
            }
            this.lockVault();
        }

        openSetting() {
            if (this.isMobile) {
                this.openPreferredEntry();
                return;
            }
            super.openSetting();
        }

        openPreferredEntry() {
            this.openVault();
        }
        
        async encryptBlock(blockElement) {
            if (this.locked) {
                siyuan.showMessage(this.i18n.vaultLockedPlaceholder || "Vault locked", 3000, "error");
                this.openVault();
                return;
            }
            const id = blockElement.getAttribute("data-node-id");
            
            const res = await siyuan.fetchSyncPost('/api/block/getBlockKramdown', { id });
            if (res.code !== 0) {
                siyuan.showMessage("Failed to get block data", 3000, "error");
                return;
            }
            const kramdown = res.data.kramdown;
            
            try {
                const encrypted = await this.crypto.encrypt({ content: kramdown });
                const jsonStr = JSON.stringify(encrypted);
                const markdown = "```crypto\n" + jsonStr + "\n```";
                
                await siyuan.fetchSyncPost('/api/block/updateBlock', {
                    dataType: "markdown",
                    data: markdown,
                    id: id
                });
            } catch(e) {
                console.error(e);
                siyuan.showMessage("Encryption failed", 3000, "error");
            }
        }
        
        async decryptBlock(blockElement) {
            if (this.locked) {
                siyuan.showMessage(this.i18n.vaultLockedPlaceholder || "Vault locked", 3000, "error");
                this.openVault();
                return;
            }
            const id = blockElement.getAttribute("data-node-id");
            const textDiv = blockElement.querySelector('[contenteditable="true"]');
            let rawText = textDiv ? textDiv.textContent : '';
            rawText = rawText.replace(/\u200B/g, '').trim();
            
            try {
                const parsed = JSON.parse(rawText);
                const decrypted = await this.crypto.decrypt(parsed.data, parsed.iv);
                const kramdown = decrypted.content || decrypted;
                
                await siyuan.fetchSyncPost('/api/block/updateBlock', {
                    dataType: "markdown",
                    data: kramdown,
                    id: id
                });
            } catch(e) {
                console.error(e);
                siyuan.showMessage("Decryption failed", 3000, "error");
            }
        }

        async openVault() {
            if (this.locked) {
                if (!this.pluginConfig.requireUnlock && this.pluginConfig.savedPassword && this.salt) {
                    try {
                        await this.crypto.deriveKey(this.pluginConfig.savedPassword, this.salt);
                        await this.loadVault();
                        this.openMainTab();
                    } catch (e) {
                        siyuan.showMessage(this.i18n.unlockFailed, 3000, 'error');
                        this.openMainTab();
                    }
                } else {
                    this.openMainTab();
                }
            } else {
                this.openMainTab();
            }
        }

        openMainTab() {
            if (this.isMobile) {
                this.openMobileSidebarPanel();
                return;
            }
            const canOpenTab = typeof siyuan.openTab === "function" && this.app;
            if (!canOpenTab) {
                this.openMainDialog();
                return;
            }
            try {
                siyuan.openTab({
                    app: this.app,
                    custom: {
                        icon: "iconLock",
                        title: this.i18n.pluginName || "PassManager",
                        id: this.name + "passmanager-tab"
                    }
                });
                if (this.tabElement) {
                    this.renderTabContent();
                }
                this.refreshCryptoBlocks();
            } catch (error) {
                this.openMainDialog();
            }
        }

        openMobileSidebarPanel() {
            const sidebarElement = document.getElementById("sidebar");
            const pluginPanelElement = sidebarElement?.querySelector('[data-type="sidebar-plugin"]');
            if (!sidebarElement || !pluginPanelElement) {
                return;
            }
            const toolbarElement = sidebarElement.querySelector(".toolbar--border");
            const pluginTabIcon = toolbarElement?.querySelector('svg[data-type="sidebar-plugin-tab"]');
            if (toolbarElement) {
                toolbarElement.querySelectorAll(".toolbar__icon").forEach((item) => {
                    item.classList.remove("toolbar__icon--active");
                });
            }
            if (pluginTabIcon) {
                pluginTabIcon.classList.add("toolbar__icon--active");
            }
            const panelContainer = sidebarElement.lastElementChild;
            if (panelContainer) {
                Array.from(panelContainer.children).forEach((item) => {
                    if (item.getAttribute("data-type")) {
                        item.classList.add("fn__none");
                    }
                });
            }
            pluginPanelElement.classList.remove("fn__none");
            sidebarElement.style.transform = "translateX(0px)";
            this.tabElement = pluginPanelElement;
            this.renderTabContent();
            this.refreshCryptoBlocks();
        }

        openMainDialog() {
            if (this.mainDialog) {
                this.mainDialog.destroy();
            }
            this.mainDialog = new siyuan.Dialog({
                title: this.i18n.pluginName || "PassManager",
                width: this.isMobile ? "96vw" : "1240px",
                height: this.isMobile ? "92vh" : "88vh",
                content: `<div class="passmanager-dialog-host" style="height:100%;"></div>`,
                destroyCallback: () => {
                    if (this.tabElement === this.dialogTabElement) {
                        this.tabElement = null;
                    }
                    this.dialogTabElement = null;
                    this.mainDialog = null;
                }
            });
            this.dialogTabElement = this.mainDialog.element.querySelector(".passmanager-dialog-host");
            this.tabElement = this.dialogTabElement;
            this.renderTabContent();
            this.refreshCryptoBlocks();
        }

        lockVault() {
            this.crypto.lock();
            this.locked = true;
            this.vaultData = { entries: [], categories: [] };
            if (this.tabElement) {
                this.renderTabContent();
            }
            this.refreshCryptoBlocks();
        }

        refreshCryptoBlocks() {
            if (this.cryptoBlockManager) {
                const blocks = document.querySelectorAll('[data-crypto-processed="true"]');
                blocks.forEach(b => {
                    this.cryptoBlockManager.renderBlock(b);
                });
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
                    this.autoLock = new AutoLockManager(this);
                }
                this.autoLock.start();
            } catch (e) {
                console.error(e);
                throw new Error(this.i18n.unlockFailed);
            }
        }

        renderTabContent() {
            if (!this.tabElement) return;
            
            if (this.locked) {
                this.renderUnlockUI();
            } else {
                this.renderMainUI();
            }
        }

        renderUnlockUI() {
            const isSetup = !this.salt;
            this.tabElement.innerHTML = `
                <div class="passmanager-tab-container" style="display: flex; justify-content: center; align-items: center; height: 100%; width: 100%; background: var(--b3-theme-background);">
                    <div style="width: min(400px, calc(100% - 24px)); padding: 24px; border: 1px solid var(--b3-theme-surface-lighter); border-radius: 8px; background: var(--b3-theme-surface);">
                        <h3 style="margin-top: 0; text-align: center;">${isSetup ? this.i18n.setupMasterPassword : this.i18n.unlockTitle}</h3>
                        <div class="passmanager-dialog-form" style="margin-top: 16px;">
                            <input type="password" class="passmanager-input b3-text-field" id="pm-master-pwd" placeholder="${this.i18n.masterPassword}">
                            ${isSetup ? `
                                <input type="password" class="passmanager-input b3-text-field" id="pm-master-pwd-confirm" placeholder="${this.i18n.confirmPassword}">
                                <input type="password" class="passmanager-input b3-text-field" id="pm-siyuan-pwd" placeholder="${this.i18n.siyuanLoginPassword || 'Siyuan Password'}" title="${this.i18n.recoveryInputDesc}">
                                <div style="font-size: 12px; color: var(--b3-theme-on-surface-light);">${this.i18n.recoveryInputDesc || 'Optional: Used to recover master password'}</div>
                            ` : ''}
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 24px;">
                                <div>
                                    ${!isSetup ? `<a href="javascript:void(0)" id="pm-forgot-pwd" style="color: var(--b3-theme-primary); font-size: 12px;">${this.i18n.forgotPassword || 'Forgot Password?'}</a>` : ''}
                                </div>
                                <button class="passmanager-btn b3-button" id="pm-unlock-btn">${isSetup ? this.i18n.createVault : this.i18n.unlock}</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            if (!isSetup) {
                this.tabElement.querySelector('#pm-forgot-pwd').addEventListener('click', () => {
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
                                this.tabElement.querySelector('#pm-master-pwd').value = masterPwd;
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

            const btn = this.tabElement.querySelector('#pm-unlock-btn');
            btn.addEventListener('click', async () => {
                const pwd = this.tabElement.querySelector('#pm-master-pwd').value;
                if (!pwd) return;
                
                if (isSetup) {
                    const confirmPwd = this.tabElement.querySelector('#pm-master-pwd-confirm').value;
                    const siyuanPwd = this.tabElement.querySelector('#pm-siyuan-pwd').value;
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
                    this.renderTabContent();
                    this.refreshCryptoBlocks();
                } else {
                    try {
                        await this.crypto.deriveKey(pwd, this.salt);
                        await this.loadVault();
                        
                        if (!this.pluginConfig.requireUnlock) {
                            this.pluginConfig.savedPassword = pwd;
                            await this.saveData('plugin-config.json', this.pluginConfig);
                        }
                        
                        this.renderTabContent();
                        this.refreshCryptoBlocks();
                    } catch (e) {
                        siyuan.showMessage(e.message, 3000, 'error');
                    }
                }
            });
            
            // Add enter key listener for password input
            this.tabElement.querySelector('#pm-master-pwd').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    btn.click();
                }
            });
        }

        renderMainUI() {
            const categoryOptions = `<option value="">${this.i18n.allCategories || 'All Categories'}</option>` + 
                this.vaultData.categories.map(c => `<option value="${c.id}">${c.name}</option>`).join('');

            this.tabElement.innerHTML = `
                <div class="passmanager-container">
                    <div class="passmanager-header">
                        <div class="passmanager-tabs">
                            <button class="b3-button pm-tab-btn" data-tab="passwords">
                                <span class="pm-tab-icon">🔐</span>
                                <span class="pm-tab-text">${this.i18n.passwordsTab || 'Passwords'}</span>
                            </button>
                            <button class="b3-button b3-button--outline pm-tab-btn" data-tab="texts">
                                <span class="pm-tab-icon">📝</span>
                                <span class="pm-tab-text">${this.i18n.encryptedTextsTab || 'Encrypted Texts'}</span>
                            </button>
                        </div>
                        <div class="pm-header-field pm-header-field-select">
                            <span class="pm-header-icon">📁</span>
                            <select id="pm-filter-category" class="passmanager-select b3-select">
                                ${categoryOptions}
                            </select>
                        </div>
                        <div class="pm-header-field pm-header-field-search">
                            <span class="pm-header-icon">🔎</span>
                            <input type="text" class="passmanager-search b3-text-field" id="pm-search" placeholder="${this.i18n.searchPlaceholder}">
                        </div>
                        <div class="passmanager-toolbar">
                            ${this.isMobile ? '' : `<button class="passmanager-btn-secondary b3-button b3-button--outline pm-toolbar-btn pm-toolbar-tab" id="pm-export-json-btn"><span class="pm-toolbar-icon">📤</span><span class="pm-toolbar-text">${this.i18n.exportJson || 'Export JSON'}</span></button>`}
                            <button class="passmanager-btn-secondary b3-button b3-button--outline pm-toolbar-btn pm-toolbar-tab" id="pm-export-note-unencrypted-btn"><span class="pm-toolbar-icon">📄</span><span class="pm-toolbar-text">${this.i18n.exportUnencryptedNote || 'Export Unencrypted Note'}</span></button>
                            <button class="passmanager-btn-secondary b3-button b3-button--outline pm-toolbar-btn pm-toolbar-tab" id="pm-export-note-encrypted-btn"><span class="pm-toolbar-icon">🔒</span><span class="pm-toolbar-text">${this.i18n.exportEncryptedNote || 'Export Encrypted Note'}</span></button>
                            <button class="passmanager-btn-secondary b3-button b3-button--outline pm-toolbar-btn pm-toolbar-tab" id="pm-cat-btn"><span class="pm-toolbar-icon">🗂</span><span class="pm-toolbar-text">${this.i18n.manageCategories || 'Manage Categories'}</span></button>
                            <button class="passmanager-btn b3-button pm-toolbar-btn pm-toolbar-btn--primary pm-toolbar-tab" id="pm-add-btn"><span class="pm-toolbar-icon">＋</span><span class="pm-toolbar-text">${this.i18n.addEntry}</span></button>
                            <button class="passmanager-btn-secondary b3-button b3-button--cancel pm-toolbar-btn pm-toolbar-tab" id="pm-lock-btn"><span class="pm-toolbar-icon">🔐</span><span class="pm-toolbar-text">${this.i18n.lock}</span></button>
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
            `;

            // Tabs
            const tabBtns = this.tabElement.querySelectorAll('.pm-tab-btn');
            tabBtns.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const tab = e.currentTarget.getAttribute('data-tab');
                    this.currentTab = tab;
                    tabBtns.forEach(b => {
                        if (b.getAttribute('data-tab') === tab) {
                            b.classList.remove('b3-button--outline');
                        } else {
                            b.classList.add('b3-button--outline');
                        }
                    });
                    
                    if (tab === 'passwords') {
                        this.tabElement.querySelector('#pm-table-passwords').style.display = 'table';
                        this.tabElement.querySelector('#pm-table-texts').style.display = 'none';
                    } else {
                        this.tabElement.querySelector('#pm-table-passwords').style.display = 'none';
                        this.tabElement.querySelector('#pm-table-texts').style.display = 'table';
                    }
                    
                    this.renderList();
                });
            });

            // Set initial tab state
            if (this.currentTab === 'texts') {
                this.tabElement.querySelector('[data-tab="texts"]').click();
            }

            const searchInput = this.tabElement.querySelector('#pm-search');
            searchInput.addEventListener('input', () => this.renderList());

            const categoryFilter = this.tabElement.querySelector('#pm-filter-category');
            categoryFilter.addEventListener('change', () => this.renderList());

            const catBtn = this.tabElement.querySelector('#pm-cat-btn');
            catBtn.addEventListener('click', () => {
                this.showCategoryManagerDialog();
            });

            const addBtn = this.tabElement.querySelector('#pm-add-btn');
            addBtn.addEventListener('click', () => {
                if (this.currentTab === 'texts') {
                    this.showTextDialog();
                } else {
                    this.showEntryDialog();
                }
            });

            const lockBtn = this.tabElement.querySelector('#pm-lock-btn');
            lockBtn.addEventListener('click', () => {
                this.lockVault();
                siyuan.showMessage(this.i18n.vaultLocked);
            });
            
            const exportJsonBtn = this.tabElement.querySelector('#pm-export-json-btn');
            if (exportJsonBtn) {
                exportJsonBtn.addEventListener('click', () => this.exportToJson());
            }
            
            const exportNoteUnencryptedBtn = this.tabElement.querySelector('#pm-export-note-unencrypted-btn');
            exportNoteUnencryptedBtn.addEventListener('click', () => this.exportToNote(false));
            
            const exportNoteEncryptedBtn = this.tabElement.querySelector('#pm-export-note-encrypted-btn');
            exportNoteEncryptedBtn.addEventListener('click', () => this.exportToNote(true));

            this.usernameSortOrder = null;
            const sortUsernameBtn = this.tabElement.querySelector('#pm-sort-username');
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
            if (!this.tabElement) return;
            const searchInput = this.tabElement.querySelector('#pm-search');
            const categoryFilter = this.tabElement.querySelector('#pm-filter-category');
            const query = searchInput ? searchInput.value.toLowerCase() : '';
            const catId = categoryFilter ? categoryFilter.value : '';

            if (this.currentTab === 'passwords') {
                this.renderPasswordsList(query, catId);
            } else {
                this.renderTextsList(query, catId);
            }
        }

        renderPasswordsList(query, catId) {
            const listEl = this.tabElement.querySelector('#pm-list');
            const sortIcon = this.tabElement.querySelector('#pm-sort-icon');
            
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
                    <td data-label="${this.i18n.category || 'Category'}"><div class="pm-td-content"><span class="pm-category-text">${catName}</span></div></td>
                    <td data-label="${this.i18n.title || 'Title'}"><div class="pm-td-content" title="${entry.title || ''}">${entry.title || 'Untitled'}</div></td>
                    <td data-label="${this.i18n.username || 'Username'}">
                        <div class="pm-td-content pm-td-with-copy">
                            <span class="pm-text-ellipsis" title="${entry.username || ''}">${entry.username || '-'}</span>
                            ${createCopyBtn(entry.username, this.i18n.username)}
                        </div>
                    </td>
                    <td data-label="${this.i18n.password || 'Password'}">
                        <div class="pm-td-content pm-td-with-copy" style="position: relative; display: flex; align-items: center;">
                            <span class="pm-text-ellipsis pm-secret-text" data-secret="${(entry.password || '').replace(/"/g, '&quot;')}">********</span>
                            <button class="b3-button b3-button--text b3-button--small pm-toggle-secret-btn" title="${this.i18n.showPassword || 'Show'}">
                                <svg class="b3-button__icon"><use xlink:href="#iconEyeoff"></use></svg>
                            </button>
                            ${createCopyBtn(entry.password, this.i18n.password)}
                        </div>
                    </td>
                    <td data-label="URL">
                        <div class="pm-td-content pm-td-with-copy">
                            <span class="pm-text-ellipsis" title="${entry.url || ''}">${urlDisplay || '-'}</span>
                            ${createCopyBtn(entry.url, 'URL')}
                        </div>
                    </td>
                    <td data-label="${this.i18n.notes || 'Notes'}"><div class="pm-td-content pm-notes-ellipsis" title="${entry.notes || ''}">${entry.notes || '-'}</div></td>
                    <td data-label="${this.i18n.actions || 'Actions'}">
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
                
                // Add toggle secret event listeners
                tr.querySelectorAll('.pm-toggle-secret-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const span = btn.previousElementSibling;
                        const iconUse = btn.querySelector('use');
                        const isHidden = span.textContent === '********';
                        
                        if (isHidden) {
                            span.textContent = span.getAttribute('data-secret') || '';
                            iconUse.setAttribute('xlink:href', '#iconEye');
                        } else {
                            span.textContent = '********';
                            iconUse.setAttribute('xlink:href', '#iconEyeoff');
                        }
                    });
                });

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
            const listEl = this.tabElement.querySelector('#pm-texts-list');
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
                    <td data-label="${this.i18n.category || 'Category'}"><div class="pm-td-content"><span class="pm-category-text">${catName}</span></div></td>
                    <td data-label="${this.i18n.title || 'Title'}"><div class="pm-td-content" title="${entry.title || ''}">${entry.title || 'Untitled'}</div></td>
                    <td data-label="${this.i18n.encryptedTextContent || 'Encrypted Text Content'}">
                        <div class="pm-td-content pm-td-with-copy" style="position: relative; display: flex; align-items: center;">
                            <span class="pm-text-ellipsis pm-secret-text" data-secret="${(entry.encryptedTextContent || entry.text || '').replace(/"/g, '&quot;')}">********</span>
                            <button class="b3-button b3-button--text b3-button--small pm-toggle-secret-btn" title="${this.i18n.showPassword || 'Show'}">
                                <svg class="b3-button__icon"><use xlink:href="#iconEyeoff"></use></svg>
                            </button>
                            ${createCopyBtn(entry.encryptedTextContent || entry.text, this.i18n.encryptedTextContent || 'Encrypted Text Content')}
                        </div>
                    </td>
                    <td data-label="${this.i18n.notes || 'Notes'}"><div class="pm-td-content pm-notes-ellipsis" title="${entry.notes || ''}">${entry.notes || '-'}</div></td>
                    <td data-label="${this.i18n.actions || 'Actions'}">
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
                
                // Add toggle secret event listeners
                tr.querySelectorAll('.pm-toggle-secret-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const span = btn.previousElementSibling;
                        const iconUse = btn.querySelector('use');
                        const isHidden = span.textContent === '********';
                        
                        if (isHidden) {
                            span.textContent = span.getAttribute('data-secret') || '';
                            iconUse.setAttribute('xlink:href', '#iconEye');
                        } else {
                            span.textContent = '********';
                            iconUse.setAttribute('xlink:href', '#iconEyeoff');
                        }
                    });
                });

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
                    <div class="passmanager-dialog-form pm-form-shell ${this.isMobile ? 'pm-form-shell-mobile' : ''}">
                        <input type="text" class="passmanager-input b3-text-field" id="pm-entry-title" placeholder="${this.i18n.title}" value="${entry?.title || ''}">
                        <input type="text" class="passmanager-input b3-text-field" id="pm-entry-username" placeholder="${this.i18n.username}" value="${entry?.username || ''}">
                        <div class="pm-form-password-row">
                            <div class="pm-form-password-field">
                                <input type="password" class="passmanager-input b3-text-field pm-input-password" id="pm-entry-password" placeholder="${this.i18n.password}" value="${entry?.password || ''}">
                                <button class="b3-button b3-button--text pm-dialog-toggle-pwd" title="${this.i18n.showPassword || 'Show Password'}">
                                    <svg class="b3-button__icon"><use xlink:href="#iconEyeoff"></use></svg>
                                </button>
                            </div>
                            <button class="b3-button b3-button--outline" id="pm-gen-btn">${this.i18n.generatePassword}</button>
                        </div>
                        <input type="text" class="passmanager-input b3-text-field" id="pm-entry-url" placeholder="${this.i18n.url}" value="${entry?.url || ''}">
                        <select class="passmanager-input b3-select" id="pm-entry-category">
                            ${categoryOptions}
                        </select>
                        <textarea class="passmanager-input b3-text-field" id="pm-entry-notes" placeholder="${this.i18n.notes}">${entry?.notes || ''}</textarea>
                        ${isEdit ? `
                            <div class="pm-form-meta">
                                <div>${this.i18n.createdAt || 'Created'}: ${formatDate(entry.createdAt)}</div>
                                <div>${this.i18n.updatedAt || 'Updated'}: ${formatDate(entry.updatedAt)}</div>
                            </div>
                        ` : ''}
                        <div class="pm-dialog-actions ${this.isMobile ? 'pm-dialog-actions-mobile' : ''}">
                            ${isEdit ? `<button class="b3-button b3-button--error" id="pm-del-btn">${this.i18n.delete}</button>` : ''}
                            <button class="b3-button b3-button--cancel" id="pm-cancel-btn">${this.i18n.cancel}</button>
                            <button class="b3-button" id="pm-save-btn">${this.i18n.save}</button>
                        </div>
                    </div>
                `,
                width: this.isMobile ? "96vw" : "500px",
                height: this.isMobile ? "92vh" : undefined
            });

            dialog.element.querySelector('#pm-gen-btn').addEventListener('click', () => {
                const pwd = PasswordGenerator.generate();
                const pwdInput = dialog.element.querySelector('#pm-entry-password');
                pwdInput.value = pwd;
                pwdInput.type = 'text'; // show generated password temporarily
                
                const iconUse = dialog.element.querySelector('.pm-dialog-toggle-pwd use');
                if (iconUse) iconUse.setAttribute('xlink:href', '#iconEye');
            });

            const togglePwdBtn = dialog.element.querySelector('.pm-dialog-toggle-pwd');
            if (togglePwdBtn) {
                togglePwdBtn.addEventListener('click', () => {
                    const pwdInput = dialog.element.querySelector('#pm-entry-password');
                    const iconUse = togglePwdBtn.querySelector('use');
                    if (pwdInput.type === 'password') {
                        pwdInput.type = 'text';
                        iconUse.setAttribute('xlink:href', '#iconEye');
                    } else {
                        pwdInput.type = 'password';
                        iconUse.setAttribute('xlink:href', '#iconEyeoff');
                    }
                });
            }

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
                    <div class="passmanager-dialog-form pm-form-shell ${this.isMobile ? 'pm-form-shell-mobile' : ''}">
                        <input type="text" class="passmanager-input b3-text-field" id="pm-text-title" placeholder="${this.i18n.title}" value="${entry?.title || ''}">
                        <select class="passmanager-input b3-select" id="pm-text-category">
                            ${categoryOptions}
                        </select>
                        <textarea class="passmanager-input b3-text-field" id="pm-text-content" placeholder="${this.i18n.encryptedTextContent || 'Encrypted Text Content'}" style="min-height: 120px;">${entry?.encryptedTextContent || entry?.text || ''}</textarea>
                        <textarea class="passmanager-input b3-text-field" id="pm-text-notes" placeholder="${this.i18n.notes}">${entry?.notes || ''}</textarea>
                        ${isEdit ? `
                            <div class="pm-form-meta">
                                <div>${this.i18n.createdAt || 'Created'}: ${formatDate(entry.createdAt)}</div>
                                <div>${this.i18n.updatedAt || 'Updated'}: ${formatDate(entry.updatedAt)}</div>
                            </div>
                        ` : ''}
                        <div class="pm-dialog-actions ${this.isMobile ? 'pm-dialog-actions-mobile' : ''}">
                            ${isEdit ? `<button class="b3-button b3-button--error" id="pm-del-btn">${this.i18n.delete}</button>` : ''}
                            <button class="b3-button b3-button--cancel" id="pm-cancel-btn">${this.i18n.cancel}</button>
                            <button class="b3-button" id="pm-save-btn">${this.i18n.save}</button>
                        </div>
                    </div>
                `,
                width: this.isMobile ? "96vw" : "500px",
                height: this.isMobile ? "92vh" : undefined
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
                                // Refresh main tab if it's open
                                if (this.tabElement) {
                                    this.renderTabContent();
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
                
                // Refresh main tab if it's open
                if (this.tabElement) {
                    this.renderTabContent();
                }
            });
        }
    }

    return PassManagerPlugin;
}));
