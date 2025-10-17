/**
 * WebAuthn Biometric Authentication Manager
 * Implements WebAuthn API for secure biometric authentication using Passkeys
 */

import EncryptionManager from './encryption.js';

class WebAuthnManager {
    constructor() {
        this.isSupported = this.checkSupport();
        this.credentials = new Map();
        this.authCount = 0;
        this.currentUserId = null;
        this.currentCredentialId = null;
        this.encryptionManager = new EncryptionManager();
        this.signingKeyPair = null;
    }

    /**
     * Check if WebAuthn is supported by the browser
     */
    checkSupport() {
        return !!(navigator.credentials && window.PublicKeyCredential);
    }

    /**
     * Check if platform authenticators are available
     */
    async checkPlatformAuthenticator() {
        try {
            console.log('Checking platform authenticator availability...');
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            console.log('Platform authenticator available:', available);
            
            if (!available) {
                console.warn('Platform authenticator not available, will try fallback approach');
                return false; // Don't throw error, just return false
            }
            return true;
        } catch (error) {
            console.error('Platform authenticator check failed:', error);
            console.warn('Platform authenticator check failed, will try fallback approach');
            return false; // Don't throw error, just return false
        }
    }

    /**
     * Check Android-specific requirements
     */
    checkAndroidRequirements() {
        const userAgent = navigator.userAgent.toLowerCase();
        const isAndroid = userAgent.includes('android');
        const isChrome = userAgent.includes('chrome');
        const isFirefox = userAgent.includes('firefox');
        const isSecureContext = window.isSecureContext;
        
        console.log('Browser detection:', { isAndroid, isChrome, isFirefox, isSecureContext });
        
        if (isAndroid && isChrome) {
            console.log('Android Chrome detected - applying Chrome-specific workarounds');
            
            if (!isSecureContext) {
                throw new Error('HTTPS is required for biometric authentication on Android Chrome');
            }
            
            // Check if we're in a secure context
            if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
                throw new Error('Biometric authentication requires HTTPS on Android Chrome');
            }
        } else if (isAndroid && isFirefox) {
            console.log('Android Firefox detected - should work normally');
        }
        
        return true;
    }

    /**
     * Generate a random challenge for WebAuthn
     */
    generateChallenge() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return array;
    }

    /**
     * Convert ArrayBuffer to Base64URL
     */
    arrayBufferToBase64URL(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * Convert Base64URL to ArrayBuffer
     */
    base64URLToArrayBuffer(base64URL) {
        const base64 = base64URL
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Register a new biometric credential (Passkey)
     */
    async register(userId = null) {
        if (!this.isSupported) {
            throw new Error('WebAuthn is not supported in this browser');
        }

        // Check Android-specific requirements
        this.checkAndroidRequirements();

        // Check if platform authenticator is available
        const platformAvailable = await this.checkPlatformAuthenticator();
        
        // Generate a unique user ID if not provided
        if (!userId) {
            userId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        }

        // For Android Chrome, always try fallback approach first due to Chrome bugs
        const userAgent = navigator.userAgent.toLowerCase();
        const isAndroidChrome = userAgent.includes('android') && userAgent.includes('chrome');
        
        if (isAndroidChrome || !platformAvailable) {
            console.log('Android Chrome detected or platform authenticator not available, trying fallback approach first...');
            try {
                return await this.registerFallback(userId);
            } catch (fallbackError) {
                console.error('Fallback registration failed:', fallbackError);
                // Continue to try platform authenticator approach
            }
        }

        try {
            // Generate challenge
            const challenge = this.generateChallenge();
            
            // Create credential creation options
            const createOptions = {
                publicKey: {
                    challenge: challenge,
                    rp: {
                        name: "Altis",
                        id: window.location.hostname || "localhost",
                    },
                    user: {
                        id: new TextEncoder().encode(userId),
                        name: userId,
                        displayName: "Altis User",
                    },
                    pubKeyCredParams: [
                        { type: "public-key", alg: -7 }, // ES256
                        { type: "public-key", alg: -257 }, // RS256
                    ],
                    authenticatorSelection: {
                        authenticatorAttachment: "platform", // Force platform authenticator (built-in)
                        userVerification: "required", // Require biometric verification
                        residentKey: "required" // Store credential on device
                    },
                    timeout: 60000, // 60 seconds
                    attestation: "none" // Don't require attestation for simplicity
                }
            };

            // Debug: Log the create options
            console.log('Creating credential with options:', createOptions);
            
            // Create the credential
            const credential = await navigator.credentials.create(createOptions);
            
            console.log('Credential created successfully:', credential);
            
            // Store credential data
            const credentialData = {
                id: credential.id,
                rawId: this.arrayBufferToBase64URL(credential.rawId),
                publicKey: this.arrayBufferToBase64URL(credential.response.publicKey),
                userId: userId,
                createdAt: new Date().toISOString()
            };

            // Store in memory (in a real app, this would be sent to server)
            this.credentials.set(credential.id, credentialData);
            this.currentUserId = userId;
            this.currentCredentialId = credential.id;

            // Store in localStorage for persistence
            localStorage.setItem('altis_credentials', JSON.stringify(Array.from(this.credentials.entries())));
            localStorage.setItem('altis_user_id', userId);
            localStorage.setItem('altis_credential_id', credential.id);

            // Create and store encrypted signing key pair
            try {
                console.log('Creating encrypted signing key pair...');
                const signingKeyPair = await this.encryptionManager.generateSigningKeyPair();
                const encryptionKey = await this.encryptionManager.deriveEncryptionKey({
                    credentialId: credential.id,
                    response: credential.response
                });
                await this.encryptionManager.storeEncryptedKeys(signingKeyPair.privateKey, signingKeyPair.publicKey, encryptionKey);
                this.signingKeyPair = signingKeyPair;
                console.log('Encrypted signing key pair created and stored successfully');
            } catch (error) {
                console.error('Failed to create encrypted signing key pair:', error);
                // Continue without signing keys - WebAuthn still works
            }

            return {
                success: true,
                credentialId: credential.id,
                userId: userId,
                message: 'Biometric credential created successfully!'
            };

        } catch (error) {
            console.error('Registration failed:', error);
            
            // Try fallback approach for Android Chrome
            if (error.name === 'NotSupportedError' || error.message.includes('platform authenticator')) {
                console.log('Trying fallback approach without platform authenticator restriction...');
                try {
                    return await this.registerFallback(userId);
                } catch (fallbackError) {
                    console.error('Fallback registration also failed:', fallbackError);
                }
            }
            
            // Provide more specific error messages for common Android issues
            if (error.name === 'NotSupportedError') {
                throw new Error('Biometric authentication is not supported on this device');
            } else if (error.name === 'NotAllowedError') {
                throw new Error('Registration was cancelled or not allowed');
            } else if (error.name === 'SecurityError') {
                throw new Error('Security error - make sure you are using HTTPS');
            } else if (error.name === 'InvalidStateError') {
                throw new Error('Invalid state - credential may already exist');
            } else if (error.message.includes('credential manager')) {
                // Chrome-specific error message
                const userAgent = navigator.userAgent.toLowerCase();
                if (userAgent.includes('android') && userAgent.includes('chrome')) {
                    throw new Error('Chrome on Android has known WebAuthn issues. Try using Firefox Mobile instead, or use a different device.');
                } else {
                    throw new Error(`Registration failed: ${error.message}`);
                }
            } else {
                throw new Error(`Registration failed: ${error.message || 'Unknown error occurred'}`);
            }
        }
    }

    /**
     * Fallback registration method for Android Chrome compatibility
     */
    async registerFallback(userId) {
        console.log('Attempting fallback registration...');
        
        const challenge = this.generateChallenge();
        
        // Try multiple approaches for Android Chrome
        const approaches = [
            // Approach 1: Ultra-minimal for Chrome
            {
                name: "Ultra-minimal Chrome",
                options: {
                    publicKey: {
                        challenge: challenge,
                        rp: {
                            name: "Altis",
                            id: window.location.hostname || "localhost",
                        },
                        user: {
                            id: new TextEncoder().encode(userId),
                            name: userId,
                            displayName: "Altis User",
                        },
                        pubKeyCredParams: [
                            { type: "public-key", alg: -7 }, // ES256
                        ],
                        timeout: 30000,
                        attestation: "none"
                    }
                }
            },
            // Approach 2: No authenticator selection at all
            {
                name: "No authenticator selection",
                options: {
                    publicKey: {
                        challenge: challenge,
                        rp: {
                            name: "Altis",
                            id: window.location.hostname || "localhost",
                        },
                        user: {
                            id: new TextEncoder().encode(userId),
                            name: userId,
                            displayName: "Altis User",
                        },
                        pubKeyCredParams: [
                            { type: "public-key", alg: -7 }, // ES256
                            { type: "public-key", alg: -257 }, // RS256
                        ],
                        timeout: 60000,
                        attestation: "none"
                    }
                }
            },
            // Approach 2: Minimal authenticator selection
            {
                name: "Minimal authenticator selection",
                options: {
                    publicKey: {
                        challenge: challenge,
                        rp: {
                            name: "Altis",
                            id: window.location.hostname || "localhost",
                        },
                        user: {
                            id: new TextEncoder().encode(userId),
                            name: userId,
                            displayName: "Altis User",
                        },
                        pubKeyCredParams: [
                            { type: "public-key", alg: -7 }, // ES256
                            { type: "public-key", alg: -257 }, // RS256
                        ],
                        authenticatorSelection: {
                            userVerification: "preferred"
                        },
                        timeout: 60000,
                        attestation: "none"
                    }
                }
            },
            // Approach 3: Cross-platform authenticator
            {
                name: "Cross-platform authenticator",
                options: {
                    publicKey: {
                        challenge: challenge,
                        rp: {
                            name: "Altis",
                            id: window.location.hostname || "localhost",
                        },
                        user: {
                            id: new TextEncoder().encode(userId),
                            name: userId,
                            displayName: "Altis User",
                        },
                        pubKeyCredParams: [
                            { type: "public-key", alg: -7 }, // ES256
                            { type: "public-key", alg: -257 }, // RS256
                        ],
                        authenticatorSelection: {
                            authenticatorAttachment: "cross-platform",
                            userVerification: "preferred",
                            residentKey: "preferred"
                        },
                        timeout: 60000,
                        attestation: "none"
                    }
                }
            }
        ];

        for (const approach of approaches) {
            try {
                console.log(`Trying ${approach.name}...`);
                console.log('Create options:', approach.options);
                
                const credential = await navigator.credentials.create(approach.options);
                console.log(`Success with ${approach.name}:`, credential);
                
                // Store credential data
                const credentialData = {
                    id: credential.id,
                    rawId: this.arrayBufferToBase64URL(credential.rawId),
                    publicKey: this.arrayBufferToBase64URL(credential.response.publicKey),
                    userId: userId,
                    createdAt: new Date().toISOString()
                };

                this.credentials.set(credential.id, credentialData);
                this.currentUserId = userId;
                this.currentCredentialId = credential.id;

                // Store in localStorage for persistence
                localStorage.setItem('altis_credentials', JSON.stringify(Array.from(this.credentials.entries())));
                localStorage.setItem('altis_user_id', userId);
                localStorage.setItem('altis_credential_id', credential.id);

                return {
                    success: true,
                    credentialId: credential.id,
                    userId: userId,
                    message: `Biometric credential created successfully (${approach.name})!`
                };
                
            } catch (error) {
                console.error(`${approach.name} failed:`, error);
                // Continue to next approach
            }
        }
        
        throw new Error('All fallback registration approaches failed');
    }

    /**
     * Authenticate using existing biometric credential
     */
    async authenticate() {
        if (!this.isSupported) {
            throw new Error('WebAuthn is not supported in this browser');
        }

        // Check Android-specific requirements
        this.checkAndroidRequirements();

        try {
            // Load stored credentials
            this.loadStoredCredentials();

            if (this.credentials.size === 0) {
                throw new Error('No credentials found. Please register first.');
            }

            // Generate challenge
            const challenge = this.generateChallenge();

            // Get credential IDs
            const credentialIds = Array.from(this.credentials.keys()).map(id => 
                this.base64URLToArrayBuffer(id)
            );

            // Create assertion options
            const assertionOptions = {
                publicKey: {
                    challenge: challenge,
                    allowCredentials: credentialIds.map(id => ({
                        type: "public-key",
                        id: id
                        // Remove transports restriction for Android compatibility
                    })),
                    userVerification: "preferred", // Change from "required" to "preferred"
                    timeout: 60000 // 60 seconds
                }
            };

            // Get the credential
            const assertion = await navigator.credentials.get(assertionOptions);

            // Find the matching credential
            const credentialId = this.arrayBufferToBase64URL(assertion.rawId);
            const credentialData = this.credentials.get(credentialId);

            if (!credentialData) {
                throw new Error('Credential not found');
            }

            // Update authentication count
            this.authCount++;
            this.currentUserId = credentialData.userId;
            this.currentCredentialId = credentialId;

            // Store updated data
            localStorage.setItem('altis_auth_count', this.authCount.toString());

            // Load encrypted signing key pair
            try {
                console.log('Loading encrypted signing key pair...');
                const encryptionKey = await this.encryptionManager.deriveEncryptionKey({
                    credentialId: credentialId,
                    response: assertion.response
                });
                const privateKey = await this.encryptionManager.loadEncryptedPrivateKey(encryptionKey);
                const publicKey = await this.encryptionManager.loadPublicKey();
                this.signingKeyPair = { privateKey, publicKey };
                console.log('Encrypted signing key pair loaded successfully');
            } catch (error) {
                console.error('Failed to load encrypted signing key pair:', error);
                // Continue without signing keys - WebAuthn still works
            }

            return {
                success: true,
                credentialId: credentialId,
                userId: credentialData.userId,
                authCount: this.authCount,
                message: 'Authentication successful!'
            };

        } catch (error) {
            console.error('Authentication failed:', error);
            
            // Provide more specific error messages for common Android issues
            if (error.name === 'NotSupportedError') {
                throw new Error('Biometric authentication is not supported on this device');
            } else if (error.name === 'NotAllowedError') {
                throw new Error('Authentication was cancelled or not allowed');
            } else if (error.name === 'SecurityError') {
                throw new Error('Security error - make sure you are using HTTPS');
            } else if (error.name === 'InvalidStateError') {
                throw new Error('Invalid state - no credentials found');
            } else {
                throw new Error(`Authentication failed: ${error.message || 'Unknown error occurred'}`);
            }
        }
    }

    /**
     * Load stored credentials from localStorage
     */
    loadStoredCredentials() {
        try {
            const stored = localStorage.getItem('altis_credentials');
            if (stored) {
                const entries = JSON.parse(stored);
                this.credentials = new Map(entries);
            }

            const userId = localStorage.getItem('altis_user_id');
            const credentialId = localStorage.getItem('altis_credential_id');
            const authCount = localStorage.getItem('altis_auth_count');

            if (userId) this.currentUserId = userId;
            if (credentialId) this.currentCredentialId = credentialId;
            if (authCount) this.authCount = parseInt(authCount, 10);

        } catch (error) {
            console.error('Failed to load stored credentials:', error);
        }
    }

    /**
     * Check if user is already registered
     */
    isRegistered() {
        this.loadStoredCredentials();
        return this.credentials.size > 0;
    }

    /**
     * Logout and clear session data
     */
    logout() {
        this.currentUserId = null;
        this.currentCredentialId = null;
        this.authCount = 0;
        
        // Clear session data but keep credentials for future use
        localStorage.removeItem('altis_user_id');
        localStorage.removeItem('altis_credential_id');
        localStorage.removeItem('altis_auth_count');
    }

    /**
     * Get current user info
     */
    getCurrentUser() {
        return {
            userId: this.currentUserId,
            credentialId: this.currentCredentialId,
            authCount: this.authCount,
            isAuthenticated: !!this.currentUserId
        };
    }

    /**
     * Check if user is currently authenticated
     */
    isAuthenticated() {
        return !!this.currentUserId;
    }

    /**
     * Sign data with the encrypted private key
     */
    async signData(data) {
        if (!this.signingKeyPair || !this.signingKeyPair.privateKey) {
            throw new Error('No signing key available - please authenticate first');
        }

        try {
            console.log('Signing data with encrypted private key...');
            const signature = await this.encryptionManager.signData(data, this.signingKeyPair.privateKey);
            console.log('Data signed successfully');
            return signature;
        } catch (error) {
            console.error('Failed to sign data:', error);
            throw new Error('Failed to sign data');
        }
    }

    /**
     * Verify signature with the public key
     */
    async verifySignature(data, signature) {
        if (!this.signingKeyPair || !this.signingKeyPair.publicKey) {
            throw new Error('No public key available - please authenticate first');
        }

        try {
            console.log('Verifying signature with public key...');
            const isValid = await this.encryptionManager.verifySignature(data, signature, this.signingKeyPair.publicKey);
            console.log('Signature verification completed');
            return isValid;
        } catch (error) {
            console.error('Failed to verify signature:', error);
            return false;
        }
    }

    /**
     * Get public key for external verification
     */
    async getPublicKey() {
        if (!this.signingKeyPair || !this.signingKeyPair.publicKey) {
            throw new Error('No public key available - please authenticate first');
        }

        try {
            const exportedKey = await crypto.subtle.exportKey('spki', this.signingKeyPair.publicKey);
            const keyArray = new Uint8Array(exportedKey);
            const keyBase64 = btoa(String.fromCharCode(...keyArray));
            return keyBase64;
        } catch (error) {
            console.error('Failed to export public key:', error);
            throw new Error('Failed to export public key');
        }
    }

    /**
     * Check if encrypted signing keys exist
     */
    hasEncryptedSigningKeys() {
        return this.encryptionManager.hasEncryptedKeys();
    }
}

export default WebAuthnManager;
