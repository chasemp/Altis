/**
 * WebAuthn Biometric Authentication Manager
 * Implements WebAuthn API for secure biometric authentication using Passkeys
 */

class WebAuthnManager {
    constructor() {
        this.isSupported = this.checkSupport();
        this.credentials = new Map();
        this.authCount = 0;
        this.currentUserId = null;
        this.currentCredentialId = null;
    }

    /**
     * Check if WebAuthn is supported by the browser
     */
    checkSupport() {
        return !!(navigator.credentials && window.PublicKeyCredential);
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

        try {
            // Generate a unique user ID if not provided
            if (!userId) {
                userId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            }

            // Generate challenge
            const challenge = this.generateChallenge();
            
            // Create credential creation options
            const createOptions = {
                publicKey: {
                    challenge: challenge,
                    rp: {
                        name: "Altis",
                        id: window.location.hostname,
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
                        authenticatorAttachment: "platform", // Use built-in authenticators
                        userVerification: "required", // Require biometric verification
                        residentKey: "required" // Store credential on device
                    },
                    timeout: 60000, // 60 seconds
                    attestation: "none" // Don't require attestation for simplicity
                }
            };

            // Create the credential
            const credential = await navigator.credentials.create(createOptions);
            
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

            return {
                success: true,
                credentialId: credential.id,
                userId: userId,
                message: 'Biometric credential created successfully!'
            };

        } catch (error) {
            console.error('Registration failed:', error);
            throw new Error(`Registration failed: ${error.message}`);
        }
    }

    /**
     * Authenticate using existing biometric credential
     */
    async authenticate() {
        if (!this.isSupported) {
            throw new Error('WebAuthn is not supported in this browser');
        }

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
                        id: id,
                        transports: ["internal"] // Use built-in authenticators
                    })),
                    userVerification: "required", // Require biometric verification
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

            return {
                success: true,
                credentialId: credentialId,
                userId: credentialData.userId,
                authCount: this.authCount,
                message: 'Authentication successful!'
            };

        } catch (error) {
            console.error('Authentication failed:', error);
            throw new Error(`Authentication failed: ${error.message}`);
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
}

export default WebAuthnManager;
