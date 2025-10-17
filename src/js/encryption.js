/**
 * Biometric-Encrypted Data Storage Manager
 * Handles encryption/decryption of private keys using biometric-derived keys
 */

class EncryptionManager {
    constructor() {
        this.encryptedDataKey = 'altis_encrypted_data';
        this.encryptedKeyKey = 'altis_encrypted_private_key';
        this.encryptedPublicKeyKey = 'altis_encrypted_public_key';
    }

    /**
     * Generate a new signing key pair
     */
    async generateSigningKeyPair() {
        try {
            console.log('Generating new signing key pair...');
            
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true, // extractable
                ["sign", "verify"]
            );

            console.log('Signing key pair generated successfully');
            return keyPair;
        } catch (error) {
            console.error('Failed to generate signing key pair:', error);
            throw new Error('Failed to generate signing key pair');
        }
    }

    /**
     * Derive encryption key from WebAuthn authentication
     * Uses the WebAuthn credential response to derive a consistent encryption key
     */
    async deriveEncryptionKey(webauthnResponse) {
        try {
            console.log('Deriving encryption key from WebAuthn response...');
            
            // Use the WebAuthn credential ID and response as entropy
            const credentialId = webauthnResponse.credentialId || webauthnResponse.id;
            const responseData = webauthnResponse.response;
            
            // Create entropy from WebAuthn data
            const entropy = new TextEncoder().encode(
                credentialId + 
                JSON.stringify(responseData) + 
                'altis-encryption-salt'
            );
            
            // Derive key using PBKDF2
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                entropy,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );
            
            const encryptionKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: new TextEncoder().encode('altis-salt-2025'),
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            
            console.log('Encryption key derived successfully');
            return encryptionKey;
        } catch (error) {
            console.error('Failed to derive encryption key:', error);
            throw new Error('Failed to derive encryption key from WebAuthn response');
        }
    }

    /**
     * Encrypt private key using derived encryption key
     */
    async encryptPrivateKey(privateKey, encryptionKey) {
        try {
            console.log('Encrypting private key...');
            
            // Export the private key
            const exportedKey = await crypto.subtle.exportKey('pkcs8', privateKey);
            
            // Generate random IV
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Encrypt the private key
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                encryptionKey,
                exportedKey
            );
            
            // Store IV + encrypted data
            const result = {
                iv: Array.from(iv),
                data: Array.from(new Uint8Array(encryptedData)),
                timestamp: new Date().toISOString()
            };
            
            console.log('Private key encrypted successfully');
            return result;
        } catch (error) {
            console.error('Failed to encrypt private key:', error);
            throw new Error('Failed to encrypt private key');
        }
    }

    /**
     * Decrypt private key using derived encryption key
     */
    async decryptPrivateKey(encryptedData, encryptionKey) {
        try {
            console.log('Decrypting private key...');
            
            const iv = new Uint8Array(encryptedData.iv);
            const data = new Uint8Array(encryptedData.data);
            
            // Decrypt the private key
            const decryptedData = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                encryptionKey,
                data
            );
            
            // Import the decrypted private key
            const privateKey = await crypto.subtle.importKey(
                'pkcs8',
                decryptedData,
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                true,
                ['sign']
            );
            
            console.log('Private key decrypted successfully');
            return privateKey;
        } catch (error) {
            console.error('Failed to decrypt private key:', error);
            throw new Error('Failed to decrypt private key - biometric authentication may be required');
        }
    }

    /**
     * Store encrypted private key and public key
     */
    async storeEncryptedKeys(privateKey, publicKey, encryptionKey) {
        try {
            console.log('Storing encrypted keys...');
            
            // Encrypt private key
            const encryptedPrivateKey = await this.encryptPrivateKey(privateKey, encryptionKey);
            
            // Export and store public key (not encrypted)
            const exportedPublicKey = await crypto.subtle.exportKey('spki', publicKey);
            const publicKeyData = {
                data: Array.from(new Uint8Array(exportedPublicKey)),
                timestamp: new Date().toISOString()
            };
            
            // Store in localStorage
            localStorage.setItem(this.encryptedKeyKey, JSON.stringify(encryptedPrivateKey));
            localStorage.setItem(this.encryptedPublicKeyKey, JSON.stringify(publicKeyData));
            
            console.log('Encrypted keys stored successfully');
            return true;
        } catch (error) {
            console.error('Failed to store encrypted keys:', error);
            throw new Error('Failed to store encrypted keys');
        }
    }

    /**
     * Load and decrypt private key
     */
    async loadEncryptedPrivateKey(encryptionKey) {
        try {
            console.log('Loading encrypted private key...');
            
            const encryptedData = localStorage.getItem(this.encryptedKeyKey);
            if (!encryptedData) {
                throw new Error('No encrypted private key found');
            }
            
            const parsedData = JSON.parse(encryptedData);
            const privateKey = await this.decryptPrivateKey(parsedData, encryptionKey);
            
            console.log('Encrypted private key loaded successfully');
            return privateKey;
        } catch (error) {
            console.error('Failed to load encrypted private key:', error);
            throw new Error('Failed to load encrypted private key');
        }
    }

    /**
     * Load public key
     */
    async loadPublicKey() {
        try {
            console.log('Loading public key...');
            
            const publicKeyData = localStorage.getItem(this.encryptedPublicKeyKey);
            if (!publicKeyData) {
                throw new Error('No public key found');
            }
            
            const parsedData = JSON.parse(publicKeyData);
            const publicKey = await crypto.subtle.importKey(
                'spki',
                new Uint8Array(parsedData.data),
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                true,
                ['verify']
            );
            
            console.log('Public key loaded successfully');
            return publicKey;
        } catch (error) {
            console.error('Failed to load public key:', error);
            throw new Error('Failed to load public key');
        }
    }

    /**
     * Sign data with private key
     */
    async signData(data, privateKey) {
        try {
            console.log('Signing data with private key...');
            
            const dataBuffer = new TextEncoder().encode(data);
            const signature = await crypto.subtle.sign(
                {
                    name: 'ECDSA',
                    hash: 'SHA-256'
                },
                privateKey,
                dataBuffer
            );
            
            // Convert to base64 for storage/transmission
            const signatureArray = new Uint8Array(signature);
            const signatureBase64 = btoa(String.fromCharCode(...signatureArray));
            
            console.log('Data signed successfully');
            return signatureBase64;
        } catch (error) {
            console.error('Failed to sign data:', error);
            throw new Error('Failed to sign data');
        }
    }

    /**
     * Verify signature with public key
     */
    async verifySignature(data, signature, publicKey) {
        try {
            console.log('Verifying signature...');
            
            const dataBuffer = new TextEncoder().encode(data);
            const signatureArray = new Uint8Array(
                atob(signature).split('').map(char => char.charCodeAt(0))
            );
            
            const isValid = await crypto.subtle.verify(
                {
                    name: 'ECDSA',
                    hash: 'SHA-256'
                },
                publicKey,
                signatureArray,
                dataBuffer
            );
            
            console.log('Signature verification result:', isValid);
            return isValid;
        } catch (error) {
            console.error('Failed to verify signature:', error);
            return false;
        }
    }

    /**
     * Check if encrypted keys exist
     */
    hasEncryptedKeys() {
        return !!(localStorage.getItem(this.encryptedKeyKey) && localStorage.getItem(this.encryptedPublicKeyKey));
    }

    /**
     * Clear all encrypted data
     */
    clearEncryptedData() {
        localStorage.removeItem(this.encryptedKeyKey);
        localStorage.removeItem(this.encryptedPublicKeyKey);
        console.log('Encrypted data cleared');
    }
}

export default EncryptionManager;
