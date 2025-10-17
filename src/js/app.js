/**
 * Main Application Controller
 * Manages the PWA UI and WebAuthn integration
 */

import WebAuthnManager from './webauthn.js';

class PWAApp {
    constructor() {
        this.webauthn = new WebAuthnManager();
        this.elements = this.initializeElements();
        this.initializeApp();
    }

    /**
     * Initialize DOM element references
     */
    initializeElements() {
        return {
            statusIndicator: document.getElementById('status-indicator'),
            statusText: document.getElementById('status-text'),
            registerBtn: document.getElementById('register-btn'),
            authenticateBtn: document.getElementById('authenticate-btn'),
            logoutBtn: document.getElementById('logout-btn'),
            userInfo: document.getElementById('user-info'),
            userId: document.getElementById('user-id'),
            credentialId: document.getElementById('credential-id'),
            authCount: document.getElementById('auth-count'),
            authContainer: document.getElementById('auth-container'),
            content: document.getElementById('content'),
            returnHomeBtn: document.getElementById('return-home-btn'),
            logoutContentBtn: document.getElementById('logout-content-btn'),
            signingInput: document.getElementById('signing-input'),
            signDataBtn: document.getElementById('sign-data-btn'),
            signingResult: document.getElementById('signing-result')
        };
    }

    /**
     * Initialize the application
     */
    async initializeApp() {
        try {
            // Initialize version display
            this.initializeVersionDisplay();
            
            // Check WebAuthn support
            if (!this.webauthn.isSupported) {
                this.updateStatus('error', 'WebAuthn not supported in this browser');
                this.disableAllButtons();
                return;
            }

            // Load stored credentials
            this.webauthn.loadStoredCredentials();

            // Check if user is already registered
            if (this.webauthn.isRegistered()) {
                this.updateStatus('loading', 'Checking authentication...');
                
                if (this.webauthn.isAuthenticated()) {
                    this.showAuthenticatedState();
                } else {
                    this.showRegisteredState();
                }
            } else {
                this.showUnregisteredState();
            }

            // Set up event listeners
            this.setupEventListeners();

        } catch (error) {
            console.error('App initialization failed:', error);
            this.updateStatus('error', 'Initialization failed');
        }
    }

    /**
     * Initialize version display
     */
    initializeVersionDisplay() {
        const versionNumber = document.getElementById('version-number');
        const buildInfo = document.getElementById('build-info');
        
        if (versionNumber && buildInfo) {
            // Get current date and time
            const now = new Date();
            const year = now.getFullYear();
            const month = String(now.getMonth() + 1).padStart(2, '0');
            const day = String(now.getDate()).padStart(2, '0');
            const hours = String(now.getHours()).padStart(2, '0');
            const minutes = String(now.getMinutes()).padStart(2, '0');
            
            // Format date strings
            const dateString = `${year}${month}${day}-${hours}${minutes}`;
            const timeString = now.toLocaleString('en-US', {
                month: '2-digit',
                day: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: true
            });
            
            // Update version display
            versionNumber.textContent = `v0.0.1+${dateString}`;
            buildInfo.textContent = `Build: ${dateString} (${timeString})`;
        }
    }

    /**
     * Set up event listeners for buttons
     */
    setupEventListeners() {
        this.elements.registerBtn.addEventListener('click', () => this.handleRegister());
        this.elements.authenticateBtn.addEventListener('click', () => this.handleAuthenticate());
        this.elements.logoutBtn.addEventListener('click', () => this.handleLogout());
        this.elements.returnHomeBtn.addEventListener('click', () => this.handleReturnHome());
        this.elements.logoutContentBtn.addEventListener('click', () => this.handleLogout());
        this.elements.signDataBtn.addEventListener('click', () => this.handleSignData());
    }

    /**
     * Handle registration button click
     */
    async handleRegister() {
        try {
            this.updateStatus('loading', 'Creating biometric key...');
            this.disableAllButtons();

            const result = await this.webauthn.register();
            
            if (result.success) {
                this.updateStatus('authenticated', 'Biometric key created successfully!');
                this.showAuthenticatedState();
                this.showUserInfo(result.userId, result.credentialId);
            }

        } catch (error) {
            console.error('Registration error:', error);
            this.updateStatus('error', error.message);
            this.showRegisteredState();
        }
    }

    /**
     * Handle authentication button click
     */
    async handleAuthenticate() {
        try {
            this.updateStatus('loading', 'Authenticating with biometric...');
            this.disableAllButtons();

            const result = await this.webauthn.authenticate();
            
            if (result.success) {
                this.updateStatus('authenticated', 'Authentication successful!');
                this.showAuthenticatedState();
                this.showUserInfo(result.userId, result.credentialId, result.authCount);
            }

        } catch (error) {
            console.error('Authentication error:', error);
            this.updateStatus('error', error.message);
            this.showRegisteredState();
        }
    }

    /**
     * Handle logout button click
     */
    handleLogout() {
        this.webauthn.logout();
        this.updateStatus('loading', 'Logged out');
        this.showRegisteredState();
    }

    /**
     * Handle return home button click
     */
    handleReturnHome() {
        this.showRegisteredState();
    }

    /**
     * Handle sign data button click
     */
    async handleSignData() {
        const dataToSign = this.elements.signingInput.value.trim();
        
        if (!dataToSign) {
            this.showNotification('Please enter some text to sign', 'warning');
            return;
        }

        try {
            this.elements.signDataBtn.disabled = true;
            this.elements.signDataBtn.textContent = 'Signing...';

            console.log('Signing data:', dataToSign);
            
            // Sign the data
            const signature = await this.webauthn.signData(dataToSign);
            
            // Verify the signature
            const isValid = await this.webauthn.verifySignature(dataToSign, signature);
            
            // Display results
            document.getElementById('original-data').textContent = dataToSign;
            document.getElementById('signature-data').textContent = signature;
            document.getElementById('verification-result').textContent = isValid ? '✅ Valid' : '❌ Invalid';
            
            this.elements.signingResult.style.display = 'block';
            
            this.showNotification('Data signed and verified successfully!', 'success');
            
        } catch (error) {
            console.error('Signing failed:', error);
            this.showNotification(`Signing failed: ${error.message}`, 'error');
        } finally {
            this.elements.signDataBtn.disabled = false;
            this.elements.signDataBtn.textContent = 'Sign Data';
        }
    }

    /**
     * Update status indicator and text
     */
    updateStatus(type, message) {
        // Update status indicator
        this.elements.statusIndicator.className = `status-indicator ${type}`;
        this.elements.statusText.textContent = message;

        // Update button states based on status
        if (type === 'loading') {
            this.disableAllButtons();
        } else if (type === 'error') {
            this.showRegisteredState();
        }
    }

    /**
     * Show unregistered state (user needs to register)
     */
    showUnregisteredState() {
        this.elements.registerBtn.disabled = false;
        this.elements.authenticateBtn.disabled = true;
        this.elements.logoutBtn.disabled = true;
        this.elements.userInfo.style.display = 'none';
        this.elements.content.style.display = 'none';
        this.elements.authContainer.style.display = 'block';
    }

    /**
     * Show registered state (user can authenticate)
     */
    showRegisteredState() {
        this.elements.registerBtn.disabled = true;
        this.elements.authenticateBtn.disabled = false;
        this.elements.logoutBtn.disabled = false;
        this.elements.userInfo.style.display = 'none';
        this.elements.content.style.display = 'none';
        this.elements.authContainer.style.display = 'block';
    }

    /**
     * Show authenticated state (user is logged in)
     */
    showAuthenticatedState() {
        this.elements.registerBtn.disabled = true;
        this.elements.authenticateBtn.disabled = true;
        this.elements.logoutBtn.disabled = false;
        this.elements.userInfo.style.display = 'block';
        this.elements.content.style.display = 'block';
        this.elements.authContainer.style.display = 'none';
    }

    /**
     * Show user information
     */
    showUserInfo(userId, credentialId, authCount = 0) {
        // Update the small user info panel
        this.elements.userId.textContent = userId;
        this.elements.credentialId.textContent = credentialId;
        this.elements.authCount.textContent = authCount;
        
        // Update the detailed content page
        this.updateContentDetails(userId, credentialId, authCount);
    }

    /**
     * Update detailed content information
     */
    updateContentDetails(userId, credentialId, authCount = 0) {
        // Get credential data for additional details
        const credentialData = this.webauthn.credentials.get(credentialId);
        
        // Update content page details
        document.getElementById('content-user-id').textContent = userId;
        document.getElementById('content-credential-id').textContent = credentialId;
        document.getElementById('content-auth-count').textContent = authCount;
        
        // Registration date
        const registrationDate = credentialData ? 
            new Date(credentialData.createdAt).toLocaleString() : 
            'Unknown';
        document.getElementById('content-registration-date').textContent = registrationDate;
        
        // Last authentication (current time)
        const lastAuth = new Date().toLocaleString();
        document.getElementById('content-last-auth').textContent = lastAuth;
        
        // Browser information
        const userAgent = navigator.userAgent;
        const browserInfo = this.getBrowserInfo(userAgent);
        document.getElementById('content-browser').textContent = browserInfo;
    }

    /**
     * Get browser information from user agent
     */
    getBrowserInfo(userAgent) {
        if (userAgent.includes('Chrome')) {
            return 'Chrome';
        } else if (userAgent.includes('Firefox')) {
            return 'Firefox';
        } else if (userAgent.includes('Safari')) {
            return 'Safari';
        } else if (userAgent.includes('Edge')) {
            return 'Edge';
        } else {
            return 'Unknown Browser';
        }
    }

    /**
     * Disable all buttons
     */
    disableAllButtons() {
        this.elements.registerBtn.disabled = true;
        this.elements.authenticateBtn.disabled = true;
        this.elements.logoutBtn.disabled = true;
    }

    /**
     * Show notification to user
     */
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        // Style the notification
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '1rem 1.5rem',
            borderRadius: '10px',
            color: 'white',
            fontWeight: '600',
            zIndex: '1000',
            maxWidth: '300px',
            wordWrap: 'break-word',
            boxShadow: '0 10px 20px rgba(0, 0, 0, 0.2)',
            transform: 'translateX(100%)',
            transition: 'transform 0.3s ease'
        });

        // Set background color based on type
        const colors = {
            success: '#48bb78',
            error: '#f56565',
            info: '#4299e1',
            warning: '#ed8936'
        };
        notification.style.backgroundColor = colors[type] || colors.info;

        // Add to page
        document.body.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.pwaApp = new PWAApp();
});

// Handle PWA installation
let deferredPrompt;
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    
        // Show install button or notification
        if (window.pwaApp) {
            window.pwaApp.showNotification('Altis can be installed on your device!', 'info');
        }
});

// Handle PWA installation
window.addEventListener('appinstalled', () => {
    console.log('PWA was installed');
    if (window.pwaApp) {
        window.pwaApp.showNotification('Altis installed successfully!', 'success');
    }
});

// Handle online/offline status
window.addEventListener('online', () => {
    if (window.pwaApp) {
        window.pwaApp.showNotification('You are back online!', 'success');
    }
});

window.addEventListener('offline', () => {
    if (window.pwaApp) {
        window.pwaApp.showNotification('You are offline. Some features may be limited.', 'warning');
    }
});
