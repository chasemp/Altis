# How Altis PWA Works

I'll explain how the Altis PWA with WebAuthn biometric authentication works, breaking it down into the key components and flow.

## 🔐 How Altis PWA Works

### 1. **WebAuthn Biometric Authentication Flow**

#### **Registration Process** (First Time Setup)
```
User clicks "Create Biometric Key" 
    ↓
Browser prompts for biometric (fingerprint/face)
    ↓
Device creates cryptographic key pair
    ↓
Private key stored in device's secure enclave
    ↓
Public key + credential ID saved locally
    ↓
User is registered and can authenticate
```

#### **Authentication Process** (Login)
```
User clicks "Authenticate"
    ↓
Browser requests biometric verification
    ↓
Device verifies biometric locally
    ↓
Device signs challenge with private key
    ↓
Browser receives signed response
    ↓
User is authenticated
```

### 2. **Security Architecture**

#### **Key Storage Strategy**
- **Private Key**: Never leaves the device - stored in hardware security module
- **Public Key**: Stored locally in browser's credential manager
- **Biometric Data**: Never transmitted - only used locally for verification
- **Credential ID**: Unique identifier linking to the stored credential

#### **Why This is the Safest Approach**
1. **Hardware Security**: Uses device's secure enclave/TEE
2. **Zero Trust**: No server dependency for authentication
3. **Standard Compliance**: Follows WebAuthn/FIDO2 standards
4. **Privacy First**: Biometric data never leaves the device

### 3. **Technical Implementation**

#### **WebAuthn Manager (`js/webauthn.js`)**
```javascript
// Key functions:
- register()     // Creates new biometric credential
- authenticate() // Verifies user with biometric
- loadStoredCredentials() // Retrieves saved credentials
- isSupported()  // Checks browser compatibility
```

#### **Credential Creation Process**
```javascript
// 1. Generate challenge (random 32 bytes)
const challenge = crypto.getRandomValues(new Uint8Array(32));

// 2. Create credential options
const createOptions = {
  publicKey: {
    challenge: challenge,
    rp: { name: "Altis", id: window.location.hostname },
    user: { id: userId, name: userId, displayName: "Altis User" },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },  // ES256
      { type: "public-key", alg: -257 } // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",    // Built-in authenticators only
      userVerification: "required",           // Must use biometric
      residentKey: "required"                 // Store on device
    }
  }
};

// 3. Create credential
const credential = await navigator.credentials.create(createOptions);
```

#### **Authentication Process**
```javascript
// 1. Generate new challenge
const challenge = crypto.getRandomValues(new Uint8Array(32));

// 2. Request authentication
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: challenge,
    allowCredentials: [/* stored credential IDs */],
    userVerification: "required"
  }
});

// 3. Verify response (in real app, would verify server-side)
```

### 4. **PWA Features**

#### **Service Worker (`sw.js`)**
- **Caching Strategy**: Cache-first for static assets, network-first for API calls
- **Offline Support**: App works without internet connection
- **Background Sync**: Handles offline data when connection returns

#### **App Controller (`js/app.js`)**
- **UI Management**: Handles button states and user feedback
- **State Management**: Tracks authentication status
- **Error Handling**: Provides user-friendly error messages
- **PWA Events**: Handles installation and offline/online status

### 5. **Data Flow**

#### **Registration Flow**
```
User → "Create Biometric Key" → WebAuthn API → Device Biometric → 
Hardware Security Module → Credential Created → Stored Locally → 
UI Updated → User Registered
```

#### **Authentication Flow**
```
User → "Authenticate" → WebAuthn API → Device Biometric → 
Hardware Verification → Signed Response → UI Updated → 
User Authenticated
```

### 6. **Browser Compatibility**

#### **Supported Platforms**
- **Chrome/Edge**: Android & Desktop (full support)
- **Safari**: iOS & macOS (Face ID, Touch ID)
- **Firefox**: Desktop (limited support)
- **Samsung Internet**: Android devices

#### **Required Features**
- WebAuthn API support
- Platform authenticators (built-in biometric sensors)
- Secure context (HTTPS required)

### 7. **Security Benefits**

#### **Why WebAuthn is Superior**
1. **Phishing Resistant**: Credentials are bound to the domain
2. **No Password Storage**: Eliminates password-based attacks
3. **Hardware Security**: Uses device's secure enclave
4. **User Verification**: Requires biometric or PIN
5. **Standardized**: Industry-standard security protocol

#### **Attack Resistance**
- **Man-in-the-Middle**: Credentials bound to domain
- **Replay Attacks**: Each authentication uses unique challenge
- **Credential Theft**: Private keys never leave device
- **Biometric Spoofing**: Hardware-level verification

### 8. **User Experience**

#### **Mobile Experience**
1. **Installation**: Add to home screen from browser
2. **Authentication**: Tap button → biometric prompt → authenticated
3. **Offline**: Works without internet connection
4. **Native Feel**: Full-screen app experience

#### **Desktop Experience**
1. **Installation**: Browser install prompt or manual installation
2. **Authentication**: Click button → biometric prompt → authenticated
3. **Cross-Platform**: Works on Windows Hello, Touch ID, etc.

### 9. **Deployment Architecture**

#### **GitHub Pages Setup**
```
Source Code (src/) → Vite Build → Production Build (docs/) → 
GitHub Pages → https://altis.523.life
```

#### **File Structure**
- **`/src`**: Source code (HTML, CSS, JS)
- **`/public`**: Static assets (manifest, icons, CNAME)
- **`/docs`**: Built production files (auto-generated)
- **Service Worker**: Handles caching and offline functionality

### 10. **Local Storage Management**

#### **Credential Storage**
```javascript
// Stored in browser's localStorage
localStorage.setItem('altis_credentials', JSON.stringify(credentials));
localStorage.setItem('altis_user_id', userId);
localStorage.setItem('altis_credential_id', credentialId);
localStorage.setItem('altis_auth_count', authCount);
```

#### **Data Persistence**
- **Credentials**: Stored in browser's credential manager
- **User Data**: Stored in localStorage for session management
- **Authentication State**: Managed by the app controller
- **Offline Data**: Cached by service worker

### 11. **Error Handling**

#### **Common Scenarios**
- **WebAuthn Not Supported**: Graceful fallback with error message
- **Biometric Failure**: User-friendly retry prompts
- **Network Issues**: Offline mode with cached functionality
- **Credential Errors**: Clear error messages and recovery options

#### **User Feedback**
- **Status Indicators**: Visual feedback for authentication state
- **Notifications**: Toast messages for important events
- **Error Messages**: Clear, actionable error descriptions
- **Loading States**: Progress indicators during operations

### 12. **Performance Optimizations**

#### **Caching Strategy**
- **Static Assets**: Cached immediately on first load
- **Dynamic Content**: Stale-while-revalidate strategy
- **API Calls**: Network-first with cache fallback
- **Service Worker**: Intelligent cache management

#### **Loading Performance**
- **Code Splitting**: Modular JavaScript loading
- **Asset Optimization**: Minified and compressed files
- **Lazy Loading**: Load resources as needed
- **Preloading**: Critical resources loaded first

This architecture provides a secure, user-friendly biometric authentication system that leverages the browser's native security features while maintaining the convenience of a Progressive Web App.

---

**Built with ❤️ following PWA best practices and WebAuthn security standards**
