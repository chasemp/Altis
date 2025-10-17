# Altis - Biometric PWA

A Progressive Web App demonstrating WebAuthn biometric authentication using Passkeys. Built following PWA best practices from the [peadoubleueh template](https://github.com/chasemp/peadoubleueh).

🔐 **Features:**
- WebAuthn biometric authentication (fingerprint, face recognition)
- Secure credential storage using browser's native credential manager
- Offline functionality with service worker
- Installable PWA with GitHub Pages deployment
- Modern, responsive UI with mobile-first design

## 🚀 Quick Start

### Development
```bash
# Install dependencies
npm install

# Start development server
npm run dev
# → Opens at http://localhost:3456

# Build for production
npm run build
# → Outputs to /docs for GitHub Pages deployment

# Preview production build
npm run preview
```

### Deployment to GitHub Pages
1. Push to `main` branch
2. Enable GitHub Pages in repository settings
3. Set source to "Deploy from a branch" → "main" → "/docs"
4. Your PWA will be live at `https://altis.523.life`

## 🔐 Biometric Authentication

This PWA implements WebAuthn (Web Authentication API) for secure biometric authentication:

### How It Works
1. **Registration**: User creates a biometric credential (Passkey) using their device's built-in authenticator
2. **Storage**: Credential ID is stored locally (biometric data never leaves the device)
3. **Authentication**: User authenticates using fingerprint, face recognition, or device PIN
4. **Security**: All cryptographic operations happen on the device using hardware security modules

### Browser Support
- ✅ Chrome/Edge (Android & Desktop)
- ✅ Safari (iOS & macOS)
- ✅ Firefox (Desktop)
- ✅ Samsung Internet

### Security Features
- **Platform authenticators only**: Uses built-in biometric sensors
- **User verification required**: Must use biometric or device PIN
- **Resident keys**: Credentials stored on device for convenience
- **No server dependency**: All authentication happens client-side
- **Hardware security**: Uses device's secure enclave when available

## 📁 Project Structure

```
Altis/
├── src/                    # Source code
│   ├── index.html         # Main HTML entry
│   ├── css/styles.css     # Styles
│   ├── js/
│   │   ├── app.js         # Main application controller
│   │   └── webauthn.js    # WebAuthn authentication manager
│   └── sw.js              # Service worker
├── public/                # Static assets
│   ├── manifest.json      # PWA manifest
│   ├── CNAME             # Custom domain (optional)
│   └── assets/           # Icons and favicons
├── docs/                 # Build output (auto-generated)
├── package.json          # Dependencies
└── vite.config.js        # Build configuration
```

## 🛠️ Technical Implementation

### WebAuthn Manager (`js/webauthn.js`)
- Handles credential creation and authentication
- Manages local credential storage
- Provides secure key management
- Implements proper error handling

### PWA Features
- **Service Worker**: Offline functionality and caching
- **Manifest**: App installation and metadata
- **Responsive Design**: Mobile-first approach
- **Performance**: Optimized loading and caching strategies

### Security Considerations
- Credentials stored in browser's credential manager
- No biometric data transmitted to servers
- Uses WebAuthn standard for maximum security
- Implements proper challenge-response authentication

## 🧪 Testing

### Local Testing
1. Run `npm run dev` for development
2. Open in Chrome/Safari on mobile device
3. Test biometric authentication flow
4. Test offline functionality (DevTools → Network → Offline)

### PWA Testing
1. Build with `npm run build`
2. Test installation prompt
3. Verify service worker registration
4. Test offline mode

## 📱 Mobile Experience

- **Installation**: Add to home screen from browser
- **Biometric Auth**: Uses device's fingerprint scanner or face recognition
- **Offline**: Works without internet connection
- **Native Feel**: Full-screen app experience

## 🔧 Configuration

### Custom Domain
Edit `public/CNAME` to set your custom domain for GitHub Pages.

### PWA Manifest
Modify `public/manifest.json` for:
- App name and description
- Theme colors
- Icon paths
- Display preferences

### Build Settings
Configure `vite.config.js` for:
- Build output directory
- Asset optimization
- Development server settings

## 📚 Learn More

- [WebAuthn Guide](https://webauthn.guide/)
- [PWA Best Practices](https://web.dev/pwa-checklist/)
- [Progressive Web Apps](https://web.dev/progressive-web-apps/)
- [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)

## 🤝 Contributing

This is a demonstration project showcasing PWA and WebAuthn best practices. Feel free to use it as a starting point for your own biometric authentication PWA!

## 📄 License

MIT License - See LICENSE file for details

---

**Built with ❤️ following PWA best practices and WebAuthn security standards**