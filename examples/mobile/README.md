# CryptoLogin Mobile Example (React Native)

Simple React Native app demonstrating CryptoLogin integration.

## Prerequisites

```bash
npm install
```

## Setup

### 1. Update the API URL in App.js:

```javascript
const API_URL = "https://api.docudeeper.com/api/v1";
```

### 2. Run the app:

```bash
# iOS
npx react-native run-ios

# Android
npx react-native run-android
```

## Features

- ✅ User registration with master secret
- ✅ Login with HMAC-based authentication
- ✅ Session management
- ✅ Secure storage of master secret (Keychain/Keystore)

## Security Notes

- The master secret is stored securely using React Native Keychain
- The secret never leaves the device
- All cryptographic operations happen client-side
