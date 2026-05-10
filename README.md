# AtlasID - Decentralized Credential Wallet

AtlasID is a React Native mobile wallet and Node.js backend system designed for issuing, storing, and cryptographically verifying decentralized identity credentials using Ed25519 signatures.

## 🏗️ Architecture
- **Backend:** Node.js, Express, PostgreSQL (for mock MOSIP registry and credential backup)
- **Frontend (Wallet & Verifier):** React Native (Expo), AsyncStorage
- **Cryptography:** TweetNaCl.js (Ed25519 Detached Signatures)

## 🚀 Quick Start Guide

### 1. Database Setup
Ensure PostgreSQL is running locally. Create a database named `atlasid`.
The backend will automatically initialize the required tables (`users`, `credentials`, `mosip_mock_registry`) on the first run.

### 2. Backend Setup
Navigate to the `backend` directory:
```bash
cd backend
npm install