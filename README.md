# AtlasID - Decentralized Credential Wallet

AtlasID is a React Native mobile wallet and Node.js backend system designed for issuing, storing, and cryptographically verifying decentralized identity credentials. 

This project utilizes an offline-first architecture, allowing users to verify Ed25519-signed credentials securely without needing an active internet connection at the time of verification.

## 🏗️ Architecture (v2)
- **Backend:** Node.js, Express, PostgreSQL
- **Frontend (Wallet & Verifier):** React Native (Expo), AsyncStorage
- **Cryptography:** TweetNaCl.js (Ed25519 Detached Signatures)
- **Data Integrity:** Strict deterministic string hashing for guaranteed signature validation across V8 and Hermes JavaScript engines.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Node.js** (v18 or higher)
- **PostgreSQL** (Running locally or hosted)
- **Expo Go** app installed on your physical mobile device.

### 2. Database Setup
Ensure PostgreSQL is running. Create a fresh database named `atlasid`.
The backend will automatically initialize the required tables (`users`, `credentials`, `mosip_mock_registry`) and handle the `full_credential` JSONB migrations on the first run.

### 3. Backend Setup
Open a terminal and navigate to the backend directory:
```bash
cd backend
npm install
```
Create a .env file in the backend folder:

```
PORT=3000
DB_USER=postgres
DB_PASSWORD=your_postgres_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=atlasid
```
Start the server:

```Bash
npm start
```
(Note: A new issuer_keys.json file containing your cryptographic key pair will be generated automatically on the first run. Do NOT commit this file to version control).

4. Network Tunneling (Ngrok)
To allow your physical mobile device to reach your local backend through your Wi-Fi/Firewall, start an Ngrok tunnel in a new terminal:

```Bash
ngrok http 3000
```
Copy the secure forwarding URL (e.g., https://abcd-123.ngrok-free.app).

5. Frontend Setup
Open a third terminal and navigate to the frontend directory:

```Bash
cd wallet
npm install
```
Open src/services/WalletService.js and update the API_URL variable with your new Ngrok URL:


// Ensure there is NO trailing slash at the end of the URL
const API_URL = '[https://abcd-123.ngrok-free.app](https://abcd-123.ngrok-free.app)';
Start the Expo server and clear the cache:

```Bash
npx expo start -c
```
Scan the QR code printed in the terminal with your phone's camera (iOS) or the Expo Go app (Android) to launch the application.

📱 Application Flow
Sync Keys: Upon opening the Wallet tab, the app will automatically reach out to the backend to cache the active Public Key.

Issue Credential: Tap the + button to generate a mock MOSIP ID. The backend creates a strict deterministic payload, signs it with the Private Key, stores the full credential in Postgres, and returns it to the phone.

Verify: Switch to the Verifier tab. The scanner will instantly validate the Ed25519 signature of any presented AtlasID QR code entirely offline.

Cloud Sync: If you clear your local device memory, use the Cloud Sync button to securely restore your active IDs from the PostgreSQL database.

🧪 Testing & CI/CD
This repository includes a fully automated GitHub Actions pipeline. Upon pushing to main, the pipeline will automatically spin up an ephemeral PostgreSQL container to run the backend API tests.

To run the tests locally:

```Bash
cd backend
npm test
```
(Ensure your local PostgreSQL service is running before executing tests).
