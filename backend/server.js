require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const tweetnacl = require('tweetnacl');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// --- Database Connection ---
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'atlasid',
  password: process.env.DB_PASSWORD || 'postgres',
  port: process.env.DB_PORT || 5432,
});

// Auto-initialize tables
const initDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mosip_mock_registry (
        uid VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        origin VARCHAR(255),
        status VARCHAR(50)
      );
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        did VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS credentials (
        id UUID PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(100) NOT NULL,
        payload JSONB NOT NULL,
        signature TEXT,
        issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        -- FIX: store the full signed credential so GET can return it faithfully
        full_credential JSONB
      );
    `);
    // Migration: add full_credential column if it doesn't exist yet (safe to run on existing DBs)
    await pool.query(`
      ALTER TABLE credentials ADD COLUMN IF NOT EXISTS full_credential JSONB;
      ALTER TABLE credentials ADD COLUMN IF NOT EXISTS issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    `).catch(() => {}); // ignore if already exists
    console.log("✅ PostgreSQL Tables Verified");
  } catch (err) {
    console.error("Database initialization failed:", err.message);
  }
};
initDB();

// ==========================================
// 🔐 PERSISTENT CRYPTOGRAPHY SETUP
// ==========================================
const KEYS_FILE = './issuer_keys.json';
let privateKey, publicKeyBase64;

if (fs.existsSync(KEYS_FILE)) {
  const keys = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
  privateKey = new Uint8Array(Buffer.from(keys.privateKey, 'base64'));
  publicKeyBase64 = keys.publicKey;
  console.log("🔑 Loaded existing cryptographic keys from issuer_keys.json");
} else {
  const keyPair = tweetnacl.sign.keyPair();
  privateKey = keyPair.secretKey;
  publicKeyBase64 = Buffer.from(keyPair.publicKey).toString('base64');
  
  fs.writeFileSync(KEYS_FILE, JSON.stringify({
    privateKey: Buffer.from(privateKey).toString('base64'),
    publicKey: publicKeyBase64
  }, null, 2));
  console.log("🔑 Generated NEW keys and saved to issuer_keys.json");
}

const ISSUER_DID = 'did:atlas:issuer-mosip';

const toUUID = (str) => {
  const hash = crypto.createHash('md5').update(str).digest('hex');
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20)}`;
};

// ==========================================
// 🌐 API ROUTES
// ==========================================
app.get('/api/public-key', (req, res) => {
  res.status(200).json({ publicKey: publicKeyBase64, issuerDid: ISSUER_DID });
});

app.post('/mock-mosip/ida/auth', async (req, res) => {
  const { uid } = req.body;
  if (!uid) return res.status(400).json({ authStatus: false, errors: ["Missing UID"] });

  try {
    const result = await pool.query(`SELECT * FROM mosip_mock_registry WHERE uid = $1`, [uid]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      res.json({
        authStatus: true,
        kycData: { name: user.name, origin: user.origin, status: user.status }
      });
    } else {
      res.status(404).json({ authStatus: false, errors: ["UID not found"] });
    }
  } catch (error) {
    res.status(500).json({ authStatus: false, errors: ["Database error"] });
  }
});

app.post('/api/credentials/issue', async (req, res) => {
  try {
    const { userId, type, payload } = req.body; 
    if (!userId || !type || !payload) return res.status(400).json({ error: "Missing required fields" });

    await pool.query(
      `INSERT INTO mosip_mock_registry (uid, name, origin, status) 
       VALUES ($1, $2, $3, 'Active') 
       ON CONFLICT (uid) DO UPDATE 
       SET name = EXCLUDED.name, origin = EXCLUDED.origin`,
      [userId, payload.name, payload.origin || 'Unknown']
    );

    const PORT = process.env.PORT || 3000;
    const mosipUrl = process.env.MOSIP_BASE_URL || `http://127.0.0.1:${PORT}/mock-mosip/ida/auth`;
    const mosipRes = await axios.post(mosipUrl, { uid: userId });

    if (!mosipRes.data.authStatus) return res.status(401).json({ error: "MOSIP Auth Failed" });

    const verifiedPayload = mosipRes.data.kycData; 
    const rawCredId = crypto.randomUUID();

    // FIX: This is the EXACT object that gets signed. Shape must never change.
    // userId (camelCase) and issuedAt must be present — verifyOffline depends on them.
    const credentialBase = {
      id: `urn:uuid:${rawCredId}`,
      userId,           // ← camelCase, matches WalletService.verifyOffline
      type,
      payload: verifiedPayload,
      issuedAt: new Date().toISOString()   // ← must exist, matches verifyOffline
    };

    const dataToSign = JSON.stringify(credentialBase);
    const signatureUint8 = tweetnacl.sign.detached(new TextEncoder().encode(dataToSign), privateKey);
    const signature = Buffer.from(signatureUint8).toString('base64');
    
    // FIX: finalCredential is the full object clients will store and present for QR scanning
    const finalCredential = { ...credentialBase, signature };
    
    const dbUserId = toUUID(userId);
    const readableDid = `did:atlas:${userId}`; 

    await pool.query(
      `INSERT INTO users (id, name, did) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
      [dbUserId, verifiedPayload.name, readableDid]
    );

    // FIX: Store full_credential so GET /api/credentials/:userId can return the exact signed shape
    await pool.query(
      `INSERT INTO credentials (id, user_id, type, payload, signature, issued_at, full_credential)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        rawCredId,
        dbUserId,
        type,
        JSON.stringify(verifiedPayload),
        signature,
        credentialBase.issuedAt,
        JSON.stringify(finalCredential)   // ← store the complete signed object
      ]
    );

    res.status(201).json({ credential: finalCredential });
  } catch (error) {
    console.error("Issuance error:", error);
    res.status(500).json({ error: "Issuance error" });
  }
});

// FIX: Return full_credential (the original signed shape) instead of raw DB columns.
// This ensures userId/issuedAt/signature are all present and match what was signed.
app.get('/api/credentials/:userId', async (req, res) => {
  try {
    const dbUserId = toUUID(req.params.userId);
    const result = await pool.query(
      'SELECT full_credential FROM credentials WHERE user_id = $1 ORDER BY issued_at DESC',
      [dbUserId]
    );
    // full_credential is JSONB so it comes back already parsed
    const credentials = result.rows.map(r => r.full_credential);
    res.status(200).json({ credentials });
  } catch (error) {
    res.status(500).json({ error: "Fetch error" });
  }
});

app.delete('/api/credentials/clear/:userId', async (req, res) => {
  try {
    const dbUserId = toUUID(req.params.userId);
    await pool.query('DELETE FROM credentials WHERE user_id = $1', [dbUserId]);
    res.status(200).json({ message: "Cloud credentials completely wiped." });
  } catch (error) {
    console.error("Wipe error:", error);
    res.status(500).json({ error: "Failed to wipe cloud database" });
  }
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '0.0.0.0', () => console.log(`Backend online on port ${PORT}`));
}

// Change this line at the bottom:
module.exports = { app, pool, initDB };