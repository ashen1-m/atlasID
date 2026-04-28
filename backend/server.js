require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const { Pool }     = require('pg');
const { generateKeyPairSync, sign, createPublicKey } = require('crypto');
const EventEmitter = require('events');
const fs   = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────────────────────────────────────
//  EVENT BUS  — modules communicate via events, not direct calls
//  Implements the "Event-Driven Communication" from the architecture doc.
//  The offline Verifier never calls the bus — it relies on Ed25519 locally.
// ─────────────────────────────────────────────────────────────────────────────
const bus = new EventEmitter();

bus.on('USER_REGISTERED',     ({ name, did })            => console.log(`[bus] USER_REGISTERED     → ${name} (${did})`));
bus.on('CREDENTIAL_ISSUED',   ({ type, userId })         => console.log(`[bus] CREDENTIAL_ISSUED   → type=${type}  user=${userId}`));
bus.on('ENTITLEMENT_GRANTED', ({ aidType, value, currency }) => console.log(`[bus] ENTITLEMENT_GRANTED → ${aidType} ${value} ${currency}`));
bus.on('ENTITLEMENT_UPDATED', ({ entitlementId, status }) => console.log(`[bus] ENTITLEMENT_UPDATED → ${entitlementId} → ${status}`));
bus.on('IDENTITY_REVOKED',    ({ userId })               => console.log(`[bus] IDENTITY_REVOKED    → ${userId}`));

// ─────────────────────────────────────────────────────────────────────────────
//  ISSUER IDENTITY  (the backend has its own DID — Mock MOSIP adapter)
// ─────────────────────────────────────────────────────────────────────────────
const ISSUER_DID = 'did:atlas:issuer-mosip-mock';

// ─────────────────────────────────────────────────────────────────────────────
//  ISSUER KEY PAIR  (Ed25519 — persisted so the public key never changes)
// ─────────────────────────────────────────────────────────────────────────────
const KEYS_FILE = path.join(__dirname, 'issuer_keys.json');
let issuerPrivateKeyPem, issuerPublicKeyDer;

if (fs.existsSync(KEYS_FILE)) {
  const stored = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
  issuerPrivateKeyPem = stored.privateKey;
  issuerPublicKeyDer  = stored.publicKeyDer;
  console.log('🔑  Loaded existing issuer keypair');
} else {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding:  { type: 'spki',  format: 'pem' }
  });
  issuerPrivateKeyPem = privateKey;
  issuerPublicKeyDer  = createPublicKey(publicKey)
                          .export({ type: 'spki', format: 'der' })
                          .toString('base64');
  fs.writeFileSync(KEYS_FILE,
    JSON.stringify({ privateKey: issuerPrivateKeyPem, publicKeyDer: issuerPublicKeyDer })
  );
  console.log('🔑  Generated new issuer keypair → issuer_keys.json');
}

// ─────────────────────────────────────────────────────────────────────────────
//  DATABASE
// ─────────────────────────────────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Only do the initial connection test if we are NOT running Jest
if (process.env.NODE_ENV !== 'test') {
  pool.connect()
    .then(c => { c.release(); console.log('🗄️   PostgreSQL connected'); })
    .catch(e => console.error('❌  DB connection failed:', e.message));
}

// ─────────────────────────────────────────────────────────────────────────────
//  CRYPTO HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function signData(obj) {
  return sign(null, Buffer.from(JSON.stringify(obj)), issuerPrivateKeyPem).toString('base64');
}

function buildSigningPayload(id, userId, type, payload, issuedAt) {
  return { id, userId, type, payload, issuedAt }; // fixed key order — must match verifier
}

// ─────────────────────────────────────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/public-key', (req, res) => {
  res.json({ publicKey: issuerPublicKeyDer, issuerDid: ISSUER_DID });
});

// ══════════════════════════════════════════════════════════════
//  MODULE: ISSUANCE  (Mock MOSIP adapter + Identity Registry)
// ══════════════════════════════════════════════════════════════

app.post('/api/users/register', async (req, res) => {
  const { name, did, publicKey, dateOfBirth } = req.body;
  if (!name || !did)
    return res.status(400).json({ error: 'name and did are required' });
  try {
    await pool.query('BEGIN');

    const userResult = await pool.query(
      `INSERT INTO users (name, did, date_of_birth, status)
       VALUES ($1, $2, $3, 'Active') RETURNING id, enrollment_date`,
      [name, did, dateOfBirth || null]
    );
    const { id: userId, enrollment_date } = userResult.rows[0];

    if (publicKey) {
      await pool.query(
        'INSERT INTO public_keys (user_id, issuer_did, key_value) VALUES ($1, $2, $3)',
        [userId, ISSUER_DID, publicKey]
      );
    }

    await pool.query(
      'INSERT INTO logs (action, details) VALUES ($1, $2)',
      ['USER_REGISTERED', JSON.stringify({ userId, did, name })]
    );

    await pool.query('COMMIT');
    bus.emit('USER_REGISTERED', { userId, did, name });

    res.status(201).json({ message: 'User registered successfully', userId, did, name, enrollmentDate: enrollment_date });
  } catch (err) {
    await pool.query('ROLLBACK');
    if (err.code === '23505')
      return res.status(409).json({ error: 'A user with this DID already exists' });
    console.error(err);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

app.post('/api/credentials/issue', async (req, res) => {
  const { userId, type, payload } = req.body;
  if (!userId || !type || !payload)
    return res.status(400).json({ error: 'userId, type, and payload are required' });
  try {
    const credResult = await pool.query(
      'INSERT INTO credentials (user_id, issuer_did, type, payload) VALUES ($1, $2, $3, $4) RETURNING id, created_at',
      [userId, ISSUER_DID, type, JSON.stringify(payload)]
    );
    const { id: credentialId, created_at: issuedAt } = credResult.rows[0];

    const signature = signData(buildSigningPayload(credentialId, userId, type, payload, issuedAt));

    await pool.query('UPDATE credentials SET signature = $1 WHERE id = $2', [signature, credentialId]);

    await pool.query(
      'INSERT INTO logs (action, details) VALUES ($1, $2)',
      ['CREDENTIAL_ISSUED', JSON.stringify({ credentialId, type, userId, issuerDid: ISSUER_DID })]
    );

    bus.emit('CREDENTIAL_ISSUED', { credentialId, type, userId });

    res.status(201).json({
      message: 'Credential issued and signed successfully',
      credential: { id: credentialId, userId, issuerDid: ISSUER_DID, type, payload, issuedAt, signature }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to issue credential' });
  }
});

app.get('/api/credentials/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id AS "userId", issuer_did AS "issuerDid",
              type, payload, signature, created_at AS "issuedAt"
       FROM credentials WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.params.userId]
    );
    res.json({ credentials: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch credentials' });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, did, date_of_birth AS "dateOfBirth",
              enrollment_date AS "enrollmentDate", status
       FROM users ORDER BY enrollment_date DESC`
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.patch('/api/users/:id/status', async (req, res) => {
  const { status } = req.body;
  if (!['Active', 'Revoked'].includes(status))
    return res.status(400).json({ error: 'status must be Active or Revoked' });
  try {
    const result = await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2 RETURNING id, name, status',
      [status, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });

    await pool.query(
      'INSERT INTO logs (action, details) VALUES ($1, $2)',
      ['IDENTITY_STATUS_CHANGED', JSON.stringify({ userId: req.params.id, status })]
    );
    if (status === 'Revoked') bus.emit('IDENTITY_REVOKED', { userId: req.params.id });

    res.json({ message: `Identity ${status.toLowerCase()}`, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// ══════════════════════════════════════════════════════════════
//  MODULE: AID ENTITLEMENT
//  Matches PDF: Aid_Entitlement table with entitlement_id PK,
//  identity_id FK, aid_type, value DECIMAL, issued_at
// ══════════════════════════════════════════════════════════════

// Grant a new entitlement to an identity
app.post('/api/entitlements/grant', async (req, res) => {
  const { identityId, aidType, value, currency, periodStart, periodEnd, notes } = req.body;
  if (!identityId || !aidType || value === undefined)
    return res.status(400).json({ error: 'identityId, aidType, and value are required' });
  try {
    const userCheck = await pool.query(
      'SELECT id, name, status FROM users WHERE id = $1', [identityId]
    );
    if (!userCheck.rows.length)
      return res.status(404).json({ error: 'Identity not found' });
    if (userCheck.rows[0].status === 'Revoked')
      return res.status(403).json({ error: 'Cannot grant entitlement to a revoked identity' });

    const result = await pool.query(
      `INSERT INTO aid_entitlements
         (identity_id, aid_type, value, currency, period_start, period_end, status, notes)
       VALUES ($1, $2, $3, $4, $5, $6, 'Active', $7)
       RETURNING *`,
      [identityId, aidType, value, currency || 'USD', periodStart || null, periodEnd || null, notes || null]
    );
    const e = result.rows[0];

    await pool.query(
      'INSERT INTO logs (action, details) VALUES ($1, $2)',
      ['ENTITLEMENT_GRANTED', JSON.stringify({
        entitlementId: e.entitlement_id, identityId, aidType, value,
        currency: currency || 'USD', beneficiary: userCheck.rows[0].name
      })]
    );

    bus.emit('ENTITLEMENT_GRANTED', { entitlementId: e.entitlement_id, identityId, aidType, value, currency: e.currency });

    res.status(201).json({
      message: `${aidType} entitlement granted`,
      entitlement: {
        entitlementId: e.entitlement_id,
        identityId:    e.identity_id,
        aidType:       e.aid_type,
        value:         e.value,
        currency:      e.currency,
        periodStart:   e.period_start,
        periodEnd:     e.period_end,
        status:        e.status,
        issuedAt:      e.issued_at,
        notes:         e.notes
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to grant entitlement' });
  }
});

// Get all entitlements for one identity
app.get('/api/entitlements/:identityId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT entitlement_id AS "entitlementId", identity_id AS "identityId",
              aid_type AS "aidType", value, currency,
              period_start AS "periodStart", period_end AS "periodEnd",
              status, issued_at AS "issuedAt", notes
       FROM aid_entitlements
       WHERE identity_id = $1 ORDER BY issued_at DESC`,
      [req.params.identityId]
    );
    res.json({ entitlements: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch entitlements' });
  }
});

// Update entitlement status (Active → Suspended | Exhausted | Expired)
app.patch('/api/entitlements/:entitlementId/status', async (req, res) => {
  const { status } = req.body;
  const allowed = ['Active', 'Suspended', 'Exhausted', 'Expired'];
  if (!allowed.includes(status))
    return res.status(400).json({ error: `status must be one of: ${allowed.join(', ')}` });
  try {
    const result = await pool.query(
      'UPDATE aid_entitlements SET status = $1 WHERE entitlement_id = $2 RETURNING *',
      [status, req.params.entitlementId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Entitlement not found' });

    await pool.query(
      'INSERT INTO logs (action, details) VALUES ($1, $2)',
      ['ENTITLEMENT_UPDATED', JSON.stringify({ entitlementId: req.params.entitlementId, status })]
    );
    bus.emit('ENTITLEMENT_UPDATED', { entitlementId: req.params.entitlementId, status });

    res.json({ message: `Status updated to ${status}`, entitlement: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update entitlement' });
  }
});

// Admin: all entitlements with beneficiary name joined
app.get('/api/entitlements', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ae.entitlement_id AS "entitlementId", ae.identity_id AS "identityId",
              u.name AS "beneficiaryName", u.did AS "beneficiaryDid",
              ae.aid_type AS "aidType", ae.value, ae.currency,
              ae.period_start AS "periodStart", ae.period_end AS "periodEnd",
              ae.status, ae.issued_at AS "issuedAt", ae.notes
       FROM aid_entitlements ae
       JOIN users u ON u.id = ae.identity_id
       ORDER BY ae.issued_at DESC`
    );
    res.json({ entitlements: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch entitlements' });
  }
});

// ══════════════════════════════════════════════════════════════
//  AUDIT LOG
// ══════════════════════════════════════════════════════════════

app.get('/api/logs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50');
    res.json({ logs: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// ══════════════════════════════════════════════════════════════
//  LANDING PAGE
// ══════════════════════════════════════════════════════════════

// Serve the Wallet UI from the 'wallet' folder
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../wallet/index.html'));
});

const PORT = process.env.PORT || 3000;
// Only start the server if this file is run directly (not imported by tests)
if (require.main === module) {
  app.listen(PORT, () =>
    console.log(`\n🚀  AtlasID Backend → http://localhost:${PORT}\n`)
  );
}

app.pool = pool; // Expose the database pool
module.exports = app; // Export for testing // Export for testing
