const request = require('supertest');
const { app, pool, initDB } = require('../server');

const TEST_UID = 'mosip-uid-test-999';
let server; 

describe('AtlasID Backend API Tests', () => {


  beforeAll(async () => {
    await initDB();
    server = app.listen(3000); 
  });


  afterAll(async () => {
    await pool.end();
    server.close();
  });


  describe('GET /api/public-key', () => {
    it('should return the cryptographic public key and issuer DID', async () => {
      const response = await request(app).get('/api/public-key');
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toHaveProperty('publicKey');
      expect(response.body).toHaveProperty('issuerDid');
      expect(typeof response.body.publicKey).toBe('string');
    });
  });

  describe('POST /mock-mosip/ida/auth', () => {
    it('should reject authentication if UID is missing', async () => {
      const response = await request(app)
        .post('/mock-mosip/ida/auth')
        .send({});
      
      expect(response.statusCode).toBe(400);
      expect(response.body.authStatus).toBe(false);
    });

    // Note: The successful auth test usually happens implicitly 
    // during the issuance test since the backend auto-registers the user.
  });

  describe('POST /api/credentials/issue', () => {
    it('should fail if required fields are missing', async () => {
      const response = await request(app)
        .post('/api/credentials/issue')
        .send({ userId: TEST_UID }); // Missing type and payload
      
      expect(response.statusCode).toBe(400);
      expect(response.body.error).toBe('Missing required fields');
    });

    it('should issue a credential with the correct deterministic shape', async () => {
      const response = await request(app)
        .post('/api/credentials/issue')
        .send({
          userId: TEST_UID,
          type: 'Refugee_Status',
          payload: { name: 'Test User', origin: 'Morocco' }
        });
      
      expect(response.statusCode).toBe(201);
      
      const cred = response.body.credential;
      expect(cred).toBeDefined();

      // Check for the exact shape required by the React Native verifier
      expect(cred).toHaveProperty('id');
      expect(cred).toHaveProperty('userId', TEST_UID); // Must be camelCase
      expect(cred).toHaveProperty('type', 'Refugee_Status');
      expect(cred.payload).toHaveProperty('name', 'Test User');
      expect(cred.payload).toHaveProperty('origin', 'Morocco');
      expect(cred).toHaveProperty('issuedAt');
      expect(cred).toHaveProperty('signature');

      // Verify the ID is a valid URN UUID
      expect(cred.id).toMatch(/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    });
  });

  describe('GET /api/credentials/:userId', () => {
    it('should return the full_credential objects for a user', async () => {
      const response = await request(app).get(`/api/credentials/${TEST_UID}`);
      
      expect(response.statusCode).toBe(200);
      expect(Array.isArray(response.body.credentials)).toBe(true);
      expect(response.body.credentials.length).toBeGreaterThan(0);

      // Validate that the returned object is the pristine signed shape, not raw SQL columns
      const firstCred = response.body.credentials[0];
      expect(firstCred).toHaveProperty('userId', TEST_UID);
      expect(firstCred).toHaveProperty('issuedAt');
      expect(firstCred).toHaveProperty('signature');
      expect(firstCred.user_id).toBeUndefined(); // Should NOT contain snake_case SQL columns
    });
  });

  describe('DELETE /api/credentials/clear/:userId', () => {
    it('should completely wipe the cloud database for the user', async () => {
      const response = await request(app).delete(`/api/credentials/clear/${TEST_UID}`);
      
      expect(response.statusCode).toBe(200);
      expect(response.body.message).toBe('Cloud credentials completely wiped.');

      // Verify the wipe worked by fetching again
      const checkResponse = await request(app).get(`/api/credentials/${TEST_UID}`);
      expect(checkResponse.statusCode).toBe(200);
      expect(checkResponse.body.credentials.length).toBe(0);
    });
  });

});