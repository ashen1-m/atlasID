const request = require('supertest');
const app = require('../backend/server.js'); 

describe('AtlasID Core API', () => {
  
  // Clean up the database connection after tests finish
  afterAll(async () => {
    await app.pool.end();
  });

  it('should return the issuer public key and DID', async () => {
    const response = await request(app).get('/api/public-key');
    
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty('publicKey');
    expect(response.body).toHaveProperty('issuerDid');
    expect(response.body.issuerDid).toBe('did:atlas:issuer-mosip-mock');
  });
});