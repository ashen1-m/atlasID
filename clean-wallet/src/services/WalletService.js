import AsyncStorage from '@react-native-async-storage/async-storage';
import * as tweetnacl from 'tweetnacl';

const CREDENTIALS_KEY = '@atlas_credentials';
const PUB_KEY_CACHE = '@atlas_issuer_pub_key';

// 🛑 Put your EXACT Ngrok URL here (No slash at the end!)
const API_URL = 'https://request-tidbit-garnet.ngrok-free.dev'; 

const getHeaders = () => ({
  'Content-Type': 'application/json',
  'ngrok-skip-browser-warning': 'true' 
});

const encodeUTF8 = (str) => {
  const arr = [];
  for (let i = 0; i < str.length; i++) {
    let charcode = str.charCodeAt(i);
    if (charcode < 0x80) arr.push(charcode);
    else if (charcode < 0x800) { arr.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f)); }
    else { arr.push(0xe0 | (charcode >> 12), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f)); }
  }
  return new Uint8Array(arr);
};

const decodeBase64 = (base64) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let bufferLength = base64.length * 0.75;
  if (base64[base64.length - 1] === '=') bufferLength--;
  if (base64[base64.length - 2] === '=') bufferLength--;
  const bytes = new Uint8Array(bufferLength);
  let p = 0;
  for (let i = 0; i < base64.length; i += 4) {
    let e1 = chars.indexOf(base64[i]), e2 = chars.indexOf(base64[i+1]);
    let e3 = chars.indexOf(base64[i+2]), e4 = chars.indexOf(base64[i+3]);
    bytes[p++] = (e1 << 2) | (e2 >> 4);
    if (e3 !== 64) bytes[p++] = ((e2 & 15) << 4) | (e3 >> 2);
    if (e4 !== 64) bytes[p++] = ((e3 & 3) << 6) | (e4 & 63);
  }
  return bytes;
};

export const WalletService = {
  
  async syncIssuerConfig() {
    try {
      const response = await fetch(`${API_URL}/api/public-key`, {
        method: 'GET',
        headers: {
          ...getHeaders(),
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        } 
      });
      
      if (!response.ok) throw new Error(`Server returned status: ${response.status}`);
      
      const data = await response.json();
      
      if (!data || !data.publicKey) {
        throw new Error("Server connected, but the public key was missing from the response.");
      }

      await AsyncStorage.setItem(PUB_KEY_CACHE, data.publicKey);
      return data.publicKey;
      
    } catch (error) {
      console.error("RAW NETWORK ERROR:", error);
      throw error; 
    }
  },

  async getCachedPublicKey() {
    return await AsyncStorage.getItem(PUB_KEY_CACHE);
  },

  async issueCredential(userId, type, payload) {
    const response = await fetch(`${API_URL}/api/credentials/issue`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ userId, type, payload }) 
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Failed to issue credential');
    }
    
    const data = await response.json();
    // data.credential is already the full signed shape: { id, userId, type, payload, issuedAt, signature }
    await this.saveCredential(data.credential); 
    return data;
  },

  async syncFromServer(userId) {
    const response = await fetch(`${API_URL}/api/credentials/${userId}`, {
      method: 'GET',
      headers: getHeaders()
    });
    if (!response.ok) throw new Error('Failed to sync');
    const data = await response.json();
    // FIX: server now returns full signed credential objects, so we store them as-is.
    // Each item has { id, userId, type, payload, issuedAt, signature } — exactly what verifyOffline needs.
    await AsyncStorage.setItem(CREDENTIALS_KEY, JSON.stringify(data.credentials));
    return data.credentials;
  },

  async clearCloudDatabase(userId) {
    const response = await fetch(`${API_URL}/api/credentials/clear/${userId}`, {
      method: 'DELETE',
      headers: getHeaders()
    });
    if (!response.ok) throw new Error('Failed to wipe cloud data');
    return true;
  },

  async saveCredential(credential) {
    const existing = await this.getCredentials();
    // Avoid duplicates if the same credential id already exists locally
    const deduped = existing.filter(c => c.id !== credential.id);
    const updated = [credential, ...deduped];
    await AsyncStorage.setItem(CREDENTIALS_KEY, JSON.stringify(updated));
    return true;
  },

  async getCredentials() {
    const data = await AsyncStorage.getItem(CREDENTIALS_KEY);
    return data ? JSON.parse(data) : [];
  },

  // FIX: Reconstruct dataToVerify using the EXACT same field order and keys as the server used when signing.
  // Server signs: JSON.stringify({ id, userId, type, payload, issuedAt })
  // We must build the same object with the same keys in the same order.
  verifyOffline(qrPayload, issuerPublicKeyBase64) {
    try {
      if (!issuerPublicKeyBase64) throw new Error("No public key available");

      const { id, userId, type, payload, issuedAt, signature } = qrPayload;

      // Guard: all fields that were signed must be present
      if (!id || !userId || !type || !payload || !issuedAt || !signature) {
        console.error("verifyOffline: QR payload is missing required fields", { id, userId, type, payload, issuedAt, signature: !!signature });
        return false;
      }

      // FIX: Build the object in the EXACT same key order the server used
      const dataToVerify = JSON.stringify({ id, userId, type, payload, issuedAt });

      const messageUint8 = encodeUTF8(dataToVerify);
      const signatureUint8 = decodeBase64(signature);
      const pubKeyUint8 = decodeBase64(issuerPublicKeyBase64);

      const result = tweetnacl.sign.detached.verify(messageUint8, signatureUint8, pubKeyUint8);
      if (!result) {
        // Log the reconstructed string to help debug future mismatches
        console.warn("verifyOffline: signature mismatch. dataToVerify =", dataToVerify);
      }
      return result;
    } catch (error) {
      console.error("Crypto verification failed:", error);
      return false;
    }
  }
};