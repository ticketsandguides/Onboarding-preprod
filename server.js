require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const _sodium = require('libsodium-wrappers');
const axios = require('axios');
const { createAuthorizationHeader, isHeaderValid } = require('ondc-crypto-sdk-nodejs');

// Configuration
const port = process.env.PORT || 3000;
const ONDC_LOOKUP_URL = process.env.ONDC_LOOKUP_URL;
const SUBSCRIBER_ID = process.env.SUBSCRIBER_ID;
const CALLBACK_URL = process.env.CALLBACK_URL;
const REQUEST_ID = process.env.REQUEST_ID;
const UNIQUE_KEY_ID = process.env.UNIQUE_KEY_ID;
const GST_NO = process.env.GST_NO;


const htmlFile = `
<!--Contents of ondc-site-verification.html. -->
<html>
  <head>
    <meta
      name="ondc-site-verification"
      content="SIGNED_UNIQUE_REQ_ID"
    />
  </head>
  <body>
    ONDC Site Verification Page
  </body>
</html>
`;

// Validate environment variables
const requiredEnvVars = [
  'ENCRYPTION_PRIVATE_KEY',
  'ONDC_PUBLIC_KEY',
  'SIGNING_PRIVATE_KEY',
  'REQUEST_ID',
  'UNIQUE_KEY_ID',
  'ONDC_SUBSCRIBE_URL',
  'ONDC_LOOKUP_URL',
  'SUBSCRIBER_ID',
  'SUBSCRIBER_URL', // Ensure SUBSCRIBER_URL is present
  'CALLBACK_URL',
  'EMAIL_ID',
  'MOBILE_NO',
  'COUNTRY',
  'PAN_NO',
  'PAN_NAME',
  'PAN_DATE_OF_INCORPORATION',
  'NAME_OF_AUTHORISED_SIGNATORY',
  'ADDRESS_OF_AUTHORISED_SIGNATORY',
  'LEGAL_ENTITY_NAME',
  'BUSINESS_ADDRESS',
  'GST_NO',
  'DOMAIN',
  'CITY_CODE',
];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`[${new Date().toISOString()}] Error: Missing required environment variable ${envVar}`);
    process.exit(1);
  }
}

// Validate CALLBACK_URL format (still expects a relative URL starting with '/')
// The validation for SUBSCRIBER_URL is removed as it will now be an absolute URL
if (!CALLBACK_URL.match(/^\/[a-zA-Z0-9\/]*$/)) {
  console.error(`[${new Date().toISOString()}] Error: CALLBACK_URL must be a relative URL starting with '/', got ${CALLBACK_URL}`);
  process.exit(1);
}

// Validate GST_NO format (15 characters, alphanumeric)
if (!GST_NO.match(/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/)) {
  console.error(`[${new Date().toISOString()}] Error: GST_NO must be a valid 15-character GST number, got ${GST_NO}`);
  process.exit(1);
}

// Initialize keys
let privateKey, publicKey, sharedKey;
try {
  privateKey = crypto.createPrivateKey({
    key: Buffer.from(process.env.ENCRYPTION_PRIVATE_KEY, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });

  publicKey = crypto.createPublicKey({
    key: Buffer.from(process.env.ONDC_PUBLIC_KEY, 'base64'),
    format: 'der',
    type: 'spki',
  });

  // Derive shared key using Diffie-Hellman
  sharedKey = crypto.diffieHellman({
    privateKey: privateKey,
    publicKey: publicKey,
  });
  console.log(`[${new Date().toISOString()}] Key initialization successful`);
} catch (error) {
  console.error(`[${new Date().toISOString()}] Error: Failed to initialize keys, error=${error.message}`);
  process.exit(1);
}

// Helper function to get UTC timestamp
function getUTCTimestamp() {
  const now = new Date();
  return now.toISOString(); // e.g., 2025-06-02T18:03:00.000Z
}

// Helper function to get future UTC timestamp
function getFutureUTCTimestamp(yearsFromNow = 1) {
  const now = new Date();
  const futureDate = new Date(now.getTime() + yearsFromNow * 365 * 24 * 60 * 60 * 1000);
  return futureDate.toISOString(); // e.g., 2026-06-02T18:03:00.000Z
}

// Create Express app
const app = express();
app.use(bodyParser.json());


// ondc-site-verification.html endpoint
app.get('/ondc-site-verification.html', async (req, res) => {
  console.log(`[${new Date().toISOString()}] /ondc-site-verification.html: Serving ONDC site verification file, request_id=${REQUEST_ID}`);

  try {
    const signedContent = await signMessage(REQUEST_ID, process.env.SIGNING_PRIVATE_KEY);
    console.log(`[${new Date().toISOString()}] /ondc-site-verification.html: Site verification file generated, request_id=${REQUEST_ID}, signed_content=${signedContent}`);

    const modifiedHTML = htmlFile.replace(/SIGNED_UNIQUE_REQ_ID/g, signedContent);
    res.set('Content-Type', 'text/html');
    res.send(modifiedHTML);
  } catch (error) {
    console.error(`[${new Date().toISOString()}] /ondc-site-verification.html: Failed to serve site verification file, request_id=${REQUEST_ID}, error=${error.message}`);
    res.status(500).send('Internal server error');
  }
});

// Default route
app.get('/', (req, res) => {
  console.log(`[${new Date().toISOString()}] /: Received request to default route`);
  res.send('ONDC Onboarding is live');
});

// Health check route
app.get('/health', (req, res) => {
  console.log(`[${new Date().toISOString()}] /health: Health check requested`);
  res.send('Health OK!!');
});


// Start server
app.listen(port, () => {
  console.log(`[${new Date().toISOString()}] Server started on port ${port}`);
});

// Decrypt using AES-256-ECB
function decryptAES256ECB(key, encrypted) {
  try {
    const iv = Buffer.alloc(0); // ECB doesn't use IV
    const decipher = crypto.createDecipheriv('aes-256-ecb', key, iv);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    console.log(`[${new Date().toISOString()}] decryptAES256ECB: Decryption successful`);
    return decrypted;
  } catch (error) {
    console.error(`[${new Date().toISOString()}] decryptAES256ECB: Decryption failed, error=${error.message}`);
    throw new Error('Failed to decrypt challenge');
  }
}

// Sign message using Ed25519
async function signMessage(signingString, privateKey) {
  try {
    await _sodium.ready;
    const sodium = _sodium;
    const signedMessage = sodium.crypto_sign_detached(
      signingString,
      sodium.from_base64(privateKey, sodium.base64_variants.ORIGINAL),
    );
    const signature = sodium.to_base64(signedMessage, sodium.base64_variants.ORIGINAL);
    console.log(`[${new Date().toISOString()}] signMessage: Message signed successfully, signingString=${signingString}`);
    return signature;
  } catch (error) {
    console.error(`[${new Date().toISOString()}] signMessage: Failed to sign message, error=${error.message}`);
    throw new Error('Failed to sign message');
  }
}
