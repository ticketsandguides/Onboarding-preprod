require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const _sodium = require('libsodium-wrappers');
const axios = require('axios');
const { createAuthorizationHeader, isHeaderValid } = require('ondc-crypto-sdk-nodejs');

// Configuration
const port = process.env.PORT || 3000;
const ONDC_SUBSCRIBE_URL = process.env.ONDC_SUBSCRIBE_URL;
const ONDC_LOOKUP_URL = process.env.ONDC_LOOKUP_URL;
const SUBSCRIBER_ID = process.env.SUBSCRIBER_ID;
const SUBSCRIBER_URL = process.env.SUBSCRIBER_URL; // This will now be https://stage.ticketsandguides.com/bapl
const CALLBACK_URL = process.env.CALLBACK_URL;
const REQUEST_ID = process.env.REQUEST_ID;
const UNIQUE_KEY_ID = process.env.UNIQUE_KEY_ID;
const EMAIL_ID = process.env.EMAIL_ID;
const MOBILE_NO = process.env.MOBILE_NO;
const COUNTRY = process.env.COUNTRY;
const PAN_NO = process.env.PAN_NO;
const PAN_NAME = process.env.PAN_NAME;
const PAN_DATE_OF_INCORPORATION = process.env.PAN_DATE_OF_INCORPORATION;
const NAME_OF_AUTHORISED_SIGNATORY = process.env.NAME_OF_AUTHORISED_SIGNATORY;
const ADDRESS_OF_AUTHORISED_SIGNATORY = process.env.ADDRESS_OF_AUTHORISED_SIGNATORY;
const LEGAL_ENTITY_NAME = process.env.LEGAL_ENTITY_NAME;
const BUSINESS_ADDRESS = process.env.BUSINESS_ADDRESS;
const GST_NO = process.env.GST_NO;
const DOMAIN = process.env.DOMAIN;
const CITY_CODE = process.env.CITY_CODE;

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

// Subscribe endpoint (sends request to ONDC Registry)
app.post('/subscribe', async (req, res) => {
  console.log(`[${new Date().toISOString()}] /subscribe: Received subscription request, request_id=${REQUEST_ID}`);
 
  try {
    // Generate timestamps
    const validFrom = getUTCTimestamp();
    const validUntil = getFutureUTCTimestamp(1);
    const timestamp = getUTCTimestamp();

    console.log(`[${new Date().toISOString()}] /subscribe: Generated timestamps, valid_from=${validFrom}, valid_until=${validUntil}, timestamp=${timestamp}`);

    // Prepare subscription payload according to schema
    const payload = {
      context: {
        operation: {
          ops_no: 1
        }
      },
      message: {
        request_id: REQUEST_ID, // Using env variable for consistency
        timestamp: timestamp,
        entity: {
          gst: {
            legal_entity_name: LEGAL_ENTITY_NAME, // Using env variable
            business_address: BUSINESS_ADDRESS, // Using env variable
            city_code: [
              CITY_CODE // Using env variable
            ],
            gst_no: GST_NO // Using env variable
          },
          pan: {
            name_as_per_pan: PAN_NAME, // Using env variable
            pan_no: PAN_NO, // Using env variable
            date_of_incorporation: PAN_DATE_OF_INCORPORATION // Using env variable
          },
          name_of_authorised_signatory: NAME_OF_AUTHORISED_SIGNATORY, // Using env variable
          address_of_authorised_signatory: ADDRESS_OF_AUTHORISED_SIGNATORY, // Using env variable
          email_id: EMAIL_ID, // Using env variable
          mobile_no: parseInt(MOBILE_NO), // Ensure mobile_no is an integer
          country: COUNTRY, // Using env variable
          subscriber_id: SUBSCRIBER_ID, // Using env variable
          unique_key_id: UNIQUE_KEY_ID, // Using env variable
          callback_url: CALLBACK_URL, // Using env variable
          key_pair: {
            signing_public_key: process.env.SIGNING_PUBLIC_KEY, // Assuming this exists or is derived
            encryption_public_key: process.env.ENCRYPTION_PUBLIC_KEY, // Assuming this exists or is derived
            valid_from: validFrom,
            valid_until: validUntil
          }
        },
        network_participant: [
          {
            subscriber_url: "/bapl", // Changed to use the SUBSCRIBER_URL variable
            domain: DOMAIN, // Using env variable
            type: "buyerApp",
            msn: false,
            city_code: [
              CITY_CODE // Using env variable
            ]
          }
        ]
      }
    };

    console.log(`[${new Date().toISOString()}] /subscribe: Sending subscription request to ONDC Registry (${ONDC_SUBSCRIBE_URL}), payload=`, JSON.stringify(payload, null, 2));

    // Send subscription request to ONDC Registry
    const response = await axios.post(ONDC_SUBSCRIBE_URL, payload, {
      headers: { 'Content-Type': 'application/json' },
    });

    // Log the full response from ONDC Registry
    console.log(`[${new Date().toISOString()}] /subscribe: Subscription request successful, response=`, JSON.stringify(response.data, null, 2));

    res.status(200).json({
      message: 'Subscription request sent successfully to ONDC Registry',
      data: response.data,
    });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] /subscribe: Failed to send subscription request, error=${error.message}`, error.response?.data);
    res.status(500).json({ error: 'Failed to send subscription request', details: error.response?.data });
  }
});

// Endpoint for CALLBACK_URL=/ondc/onboarding
app.post(`${CALLBACK_URL}/on_subscribe`, (req, res) => { // Changed to use CALLBACK_URL variable
  console.log(`[${new Date().toISOString()}] ${CALLBACK_URL}/on_subscribe: Received challenge from ONDC Registry, request_id=${REQUEST_ID}, body=`, req.body);

  try {
    const { subscriber_id, challenge } = req.body;
    if (!challenge) {
      console.warn(`[${new Date().toISOString()}] ${CALLBACK_URL}/on_subscribe: Challenge missing in request body, request_id=${REQUEST_ID}, subscriber_id=${subscriber_id}`);
      return res.status(400).json({ error: 'Challenge is required' });
    }

    console.log(`[${new Date().toISOString()}] ${CALLBACK_URL}/on_subscribe: Processing challenge for subscriber_id=${subscriber_id}`);

    const answer = decryptAES256ECB(sharedKey, challenge);
    console.log(`[${new Date().toISOString()}] ${CALLBACK_URL}/on_subscribe: Challenge decrypted successfully, request_id=${REQUEST_ID}, answer=${answer}`);

    res.status(200).json({ answer });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] ${CALLBACK_URL}/on_subscribe: Failed to process challenge, request_id=${REQUEST_ID}, error=${error.message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// vlookup endpoint (queries ONDC Registry for subscriber details)
// /lookup endpoint using /v2.0/lookup with Ed25519 Authorization header
app.post('/lookup', async (req, res) => {
  console.log(`[${new Date().toISOString()}] /lookup: Received lookup request`);
 
  const {subscriber_id, country, city, domain, type} = req.body;
 
  try {
    const body = {
      subscriber_id: subscriber_id,
      country: country,
      city: city,
      domain: domain,
      type: type
    }
   const authHeader = await createAuthorizationHeader({
      body: JSON.stringify(body),
      privateKey: process.env.SIGNING_PRIVATE_KEY,
      subscriberId: SUBSCRIBER_ID,
      subscriberUniqueKeyId: UNIQUE_KEY_ID,
    });

    console.log("body: ",JSON.stringify(body))

    console.log("authHeader: ", authHeader)

    const isValid = await isHeaderValid({
      header: authHeader,
      body: JSON.stringify(body),
      publicKey: process.env.ONDC_PUBLIC_KEY,
    });


    console.log("is valid header: ", isValid)

    const response = await axios.post(
      ONDC_LOOKUP_URL, // Should be set to https://<env>.registry.ondc.org/v2.0/lookup in .env
      JSON.stringify(body),
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: authHeader,
        },
      }
    );

    console.log(`[${new Date().toISOString()}] /lookup: Lookup successful, response=`, response.data);
    res.status(200).json(response.data);
  } catch (error) {
    console.error(`[${new Date().toISOString()}] /lookup: Lookup failed, error=${error.message}`, error.response?.data);
    res.status(500).json({ error: 'Failed to perform lookup', details: error.response?.data });
  }
});



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

// Search endpoint to initiate ONDC search
app.post("/search", async (req, res) => {
 
    const { country, city, message } = req.body;

    if(!country || !city || !message){
        return res.status(500).json({
      error: "Search request failed",
      details: "missing items in request body",
    });
    }

  const timestamp = new Date().toISOString();
  const transactionId = crypto.randomUUID();
  const messageId = crypto.randomUUID();

  const payload = {
    context: {
      domain: DOMAIN,
      location: {
        country: { code: country },
        city: { code: city },
      },
      timestamp: timestamp,
      bap_id: SUBSCRIBER_ID,
      transaction_id: transactionId,
      message_id: messageId,
      version: "2.0.0",
      action: "search",
      bap_uri: SUBSCRIBER_URL, // This already correctly uses the SUBSCRIBER_URL variable
      ttl: "PT30S",
    },
    message: message
  };

  console.log(
    `[${new Date().toISOString()}] /search: Final payload=`,
    JSON.stringify(payload, null, 2)
  );

  try {
    const authHeader = await createAuthorizationHeader({
      body: JSON.stringify(payload),
      privateKey: process.env.SIGNING_PRIVATE_KEY,
      subscriberId: SUBSCRIBER_ID,
      subscriberUniqueKeyId: UNIQUE_KEY_ID,
    });
    console.log("public key = ", process.env.REQUEST_PUBLIC_KEY);
    const isValid = await isHeaderValid({
      header: authHeader,
      body: JSON.stringify(payload),
      publicKey: process.env.REQUEST_PUBLIC_KEY,
    });

    console.log(`[${new Date().toISOString()}] /search: isValidHeader=${isValid}`);

    if(!isValid){
         return res.status(500).json({
      error: "Search request failed",
      details: "Invalid authHeader",
    });
    }

    console.log(`[${new Date().toISOString()}] /search: AuthHeader=`, authHeader);

    const response = await axios.post(
      "https://staging.gateway.proteantech.in/search",
      JSON.stringify(payload),
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: authHeader,
        },
      }
    );

    console.log(
      `[${new Date().toISOString()}] /search: Search successful, response=`,
      JSON.stringify(response.data)
    );

    res.status(200).json({
      message: "Search request sent successfully to ONDC gateway",
      data: response.data,
    });
  } catch (error) {
    console.error(
      `[${new Date().toISOString()}] /search: Search failed, error=${error.message}`,
      error.response?.data
    );
    res.status(500).json({
      error: "Search request failed",
      details: error.response?.data || error.message,
    });
  }
});


// On_search endpoint to receive ONDC search results
app.post(`${new URL(SUBSCRIBER_URL).pathname}/on_search`, async (req, res) => { // Dynamically extracting path from SUBSCRIBER_URL
  console.log(
    `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_search: Received search results from ONDC gateway, body=`,
    JSON.stringify(req.body)
  );

  try {
    const { context, message } = req.body;
    if (!context || !message) {
      console.warn(
        `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_search: Missing context or message in request body`
      );
      return res
        .status(400)
        .json({ error: "Missing context or message in request body" });
    }

    // Verify authorization header
    console.log(req.headers)
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      console.warn(
        `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_search: Missing authorization header`
      );
      return res.status(401).json({ error: "Missing authorization header" });
    }

    const isValid = await isHeaderValid({
      header: authHeader,
      body: JSON.stringify(req.body),
      publicKey: process.env.ONDC_GATEWAY_PUBLIC_KEY,
    });

    if (!isValid) {
      console.warn(
        `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_search: Invalid authorization header`
      );
      return res.status(401).json({ error: "Invalid authorization header" });
    }

    // Process search results (e.g., store in database, send to client)
    const searchResults = message.catalog || {};
    console.log(
      `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_search: Processed search results, catalog=`,
      JSON.stringify(searchResults, null, 2)
    );

    res.status(200).json({
      message: "Search results received successfully",
      data: searchResults,
    });
  } catch (error) {
    console.error(
      `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_search: Failed to process search results, error=${
        error.message
      }`
    );
    res
      .status(500)
      .json({
        error: "Failed to process search results",
        details: error.message,
      });
  }
});


// Select endpoint to initiate ONDC select
app.post("/select", async (req, res) => {
  console.log(`[${new Date().toISOString()}] /select: Received select request`);

  const { country, city, transaction_id, message } = req.body;

  if (!country || !city || !transaction_id || !message) {
    console.warn(
      `[${new Date().toISOString()}] /select: Missing country, city, transaction_id, or message in request body`
    );
    return res.status(400).json({
      error: "Select request failed",
      details: "Missing country, city, transaction_id, or message in request body",
    });
  }

  const timestamp = new Date().toISOString();
  const messageId = crypto.randomUUID();

  const payload = {
    context: {
      domain: DOMAIN,
      location: {
        country: { code: country },
        city: { code: city },
      },
      timestamp: timestamp,
      bap_id: SUBSCRIBER_ID,
      transaction_id: transaction_id, // Use provided transaction_id
      message_id: messageId,
      version: "2.0.0",
      action: "select",
      bap_uri: SUBSCRIBER_URL,
      bpp_id: "ondc-staging.goodpass.in", // From /on_search response
      bpp_uri: "https://ondc-staging.goodpass.in", // From /on_search response
      ttl: "PT30S",
    },
    message: message,
  };

  console.log(
    `[${new Date().toISOString()}] /select: Final payload=`,
    JSON.stringify(payload, null, 2)
  );

  try {
    const authHeader = await createAuthorizationHeader({
      body: JSON.stringify(payload),
      privateKey: process.env.SIGNING_PRIVATE_KEY,
      subscriberId: SUBSCRIBER_ID,
      subscriberUniqueKeyId: UNIQUE_KEY_ID,
    });

    const isValid = await isHeaderValid({
      header: authHeader,
      body: JSON.stringify(payload),
      publicKey: process.env.REQUEST_PUBLIC_KEY,
    });

    console.log(`[${new Date().toISOString()}] /select: isValidHeader=${isValid}`);

    if (!isValid) {
      console.warn(
        `[${new Date().toISOString()}] /select: Invalid authorization header`
      );
      return res.status(401).json({
        error: "Select request failed",
        details: "Invalid authorization header",
      });
    }

    console.log(`[${new Date().toISOString()}] /select: AuthHeader=`, authHeader);

    const response = await axios.post(
      "https://ondc-staging.goodpass.in", // Use BPP URI from /on_search
      JSON.stringify(payload),
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: authHeader,
        },
      }
    );

    console.log(
      `[${new Date().toISOString()}] /select: Select request successful, response=`,
      JSON.stringify(response.data, null, 2)
    );

    res.status(200).json({
      message: "Select request sent successfully to ONDC BPP",
      data: response.data,
    });
  } catch (error) {
    console.error(
      `[${new Date().toISOString()}] /select: Select request failed, error=${error.message}`,
      error.response?.data
    );
    res.status(500).json({
      error: "Select request failed",
      details: error.response?.data || error.message,
    });
  }
});
// On_select endpoint to receive ONDC select results
app.post(`${new URL(SUBSCRIBER_URL).pathname}/on_select`, async (req, res) => {
  console.log(
    `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_select: Received select results from ONDC gateway, body=`,
    JSON.stringify(req.body, null, 2)
  );

  try {
    const { context, message } = req.body;
    if (!context || !message) {
      console.warn(
        `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_select: Missing context or message in request body`
      );
      return res.status(400).json({
        error: "Missing context or message in request body",
      });
    }

    // Verify authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      console.warn(
        `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_select: Missing authorization header`
      );
      return res.status(401).json({
        error: "Missing authorization header",
      });
    }

    const isValid = await isHeaderValid({
      header: authHeader,
      body: JSON.stringify(req.body),
      publicKey: process.env.ONDC_GATEWAY_PUBLIC_KEY,
    });

    if (!isValid) {
      console.warn(
        `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_select: Invalid authorization header`
      );
      return res.status(401).json({
        error: "Invalid authorization header",
      });
    }

    // Process select results (e.g., store in database, send to client)
    const selectResults = message.order || {};
    console.log(
      `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_select: Processed select results, order=`,
      JSON.stringify(selectResult)
    );

    res.status(200).json({
      message: "Select results received successfully",
      data: selectResults,
    });
  } catch (error) {
    console.error(
      `[${new Date().toISOString()}] ${new URL(SUBSCRIBER_URL).pathname}/on_select: Failed to process select results, error=${error.message}`
    );
    res.status(500).json({
      error: "Failed to process select results",
      details: error.message,
    });
  }
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
