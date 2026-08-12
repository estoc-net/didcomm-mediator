import { mintStoredIdentity } from "../src/identity.js";

/**
 * Mint a mediator identity for a Workers deployment and print it as the JSON
 * that `wrangler secret put MEDIATOR_IDENTITY` expects. The Node server mints
 * its own on first boot; Workers must not, so the identity is made here, once,
 * and handed over as a secret.
 */

const publicUrl = process.argv[2];
if (publicUrl === undefined || !publicUrl.startsWith("http")) {
  console.error("usage: npm run mint-identity -- <public-url>");
  console.error("  e.g. npm run mint-identity -- https://mediator.example.com");
  process.exit(1);
}

const identity = mintStoredIdentity(publicUrl);
console.error(`DID: ${identity.did}\n`);
console.log(JSON.stringify(identity));
