import { DID_METHODS, type DidMethod } from "../src/identity-core.js";
import { mintStoredIdentity } from "../src/identity.js";

/**
 * Mint a mediator identity for a Workers deployment and print it as the JSON
 * that `wrangler secret put MEDIATOR_IDENTITY` expects. The Node server mints
 * its own on first boot; Workers must not, so the identity is made here, once,
 * and handed over as a secret.
 */

function usage(): never {
  console.error(
    `usage: npm run mint-identity -- <public-url> [${DID_METHODS.join("|")}]`
  );
  console.error("  e.g. npm run mint-identity -- https://mediator.example.com web");
  process.exit(1);
}

const publicUrl = process.argv[2];
const method = process.argv[3] ?? "peer2";
if (publicUrl === undefined || !publicUrl.startsWith("http")) {
  usage();
}
if (!(DID_METHODS as readonly string[]).includes(method)) {
  usage();
}

const identity = mintStoredIdentity(publicUrl, method as DidMethod);
console.error(`DID: ${identity.did}\n`);
console.log(JSON.stringify(identity));
