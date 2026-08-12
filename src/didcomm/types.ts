/**
 * The flat DIDDoc shape didcomm-rust reads, spelled precisely.
 *
 * didcomm-node ships its own declarations, but its `ServiceKind` is
 * `DIDCommMessagingService | any`, which types every service as `any`. These
 * interfaces are structurally compatible with what the WASM accepts (they are
 * the shapes didcomm-http has been feeding it all along) and keep the compiler
 * honest inside this codebase.
 */

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: Record<string, unknown>;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
}

export interface ServiceEndpoint {
  uri: string;
  accept?: string[];
  routingKeys: string[];
}

export interface Service {
  id: string;
  type: string;
  serviceEndpoint: ServiceEndpoint | string;
}

export interface DIDDoc {
  id: string;
  keyAgreement: string[];
  authentication: string[];
  verificationMethod: VerificationMethod[];
  service: Service[];
}

export interface Secret {
  id: string;
  type: string;
  privateKeyJwk?: Record<string, unknown>;
  privateKeyMultibase?: string;
  privateKeyBase58?: string;
}
