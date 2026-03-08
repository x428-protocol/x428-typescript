import crypto from "node:crypto";
import type {
  PreconditionChallenge,
  PreconditionObject,
  TosPrecondition,
  AgePrecondition,
  IdentityPrecondition,
  AttestationMethod,
} from "./types.js";

/** TOS precondition config (without server-assigned `id`). */
export interface TosPreconditionConfig {
  type: "tos";
  tosVersion: string;
  documentUrl: string;
  documentHash: string;
  allowedAttestationMethods?: AttestationMethod[];
  uiHint?: string;
}

/** AGE precondition config (without server-assigned `id`). */
export interface AgePreconditionConfig {
  type: "age";
  minimumAge: number;
  acceptedVcIssuers?: string[];
  allowedAttestationMethods?: AttestationMethod[];
  uiHint?: string;
}

/** IDENTITY precondition config (without server-assigned `id`). */
export interface IdentityPreconditionConfig {
  type: "identity";
  allowedAttestationMethods?: AttestationMethod[];
  uiHint?: string;
}

/** Discriminated union of precondition configs — like PreconditionObject but without `id`. */
export type PreconditionConfig =
  | TosPreconditionConfig
  | AgePreconditionConfig
  | IdentityPreconditionConfig;

export interface ChallengeOptions {
  ttlSeconds?: number;
  attestationEndpoint?: string;
}

function validatePreconditionConfig(config: PreconditionConfig, index: number): void {
  switch (config.type) {
    case "tos":
      if (!config.tosVersion) throw new Error(`Precondition [${index}]: TOS requires tosVersion`);
      if (!config.documentUrl) throw new Error(`Precondition [${index}]: TOS requires documentUrl`);
      if (!config.documentHash) throw new Error(`Precondition [${index}]: TOS requires documentHash`);
      break;
    case "age":
      if (config.minimumAge == null || config.minimumAge < 0) {
        throw new Error(`Precondition [${index}]: AGE requires minimumAge >= 0`);
      }
      break;
    case "identity":
      break;
  }
}

export function generateChallenge(
  preconditions: PreconditionConfig[],
  resourceUri: string,
  options: ChallengeOptions = {},
): PreconditionChallenge {
  if (preconditions.length === 0) {
    throw new Error("At least one precondition is required");
  }

  preconditions.forEach(validatePreconditionConfig);

  const ttl = options.ttlSeconds ?? 300;
  const nonce = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

  const preconditionObjects = preconditions.map((config, index) => ({
    id: `${config.type}-${index}-${crypto.randomUUID().slice(0, 8)}`,
    allowedAttestationMethods: config.allowedAttestationMethods ?? ["self"],
    ...config,
  })) as PreconditionObject[];

  const challenge: PreconditionChallenge = {
    x428Version: 1,
    preconditions: preconditionObjects,
    resource: resourceUri,
    challenge: nonce,
    expiresAt,
  };

  if (options.attestationEndpoint) {
    challenge.attestationEndpoint = options.attestationEndpoint;
  }

  return challenge;
}
