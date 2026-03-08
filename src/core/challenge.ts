import crypto from "node:crypto";
import type { PreconditionChallenge, PreconditionObject } from "./types.js";

export interface PreconditionConfig {
  type: string;
  [key: string]: unknown;
}

export interface ChallengeOptions {
  ttlSeconds?: number;
  attestationEndpoint?: string;
}

export function generateChallenge(
  preconditions: PreconditionConfig[],
  resourceUri: string,
  options: ChallengeOptions = {},
): PreconditionChallenge {
  const ttl = options.ttlSeconds ?? 300;
  const nonce = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

  const preconditionObjects = preconditions.map((config, index) => ({
    id: `${config.type}-${index}-${crypto.randomUUID().slice(0, 8)}`,
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
