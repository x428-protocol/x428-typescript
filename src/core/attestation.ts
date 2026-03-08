import type {
  AttestationPayload,
  AttestationObject,
  PreconditionChallenge,
} from "./types.js";
import { signPayload } from "./signing.js";

export function buildAttestation(
  challenge: PreconditionChallenge,
  operatorDid: string,
  signingKey: Uint8Array,
  attestations: AttestationObject[],
): AttestationPayload {
  const payloadWithoutSig = {
    x428Version: challenge.x428Version,
    challenge: challenge.challenge,
    resource: challenge.resource,
    operatorId: operatorDid,
    attestations,
  };

  const signature = signPayload(
    payloadWithoutSig as unknown as Record<string, unknown>,
    signingKey,
  );

  return { ...payloadWithoutSig, signature };
}
