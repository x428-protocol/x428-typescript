import type { PreconditionObject, AttestationToken } from "../core/types.js";
import { generateChallenge, type PreconditionConfig } from "../core/challenge.js";
import { buildElicitation } from "./elicitation.js";

export interface X428Config {
  preconditions: PreconditionConfig[];
  resourceUri?: string;
  tokenTtl?: number;
}

export function x428Guard<TArgs, TResult>(
  config: X428Config,
  handler: (args: TArgs, ctx: any) => Promise<TResult>,
): (args: TArgs, ctx: any) => Promise<TResult> {
  const tokenTtl = config.tokenTtl ?? 3600;
  const tokenCache = new Map<string, AttestationToken>();

  return async (args: TArgs, ctx: any) => {
    const resourceUri = config.resourceUri ?? `x428://mcp/${ctx?.toolName ?? "unknown"}`;

    // Check cached token
    const cached = tokenCache.get(resourceUri);
    if (cached && new Date(cached.expiresAt) > new Date()) {
      return handler(args, ctx);
    }

    // Generate challenge
    const challenge = generateChallenge(config.preconditions, resourceUri, { ttlSeconds: 300 });

    // Elicit user confirmation for each precondition
    for (const precondition of challenge.preconditions) {
      const elicitReq = buildElicitation(precondition as PreconditionObject);
      const result = await ctx.mcpReq.elicitInput(elicitReq);

      if (result.action !== "accept") {
        return {
          content: [{ type: "text", text: `x428: User declined ${precondition.type} precondition.` }],
          isError: true,
        } as unknown as TResult;
      }

      const confirmed = result.content?.accept ?? result.content?.confirm;
      if (!confirmed) {
        return {
          content: [{ type: "text", text: `x428: User did not confirm ${precondition.type} precondition.` }],
          isError: true,
        } as unknown as TResult;
      }
    }

    // Store token
    const token: AttestationToken = {
      token: crypto.randomUUID(),
      expiresAt: new Date(Date.now() + tokenTtl * 1000).toISOString(),
      scope: resourceUri,
    };
    tokenCache.set(resourceUri, token);

    return handler(args, ctx);
  };
}
