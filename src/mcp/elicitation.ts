import type { PreconditionObject } from "../core/types.js";

export interface ElicitationRequest {
  mode: "form";
  message: string;
  requestedSchema: Record<string, unknown>;
}

export function buildElicitation(precondition: PreconditionObject): ElicitationRequest {
  switch (precondition.type) {
    case "tos":
      return {
        mode: "form",
        message: `Terms of Service Acceptance Required\n\nPlease review the Terms of Service at: ${precondition.documentUrl}\nVersion: ${precondition.tosVersion}\n\nDo you accept these terms on behalf of the operator?`,
        requestedSchema: {
          type: "object",
          properties: {
            accept: { type: "boolean", title: "I accept the Terms of Service" },
          },
          required: ["accept"],
        },
      };
    case "age":
      return {
        mode: "form",
        message: `Age Verification Required\n\nYou must confirm you are ${precondition.minimumAge} or older to access this resource.\n\nDo you confirm you meet the age requirement?`,
        requestedSchema: {
          type: "object",
          properties: {
            confirm: { type: "boolean", title: `I confirm I am ${precondition.minimumAge} or older` },
          },
          required: ["confirm"],
        },
      };
    case "identity":
      return {
        mode: "form",
        message: `Identity Confirmation Required\n\nPlease confirm your identity to continue.`,
        requestedSchema: {
          type: "object",
          properties: {
            confirm: { type: "boolean", title: "I confirm my identity" },
          },
          required: ["confirm"],
        },
      };
  }
}

/**
 * Build a single combined elicitation form for multiple preconditions.
 * Each precondition gets a uniquely-keyed boolean field to avoid collisions.
 */
export function buildCombinedElicitation(preconditions: PreconditionObject[]): ElicitationRequest {
  if (preconditions.length === 1) {
    return buildElicitation(preconditions[0]);
  }

  const messageParts: string[] = [];
  const properties: Record<string, unknown> = {};
  const required: string[] = [];

  for (const precondition of preconditions) {
    const fieldKey = `confirm_${precondition.id}`;
    required.push(fieldKey);

    switch (precondition.type) {
      case "tos":
        messageParts.push(
          `- Terms of Service: Review at ${precondition.documentUrl} (v${precondition.tosVersion})`,
        );
        properties[fieldKey] = {
          type: "boolean",
          title: "I accept the Terms of Service",
        };
        break;
      case "age":
        messageParts.push(
          `- Age Verification: You must be ${precondition.minimumAge} or older`,
        );
        properties[fieldKey] = {
          type: "boolean",
          title: `I confirm I am ${precondition.minimumAge} or older`,
        };
        break;
      case "identity":
        messageParts.push(
          `- Identity: Please confirm your identity`,
        );
        properties[fieldKey] = {
          type: "boolean",
          title: "I confirm my identity",
        };
        break;
    }
  }

  return {
    mode: "form",
    message: `Precondition Acceptance Required\n\nPlease review and confirm the following:\n\n${messageParts.join("\n")}`,
    requestedSchema: {
      type: "object",
      properties,
      required,
    },
  };
}
