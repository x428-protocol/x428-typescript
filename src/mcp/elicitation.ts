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
