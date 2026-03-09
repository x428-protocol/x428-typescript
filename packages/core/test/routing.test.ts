import { describe, it, expect } from "vitest";
import { determinePayloadForm } from "../src/routing.js";
import vectors from "@x428-vectors/payload-routing.json";

describe("Payload routing", () => {
  for (const vector of vectors) {
    it(vector.description, () => {
      const result = determinePayloadForm(vector.input.serializedPayload);
      expect(result).toBe(vector.expected.form);
    });
  }
});
