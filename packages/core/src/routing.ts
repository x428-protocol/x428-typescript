const MAX_HEADER_SIZE = 8192;

export function determinePayloadForm(serializedPayload: string): "header" | "body" {
  const byteLength = new TextEncoder().encode(serializedPayload).length;
  return byteLength <= MAX_HEADER_SIZE ? "header" : "body";
}
