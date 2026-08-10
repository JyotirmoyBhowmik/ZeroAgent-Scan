/**
 * Client-Side OpenTelemetry & Correlation-ID Tracing Utility
 */

export function generateCorrelationID(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return `corr_${crypto.randomUUID().replace(/-/g, "").substring(0, 16)}`;
  }
  return `corr_${Math.random().toString(36).substring(2, 14)}`;
}

export function generateTraceparent(): { traceparent: string; traceId: string; spanId: string } {
  const genHex = (len: number) => {
    let s = "";
    while (s.length < len) {
      s += Math.random().toString(16).substring(2);
    }
    return s.substring(0, len);
  };

  const traceId = genHex(32);
  const spanId = genHex(16);
  const traceparent = `00-${traceId}-${spanId}-01`;

  return { traceparent, traceId, spanId };
}

export function attachTraceHeaders(headers: HeadersInit = {}): HeadersInit {
  const corrID = generateCorrelationID();
  const { traceparent } = generateTraceparent();

  return {
    ...headers,
    "X-Correlation-ID": corrID,
    "traceparent": traceparent,
  };
}
