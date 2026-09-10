// 2F-F CORRECTION RED (pure module) — the outcome classifier. Written
// against the rejected candidate d391b12f; `unprovenOutcome` does not exist
// there, so this file fails at import resolution on the baseline.
//
//   U1  a transport death (network / timeout / abort) is unproven.
//   U2  a 2xx whose media type, JSON or action-specific schema could not be
//       verified is UNPROVEN — the mutation may be durably committed.
//   U3  a well-formed refusal (recognised code with its contracted status)
//       is NOT unproven; an unrecognised non-2xx body is unproven too (it is
//       never an authoritative "nothing changed" verdict).
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { unprovenOutcome } from "../api/upstream";

function httpErr(status: number, body: unknown): ApiError {
  return new ApiError(
    "http",
    `HTTP ${String(status)}`,
    status,
    JSON.stringify(body),
  );
}

describe("unprovenOutcome", () => {
  it("U1 transport deaths are unproven", () => {
    expect(unprovenOutcome(new ApiError("network", "x"))).toBe(true);
    expect(unprovenOutcome(new ApiError("timeout", "x"))).toBe(true);
    expect(unprovenOutcome(new ApiError("aborted", "x"))).toBe(true);
  });
  it("U2 an unverifiable 2xx is unproven", () => {
    expect(unprovenOutcome(new ApiError("contenttype", "x", 201))).toBe(true);
    expect(unprovenOutcome(new ApiError("contenttype", "x", 200))).toBe(true);
    expect(unprovenOutcome(new ApiError("decode", "x", 200))).toBe(true);
    expect(unprovenOutcome(new ApiError("decode", "x", 201))).toBe(true);
  });
  it("U3 a recognised refusal is a verdict; an unrecognised non-2xx body is not", () => {
    expect(
      unprovenOutcome(
        httpErr(409, { error: "x", code: "stale", current: { revision: 6 } }),
      ),
    ).toBe(false);
    expect(
      unprovenOutcome(
        httpErr(409, { error: "x", code: "made_up", current: {} }),
      ),
    ).toBe(true);
    expect(unprovenOutcome(new ApiError("http", "x", 502, "bad gateway"))).toBe(
      true,
    );
    expect(unprovenOutcome(new ApiError("http", "x", 403, "forbidden\n"))).toBe(
      false,
    );
  });
});
