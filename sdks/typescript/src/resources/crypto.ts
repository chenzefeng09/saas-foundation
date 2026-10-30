/**
 * Crypto resource — envelope encryption, KEK lifecycle, signing, password hashing.
 * Mirrors Python SDK foundation_sdk/resources/crypto.py
 */

import type { Transport } from "../transport.js";

/** The routes take bytes as base64; a string is sent as its UTF-8 encoding. */
function b64(data: string | Uint8Array): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export class CryptoResource {
  constructor(private readonly t: Transport) {}

  // --- Envelope Encryption ---

  /**
   * Envelope-encrypt under the KEK labelled `kekLabel`.
   *
   * `context` is bound as AAD; `decrypt` must present the same one. Returns `{envelope}`.
   */
  async encrypt(params: {
    plaintext: string | Uint8Array;
    kekLabel?: string;
    context?: Record<string, string>;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      key_label: params.kekLabel ?? "default",
      plaintext_b64: b64(params.plaintext),
    };
    if (params.context != null) body["context"] = params.context;
    return this.t.request("POST", "/api/crypto/v1/encrypt", { json: body });
  }

  /** Returns `{plaintext_b64}`; `context` must equal the one used to encrypt. */
  async decrypt(params: {
    envelope: Record<string, unknown>;
    context?: Record<string, string>;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { envelope: params.envelope };
    if (params.context != null) body["expected_context"] = params.context;
    return this.t.request("POST", "/api/crypto/v1/decrypt", { json: body });
  }

  /** Re-wrap the DEK under another version of the same KEK (default: the active one). */
  async rewrap(params: {
    envelope: Record<string, unknown>;
    targetKekVersion?: number;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { envelope: params.envelope };
    if (params.targetKekVersion != null) body["target_kek_version"] = params.targetKekVersion;
    return this.t.request("POST", "/api/crypto/v1/rewrap", { json: body });
  }

  // --- KEK Lifecycle ---

  /**
   * `purpose` is FIELD_ENCRYPT, AUDIT_HMAC, JWT_SIGN or FILE_ENCRYPT;
   * `algorithm` is an id from `listAlgorithms`.
   */
  async createKek(params: {
    label: string;
    purpose: string;
    algorithm?: string;
    autoRotateDays?: number;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      label: params.label,
      algorithm_id: params.algorithm ?? "AES-256-GCM",
      purpose: params.purpose,
    };
    if (params.autoRotateDays != null) body["auto_rotate_days"] = params.autoRotateDays;
    return this.t.request("POST", "/api/crypto/v1/keks", { json: body });
  }

  async rotateKek(kekId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/crypto/v1/keks/${kekId}/rotate`);
  }

  async listKeks(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/crypto/v1/keks");
  }

  // --- Signing ---

  /**
   * Sign with the KEK labelled `keyLabel`; its algorithm decides the scheme.
   * Returns `{signature_b64, kek_version, ...}`.
   */
  async sign(params: {
    data: string | Uint8Array;
    keyLabel: string;
    prehash?: boolean;
    detached?: boolean;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { key_label: params.keyLabel, data_b64: b64(params.data) };
    if (params.prehash != null) body["prehash"] = params.prehash;
    if (params.detached != null) body["detached"] = params.detached;
    return this.t.request("POST", "/api/crypto/v1/sign", { json: body });
  }

  /** `signature` is the `signature_b64` that `sign` returned. */
  async verify(params: {
    data: string | Uint8Array;
    signature: string;
    keyLabel: string;
    kekVersion?: number;
    prehash?: boolean;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      key_label: params.keyLabel,
      data_b64: b64(params.data),
      signature_b64: params.signature,
    };
    if (params.kekVersion != null) body["kek_version"] = params.kekVersion;
    if (params.prehash != null) body["prehash"] = params.prehash;
    return this.t.request("POST", "/api/crypto/v1/verify", { json: body });
  }

  // --- Password Hashing ---

  /** Returns `{encoded, algorithm}`; store `encoded`. */
  async hashPassword(password: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/password-hash", {
      json: { password },
    });
  }

  /** `passwordHash` is the `encoded` string `hashPassword` returned. */
  async verifyPassword(params: {
    password: string;
    passwordHash: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/password-verify", {
      json: { password: params.password, encoded: params.passwordHash },
    });
  }

  // --- Algorithms ---

  async listAlgorithms(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/crypto/v1/algorithms");
  }
}
