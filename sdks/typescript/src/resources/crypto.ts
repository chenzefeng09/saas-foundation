/**
 * Crypto resource — envelope encryption, KEK lifecycle, signing, password hashing.
 * Mirrors Python SDK foundation_sdk/resources/crypto.py
 */

import type { Transport } from "../transport.js";

export class CryptoResource {
  constructor(private readonly t: Transport) {}

  // --- Envelope Encryption ---

  async encrypt(params: {
    plaintext: string;
    kekLabel?: string;
    aad?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/encrypt", {
      json: {
        plaintext: params.plaintext,
        kek_label: params.kekLabel ?? "default",
        aad: params.aad ?? null,
      },
    });
  }

  async decrypt(params: {
    envelope: Record<string, unknown>;
    aad?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/decrypt", {
      json: { envelope: params.envelope, aad: params.aad ?? null },
    });
  }

  async rewrap(params: {
    envelope: Record<string, unknown>;
    targetKekLabel: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/rewrap", {
      json: {
        envelope: params.envelope,
        target_kek_label: params.targetKekLabel,
      },
    });
  }

  // --- KEK Lifecycle ---

  async createKek(params: {
    label: string;
    algorithm?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/keks", {
      json: {
        label: params.label,
        algorithm: params.algorithm ?? "AES-256-GCM",
      },
    });
  }

  async rotateKek(kekId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/crypto/v1/keks/${kekId}/rotate`);
  }

  async listKeks(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/crypto/v1/keks");
  }

  // --- Signing ---

  async sign(params: {
    data: string;
    algorithm?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/sign", {
      json: {
        data: params.data,
        algorithm: params.algorithm ?? "ECDSA-P256",
      },
    });
  }

  async verify(params: {
    data: string;
    signature: string;
    algorithm?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/verify", {
      json: {
        data: params.data,
        signature: params.signature,
        algorithm: params.algorithm ?? "ECDSA-P256",
      },
    });
  }

  // --- Password Hashing ---

  async hashPassword(password: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/hash-password", {
      json: { password },
    });
  }

  async verifyPassword(params: {
    password: string;
    passwordHash: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/crypto/v1/verify-password", {
      json: { password: params.password, password_hash: params.passwordHash },
    });
  }

  // --- Algorithms ---

  async listAlgorithms(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/crypto/v1/algorithms");
  }
}
