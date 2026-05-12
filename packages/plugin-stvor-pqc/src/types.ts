import type { UUID } from "@elizaos/core";

/** ML-KEM-768 keypair produced by wasm_mlkem_keygen() */
export interface PqcKeypair {
  /** Encapsulation key (public) — 1184 bytes, base64url */
  ek: string;
  /** Decapsulation key (private) — 64 bytes, base64url */
  dk: string;
}

/**
 * Wire format for the in-band key-exchange handshake.
 * Sent as content['stvor'] when content.type === STVOR_HANDSHAKE.
 *
 * On initiator→responder: ik + spk + mlkemEk present; mlkemCt absent.
 * On responder→initiator reply: all fields present including mlkemCt.
 */
export interface StvorHandshakePayload {
  agentId: UUID;
  /** P-256 identity public key (base64url, 65 bytes) */
  ik: string;
  /** P-256 signed pre-key public (base64url, 65 bytes) */
  spk: string;
  /** ML-KEM-768 encapsulation key (base64url, 1184 bytes) */
  mlkemEk: string;
  /**
   * ECDSA-P256 signature of the SPK public key bytes, signed by IK.
   * base64url DER format, produced by wasm_ec_sign.
   * Required — receiver must verify before using spk in the KEM.
   */
  spkSig: string;
  /** ML-KEM-768 ciphertext — only present in responder's reply */
  mlkemCt?: string;
}

/**
 * Wire format for an encrypted message.
 * Embedded in Content.metadata when Content.type === STVOR_ENCRYPTED.
 */
export interface StvorEncryptedPayload {
  /** Base64-encoded ciphertext from WasmSession.encrypt() */
  ciphertext: string;
  /** Sender's agentId — for session lookup */
  agentId: UUID;
}

export const STVOR_HANDSHAKE = "stvor:handshake" as const;
export const STVOR_ENCRYPTED = "stvor:encrypted" as const;
export const STVOR_SERVICE_TYPE = "stvor-pqc" as const;
