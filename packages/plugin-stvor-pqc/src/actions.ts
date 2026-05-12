import type {
  Action,
  ActionResult,
  IAgentRuntime,
  Memory,
  State,
  HandlerCallback,
} from "@elizaos/core";
import { wasm_ec_verify } from "@stvor/web3/wasm";
import { StvorService } from "./provider.js";
import { STVOR_SERVICE_TYPE, STVOR_HANDSHAKE, STVOR_ENCRYPTED } from "./types.js";
import type { StvorHandshakePayload, StvorEncryptedPayload } from "./types.js";
import type { UUID } from "@elizaos/core";

/**
 * STVOR_HANDSHAKE_ACCEPT
 *
 * Fires when the agent receives an inbound handshake from a peer agent.
 *
 * Initiator→responder flow (mlkemCt absent):
 *   - Record peer's public keys, call respondToSession, send our reply with mlkemCt.
 *
 * Responder→initiator reply (mlkemCt present):
 *   - We are the original initiator; complete our session with respondToSession.
 */
export const handshakeAcceptAction: Action = {
  name: "STVOR_HANDSHAKE_ACCEPT",
  description:
    "Accept a post-quantum key exchange handshake from a peer agent and establish an E2EE session",
  similes: ["ACCEPT_PQC_HANDSHAKE", "ESTABLISH_E2EE_SESSION"],

  validate: async (_runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    return message.content?.type === STVOR_HANDSHAKE;
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    _options?: Record<string, unknown>,
    callback?: HandlerCallback
  ): Promise<ActionResult | undefined> => {
    const svc = runtime.getService<StvorService>(STVOR_SERVICE_TYPE);
    if (!svc) {
      runtime.logger.warn("[stvor-pqc] StvorService not available — skipping handshake");
      return { success: false, error: "StvorService unavailable" };
    }

    const payload = message.content?.["stvor"] as StvorHandshakePayload | undefined;
    if (!payload?.ik || !payload?.spk || !payload?.spkSig || !payload?.mlkemEk || !payload?.agentId) {
      runtime.logger.warn("[stvor-pqc] Malformed handshake payload");
      return { success: false, error: "Malformed handshake payload" };
    }

    // Verify the SPK is authentically signed by the claimed identity key.
    // This prevents a key-substitution attack on the SPK field in transit.
    const spkBytes = new TextEncoder().encode(payload.spk);
    const spkValid = wasm_ec_verify(spkBytes, payload.spkSig, payload.ik);
    if (!spkValid) {
      runtime.logger.warn(`[stvor-pqc] SPK signature invalid from ${payload.agentId} — dropping handshake`);
      return { success: false, error: "SPK signature verification failed" };
    }

    const peerId = payload.agentId as UUID;

    if (payload.mlkemCt) {
      // We are the original initiator — peer is replying with their keys + our ct.
      // Complete our side of the session.
      if (!svc.hasSession(peerId)) {
        svc.respondToSession(peerId, payload.ik, payload.spk, payload.mlkemCt);
        runtime.logger.info(`[stvor-pqc] Session completed (initiator) with ${peerId}`);
      }
      return { success: true };
    }

    // We are the responder — peer sent their public keys without a ct.
    // Build a session on our side and send back our keys + mlkemCt.
    const { mlkemCt } = svc.initiateSession(peerId, payload.ik, payload.spk, payload.mlkemEk);

    if (callback) {
      const reply = svc.buildHandshakePayload();
      await callback({
        text: "",
        type: STVOR_HANDSHAKE,
        ["stvor"]: { ...reply, mlkemCt } satisfies StvorHandshakePayload,
      });
    }

    return { success: true };
  },

  examples: [],
};

/**
 * STVOR_DECRYPT_MESSAGE
 *
 * Fires when an encrypted message arrives from a peer agent.
 * Decrypts the payload and surfaces the plaintext via callback.
 */
export const decryptMessageAction: Action = {
  name: "STVOR_DECRYPT_MESSAGE",
  description:
    "Decrypt an incoming post-quantum encrypted message from a peer agent",
  similes: ["DECRYPT_PQC_MESSAGE", "UNWRAP_E2EE"],

  validate: async (_runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    return message.content?.type === STVOR_ENCRYPTED;
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    _options?: Record<string, unknown>,
    callback?: HandlerCallback
  ): Promise<ActionResult | undefined> => {
    const svc = runtime.getService<StvorService>(STVOR_SERVICE_TYPE);
    if (!svc) {
      runtime.logger.warn("[stvor-pqc] StvorService not available — cannot decrypt");
      return { success: false, error: "StvorService unavailable" };
    }

    const payload = message.content?.["stvor"] as StvorEncryptedPayload | undefined;
    if (!payload?.ciphertext || !payload?.agentId) {
      runtime.logger.warn("[stvor-pqc] Malformed encrypted payload");
      return { success: false, error: "Malformed encrypted payload" };
    }

    const peerId = payload.agentId as UUID;

    if (!svc.hasSession(peerId)) {
      runtime.logger.warn(
        `[stvor-pqc] Received encrypted message from ${peerId} but no session exists — dropping`
      );
      return { success: false, error: "No session for peer" };
    }

    try {
      const plaintext = svc.decrypt(peerId, payload.ciphertext);
      runtime.logger.info(`[stvor-pqc] Decrypted message from ${peerId}`);

      if (callback) {
        await callback({ text: plaintext });
      }

      return { success: true };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      runtime.logger.error(`[stvor-pqc] Decryption failed for peer ${peerId}: ${msg}`);
      return { success: false, error: msg };
    }
  },

  examples: [],
};
