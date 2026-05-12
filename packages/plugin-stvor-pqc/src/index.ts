import type { Plugin, Memory, MessagePayload } from "@elizaos/core";
import { EventType } from "@elizaos/core";
import { StvorService } from "./provider.js";
import { handshakeAcceptAction, decryptMessageAction } from "./actions.js";
import { STVOR_HANDSHAKE, STVOR_ENCRYPTED, STVOR_SERVICE_TYPE } from "./types.js";
import type { UUID } from "@elizaos/core";

/**
 * stvorPqcPlugin
 *
 * Adds post-quantum E2EE to elizaOS agent-to-agent communication.
 *
 * What happens at runtime:
 *   1. StvorService starts and generates an ML-KEM-768 keypair + P-256 identity keypair.
 *   2. On MESSAGE_RECEIVED, if the sender is a different agent and we have no session
 *      yet, the plugin emits a STVOR_HANDSHAKE message back into the same room.
 *   3. The peer's STVOR_HANDSHAKE_ACCEPT action completes the KEM exchange; both sides
 *      hold a shared Double Ratchet session from then on.
 *   4. STVOR_ENCRYPTED messages are decrypted transparently by STVOR_DECRYPT_MESSAGE.
 *   5. Messages from peers without Stvor installed pass through unchanged.
 */
export const stvorPqcPlugin: Plugin = {
  name: "stvor-pqc",
  description:
    "Post-quantum E2EE (ML-KEM-768 + Double Ratchet) for elizaOS agent-to-agent messaging — powered by Stvor (pqc.stvor.xyz)",

  services: [StvorService],

  actions: [handshakeAcceptAction, decryptMessageAction],

  events: {
    [EventType.MESSAGE_RECEIVED]: [
      async ({ runtime, message }: MessagePayload): Promise<void> => {
        // Only act when another agent sent the message (not a human user, not ourselves).
        // elizaOS sets memory.agentId to the receiving agent's id; the sender is entityId.
        // A message is agent-originated when its content.type is one of our Stvor types
        // OR when it comes from a room where we know the sender is an agent.
        // The safest available signal: content.source === "agent" (set by agent connectors)
        // combined with entityId !== agentId.
        const senderIsAgent =
          message.content?.source === "agent" ||
          // Fallback: already-typed Stvor messages are always agent-to-agent
          message.content?.type === STVOR_HANDSHAKE ||
          message.content?.type === STVOR_ENCRYPTED;

        const senderIsUs = message.entityId === runtime.agentId;

        if (!senderIsAgent || senderIsUs) return;

        // If the message is already a Stvor typed message the Actions handle it.
        const msgType = message.content?.type;
        if (msgType === STVOR_HANDSHAKE || msgType === STVOR_ENCRYPTED) return;

        const svc = runtime.getService<StvorService>(STVOR_SERVICE_TYPE);
        if (!svc) return;

        const peerId = message.entityId as UUID;
        if (svc.hasSession(peerId)) return;

        runtime.logger.info(
          `[stvor-pqc] First message from agent ${peerId} — sending handshake`
        );

        const handshakeMemory: Memory = {
          entityId: runtime.agentId,
          agentId: runtime.agentId,
          roomId: message.roomId,
          ...(message.worldId ? { worldId: message.worldId as string } : {}),
          content: {
            text: "",
            type: STVOR_HANDSHAKE,
            source: "agent",
            // Cast through unknown: Content's index signature requires ContentValue,
            // but StvorHandshakePayload is a plain object — safe because the runtime
            // only serialises this field, never narrows it back to ContentValue.
            ["stvor"]: svc.buildHandshakePayload() as unknown as string,
          },
        };

        try {
          await runtime.emitEvent(EventType.MESSAGE_SENT, {
            runtime,
            message: handshakeMemory,
          });
        } catch (err) {
          runtime.logger.error(`[stvor-pqc] Failed to emit handshake: ${err instanceof Error ? err.message : String(err)}`);
        }
      },
    ],
  },
};

export default stvorPqcPlugin;

export { StvorService } from "./provider.js";
export { handshakeAcceptAction, decryptMessageAction } from "./actions.js";
export * from "./types.js";
