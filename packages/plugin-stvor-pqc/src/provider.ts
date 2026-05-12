import type { IAgentRuntime } from "@elizaos/core";
import { Service } from "@elizaos/core";
import type { UUID } from "@elizaos/core";
import initWasm, {
  WasmKeyPair,
  WasmSession,
  wasm_mlkem_keygen,
  wasm_ec_sign,
  wasm_hybrid_session_initiate,
  wasm_hybrid_session_respond,
} from "@stvor/web3/wasm";
import type { PqcKeypair, StvorHandshakePayload } from "./types.js";
import { STVOR_SERVICE_TYPE } from "./types.js";

/**
 * StvorService manages this agent's ML-KEM-768 keypair and all active
 * Double Ratchet sessions with peer agents.
 *
 * Identity keypair: WasmKeyPair (P-256) for X3DH
 * KEM keypair: ML-KEM-768 for post-quantum key encapsulation
 *
 * Session establishment (initiator side):
 *   1. wasm_hybrid_session_initiate → returns { session_json, mlkem_ct }
 *   2. Send mlkem_ct + our public keys to peer in handshake message
 *
 * Session establishment (responder side):
 *   1. Receive peer's mlkem_ct + public keys
 *   2. wasm_hybrid_session_respond → returns WasmSession directly
 */
export class StvorService extends Service {
  static readonly serviceType = STVOR_SERVICE_TYPE;
  readonly capabilityDescription =
    "Post-quantum E2EE (ML-KEM-768 + Double Ratchet) for agent-to-agent messages";

  private ikPair!: WasmKeyPair;    // P-256 identity keypair
  private spkPair!: WasmKeyPair;   // P-256 signed pre-key
  private kemPair!: PqcKeypair;    // ML-KEM-768 keypair
  private sessions = new Map<UUID, { session: WasmSession; establishedAt: number }>();
  private wasmReady = false;

  static async start(runtime: IAgentRuntime): Promise<StvorService> {
    const svc = new StvorService(runtime);
    await svc._init();
    return svc;
  }

  private async _init(): Promise<void> {
    await initWasm();
    this.wasmReady = true;

    this.ikPair = new WasmKeyPair();
    this.spkPair = new WasmKeyPair();
    const kemRaw: string = wasm_mlkem_keygen();
    this.kemPair = JSON.parse(kemRaw) as PqcKeypair;

    this.runtime.logger.info(
      `[stvor-pqc] Service ready for agent ${this.runtime.agentId}. ik=${this.ikPair.public_key.slice(0, 12)}…`
    );
  }

  async stop(): Promise<void> {
    this.sessions.clear();
  }

  /** Build the payload this agent broadcasts in its handshake message. */
  buildHandshakePayload(): StvorHandshakePayload {
    this._assertReady();
    // Sign the raw SPK public-key bytes with the identity key so the peer can
    // verify the SPK wasn't substituted in transit (X3DH requirement).
    const spkBytes = new TextEncoder().encode(this.spkPair.public_key);
    const spkSig = wasm_ec_sign(spkBytes, this.ikPair);
    return {
      agentId: this.runtime.agentId,
      ik: this.ikPair.public_key,
      spk: this.spkPair.public_key,
      spkSig,
      mlkemEk: this.kemPair.ek,
    };
  }

  /**
   * Initiator side: establish a Double Ratchet session with a peer.
   * Returns the mlkem_ct the peer needs to derive the same shared secret.
   */
  initiateSession(
    peerId: UUID,
    peerIk: string,
    peerSpk: string,
    peerMlkemEk: string
  ): { mlkemCt: string } {
    this._assertReady();

    const raw: string = wasm_hybrid_session_initiate(
      this.ikPair,
      this.spkPair,
      peerIk,
      peerSpk,
      peerMlkemEk
    );
    const { session_json, mlkem_ct }: { session_json: string; mlkem_ct: string } =
      JSON.parse(raw);

    const session = WasmSession.from_json(session_json);
    this.sessions.set(peerId, { session, establishedAt: Date.now() });

    this.runtime.logger.info(`[stvor-pqc] Session initiated with peer ${peerId}`);
    return { mlkemCt: mlkem_ct };
  }

  /**
   * Responder side: complete a session given the initiator's KEM ciphertext.
   */
  respondToSession(
    peerId: UUID,
    peerIk: string,
    peerSpk: string,
    mlkemCt: string
  ): void {
    this._assertReady();

    const session: WasmSession = wasm_hybrid_session_respond(
      this.ikPair,
      this.spkPair,
      peerIk,
      peerSpk,
      this.kemPair.dk,
      mlkemCt
    );

    this.sessions.set(peerId, { session, establishedAt: Date.now() });
    this.runtime.logger.info(`[stvor-pqc] Session established (responder) with peer ${peerId}`);
  }

  hasSession(peerId: UUID): boolean {
    return this.sessions.has(peerId);
  }

  /** Encrypt plaintext for a peer. Returns base64url ciphertext string. */
  encrypt(peerId: UUID, plaintext: string): string {
    const { session } = this._getSession(peerId);
    const bytes = new TextEncoder().encode(plaintext);
    // WasmSession.encrypt(Uint8Array) → string (base64url blob)
    return session.encrypt(bytes);
  }

  /** Decrypt a base64url ciphertext blob from a peer. Returns plaintext string. */
  decrypt(peerId: UUID, ciphertextB64url: string): string {
    const { session } = this._getSession(peerId);
    // WasmSession.decrypt(string) → Uint8Array
    const bytes: Uint8Array = session.decrypt(ciphertextB64url);
    return new TextDecoder().decode(bytes);
  }

  private _getSession(peerId: UUID) {
    const s = this.sessions.get(peerId);
    if (!s) throw new Error(`[stvor-pqc] No session for peer ${peerId}`);
    return s;
  }

  private _assertReady(): void {
    if (!this.wasmReady) throw new Error("[stvor-pqc] WASM not initialised");
  }
}
