// src/voteLogic.ts
import axios from "axios";
import { Wallet as EthersWallet, JsonRpcProvider } from "ethers";
import { getPublicKey } from "@noble/secp256k1";

// NOTE: copy your davinci sdk into src/libs/davinci-sdk/... and update these imports if needed
import { CensusOrigin } from "../libs/davinci-sdk/src/index.js";
import { DavinciSDK } from "../libs/davinci-sdk/src/DavinciSDK.js";
import { CSPCensusProofProvider, CensusProviders } from "../libs/davinci-sdk/src/census/types.js";

// ------------------------
// Configuration (from your message(1).txt)
const VC_ISSUER_ENDPOINT = "https://informed-guppy-adapting.ngrok-free.app/issuer/getVC";
const CSP_VERIFIER_ENDPOINT = "https://informed-guppy-adapting.ngrok-free.app/verifier/getProof";

const SEQUENCER_API_URL = "https://sequencer-dev.davinci.vote";
const RPC_URL = "https://w3.ch4in.net/sepolia";
const USE_SEQUENCER_ADDRESSES = true;
// ------------------------

// Types matching your original script
export type StoredWallet = {
  privateKey: string; // "0x..." hex
  address: string;
  publicKey: string; // "0x..." hex uncompressed (0x04 + X + Y)
  did: string;
};

// ---- helpers
function base64UrlToBase64(b64u: string) {
  return b64u.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (b64u.length % 4)) % 4);
}
function decodeJwt(jwt: string) {
  try {
    const parts = jwt.split(".");
    if (parts.length < 2) return null;
    const header = JSON.parse(atob(base64UrlToBase64(parts[0])));
    const payload = JSON.parse(atob(base64UrlToBase64(parts[1])));
    return { header, payload };
  } catch {
    return null;
  }
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Creates a wallet exactly like your original script:
 * - ethers.Wallet.createRandom()
 * - derive uncompressed public key (0x04 + X + Y) using @noble/secp256k1
 * - DID format: did:ethr:<address>
 */
export async function createStoredWallet(): Promise<StoredWallet> {
  const w = EthersWallet.createRandom();
  const privateKey = w.privateKey;
  const address = w.address;
  const privBytes = hexToBytes(privateKey.replace(/^0x/, ""));
  const pubBytes = getPublicKey(privBytes, false); // uncompressed (65 bytes)
  const publicKey = "0x" + bytesToHex(new Uint8Array(pubBytes));
  const did = `did:ethr:${address.toLowerCase()}`;
  return { privateKey, address, publicKey, did };
}

// ------------------------------------------
// VC issuance (same logic as your script)
export async function getVerifiableCredential(wallet: StoredWallet): Promise<string> {
  try {
    const walletInstance = new EthersWallet(wallet.privateKey);
    const message = `Proof of control for DID ${wallet.did} — generated at ${new Date().toISOString()}`;

    const signature = await walletInstance.signMessage(message);

    const proof = {
      message,
      signature,
      address: wallet.address,
      publicKey: wallet.publicKey,
    };

    const body = { iss: wallet.did, proof };

    console.log("Requesting VC from:", VC_ISSUER_ENDPOINT);

    const resp = await axios.post(VC_ISSUER_ENDPOINT, body, {
      headers: { "Content-Type": "application/json" },
      timeout: 20000,
    });

    if (!resp.data || !resp.data.credential) {
      throw new Error("No credential returned from issuer");
    }
    const vcJwt = resp.data.credential;

    const decoded = decodeJwt(vcJwt);
    if (decoded) {
      console.log("Decoded VC payload:", decoded.payload);
    }

    return vcJwt;
  } catch (error: any) {
    console.error("VC error:", error?.message ?? error);
    throw error;
  }
}

// ------------------------------------------
// CSP provider factory (same as your script)
// NOTE: provider factory takes (vcJwt, publicKey) only — the SDK will call it with { processId, address } when needed.
// REPLACE your current createVCBasedCSPProvider with this version
export function createVCBasedCSPProvider(vcJwt: string, publicKey: string): CSPCensusProofProvider {
  return async ({ processId, address }) => {
    console.log(`CSP Provider called — processId=${processId} address=${address}`);

    try {
      const formData = new URLSearchParams();
      formData.append("JWT", vcJwt);
      formData.append("publicKey", publicKey);
      formData.append("address", address);
      // IMPORTANT: backend requires processId
      if (processId) {
        formData.append("processId", processId);
      } else {
        // if SDK didn't send processId, append empty string (server will reject, but this makes it explicit)
        formData.append("processId", "");
      }

      const response = await axios.post(CSP_VERIFIER_ENDPOINT, formData, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 20000,
      });

      if (!response.data?.proof) {
        console.error("CSP verifier returned invalid body:", response.data);
        throw new Error("No proof returned from CSP verifier");
      }

      const proof = response.data.proof;

      return {
        root: proof.root,
        address: proof.address,
        weight: proof.weight || "1",
        censusOrigin: CensusOrigin.CensusOriginCSP,
        processId: proof.processId,
        publicKey: proof.publicKey,
        signature: proof.signature,
      };
    } catch (err: any) {
      // show server response body (very helpful when debugging)
      if (err?.response?.data) {
        console.error("CSP verifier error response data:", err.response.data);
      } else {
        console.error("CSP provider call failed:", err?.message ?? err);
      }
      throw err;
    }
  };
}


// ------------------------------------------
// MAIN: run steps 2,3,4 (matches message(1).txt)
export async function runRemainingSteps(wallet: StoredWallet, choices: number[], processId?: string) {
  if (!processId) {
    processId = "0x97f2ceae823fd8d9ab0dcd011efcb24f2ea3b0ffe388d14f0000000000000008";
  }

  // Step 2: request VC
  console.log("Step 2: Requesting VC...");
  const vcJwt = await getVerifiableCredential(wallet);

  // Step 3: init SDK using provider+signer (provider created here)
  console.log("Step 3: Initializing SDK...");
  const signer = new EthersWallet(wallet.privateKey, new JsonRpcProvider(RPC_URL));
  const voterSDK = new DavinciSDK({
    signer,
    environment: "dev",
    sequencerUrl: SEQUENCER_API_URL,
    chain: "sepolia",
    useSequencerAddresses: USE_SEQUENCER_ADDRESSES,
    censusProviders: {
      csp: createVCBasedCSPProvider(vcJwt, wallet.publicKey),
    } as unknown as CensusProviders,
  });

  await voterSDK.init();

  // Step 4: submit vote
  console.log("Step 4: Submitting vote...");
  const result = await voterSDK.submitVote({
    processId,
    choices,
  });

  console.log("Vote result:", result);
  return result;
}
