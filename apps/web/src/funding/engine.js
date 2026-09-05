import { instantiateWasm } from "../wasm/loader.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const originExports = Object.freeze({
  buildStagingFrame: "bp52_origin_build_staging_frame",
  buildPackage: "bp52_origin_build",
  authorizeRefund: "bp52_origin_authorize_refund_signature",
  sealRefund: "bp52_origin_seal_refund_signature",
  assembleRefund: "bp52_origin_assemble_refund",
  buildActivation: "bp52_origin_build_activation",
  authorizeActivation: "bp52_origin_authorize_activation_signature",
  sealActivation: "bp52_origin_seal_activation_signature",
  assembleActivation: "bp52_origin_assemble_activation",
  authorizeFunding: "bp52_origin_authorize_funding_signature",
  sealFunding: "bp52_origin_seal_funding_signature",
  assembleFunding: "bp52_origin_assemble_funding",
  commitSessionNonceShare: "bp52_origin_commit_session_nonce_share",
  deriveSessionNonce: "bp52_origin_derive_session_nonce",
});

let originPromise;
let walletPromise;
let originTail = Promise.resolve();
let walletTail = Promise.resolve();

function canonicalHexBytes(value, length, label) {
  if (
    typeof value !== "string" ||
    value.length !== length * 2 ||
    !/^[0-9a-f]+$/.test(value)
  ) {
    throw new Error(`${label} is not canonical hexadecimal.`);
  }
  const result = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fixedHexResult(value, field, label) {
  if (
    !value || typeof value !== "object" || Array.isArray(value) ||
    Object.keys(value).length !== 1 || !Object.hasOwn(value, field)
  ) {
    throw new Error(`${label} has an unexpected shape.`);
  }
  canonicalHexBytes(value[field], 32, label).fill(0);
  return Object.freeze({ [field]: value[field] });
}

function requiredFunction(api, name, boundary) {
  if (typeof api[name] !== "function") {
    throw new Error(`${boundary} module has an unexpected interface.`);
  }
}

async function loadOrigin() {
  originPromise ||= (async () => {
    const api = (await instantiateWasm("origin")).exports;
    for (const name of [
      "bp52_origin_abi_version",
      "bp52_origin_max_input_len",
      "bp52_origin_max_output_len",
      "bp52_origin_max_error_len",
      "bp52_origin_begin_input",
      "bp52_origin_input_ptr",
      ...Object.values(originExports),
      "bp52_origin_output_ptr",
      "bp52_origin_output_len",
      "bp52_origin_last_error_ptr",
      "bp52_origin_last_error_len",
      "bp52_origin_clear",
    ]) {
      requiredFunction(api, name, "Origin");
    }
    if (!(api.memory instanceof WebAssembly.Memory) || api.bp52_origin_abi_version() !== 2) {
      throw new Error("Origin module has an unexpected interface.");
    }
    for (const length of [
      api.bp52_origin_max_input_len(),
      api.bp52_origin_max_output_len(),
      api.bp52_origin_max_error_len(),
    ]) {
      if (!Number.isSafeInteger(length) || length <= 0) {
        throw new Error("Origin module reported an invalid boundary size.");
      }
    }
    return api;
  })();
  try {
    return await originPromise;
  } catch (error) {
    originPromise = undefined;
    throw error;
  }
}

async function loadWallet() {
  walletPromise ||= (async () => {
    const api = (await instantiateWasm("wallet")).exports;
    for (const name of [
      "bp52_wallet_set_secret_byte",
      "bp52_wallet_set_sighash_byte",
      "bp52_wallet_derive_public_key",
      "bp52_wallet_derive_staging_descriptor",
      "bp52_wallet_witness_script_byte",
      "bp52_wallet_script_pubkey_byte",
      "bp52_wallet_address_len",
      "bp52_wallet_address_byte",
      "bp52_wallet_sign_sighash_der",
      "bp52_wallet_compact_signature_len",
      "bp52_wallet_compact_signature_byte",
      "bp52_wallet_clear",
    ]) {
      requiredFunction(api, name, "Wallet");
    }
    const compactSignatureLength = api.bp52_wallet_compact_signature_len();
    if (
      !Number.isSafeInteger(compactSignatureLength) ||
      compactSignatureLength <= 0 ||
      compactSignatureLength > 0xffff
    ) {
      throw new Error("Wallet module reported an invalid signature size.");
    }
    return Object.freeze({ api, compactSignatureLength });
  })();
  try {
    return await walletPromise;
  } catch (error) {
    walletPromise = undefined;
    throw error;
  }
}

function serialOrigin(operation) {
  const run = originTail.then(async () => operation(await loadOrigin()));
  originTail = run.catch(() => undefined);
  return run;
}

function serialWallet(operation) {
  const run = walletTail.then(async () => operation(await loadWallet()));
  walletTail = run.catch(() => undefined);
  return run;
}

function checkedRegion(api, pointer, length, maximum, label, allowEmpty = false) {
  if (
    !Number.isSafeInteger(pointer) ||
    !Number.isSafeInteger(length) ||
    pointer < 0 ||
    length < 0 ||
    (!allowEmpty && length === 0) ||
    length > maximum
  ) {
    throw new Error(`${label} has an invalid Wasm region.`);
  }
  const end = pointer + length;
  if (!Number.isSafeInteger(end) || end > api.memory.buffer.byteLength) {
    throw new Error(`${label} exceeds Wasm memory.`);
  }
  return Uint8Array.from(new Uint8Array(api.memory.buffer, pointer, length));
}

function originFailure(api, operation, code) {
  const bytes = checkedRegion(
    api,
    api.bp52_origin_last_error_ptr(),
    api.bp52_origin_last_error_len(),
    api.bp52_origin_max_error_len(),
    "Origin diagnostic",
    true,
  );
  const detail = bytes.length === 0 ? "unknown error" : decoder.decode(bytes);
  return new Error(`${operation} failed (${code}): ${detail}`);
}

function invokeOrigin(api, exportName, input) {
  let request;
  try {
    request = encoder.encode(JSON.stringify(input));
  } catch {
    throw new Error("Origin request is not JSON serializable.");
  }
  const maximumInput = api.bp52_origin_max_input_len();
  if (request.length === 0 || request.length > maximumInput) {
    throw new Error("Origin request exceeds its bounded Wasm interface.");
  }
  try {
    const beginCode = api.bp52_origin_begin_input(request.length);
    if (beginCode !== 0) throw originFailure(api, "Staging origin request", beginCode);
    const pointer = api.bp52_origin_input_ptr();
    const target = checkedRegion(
      api,
      pointer,
      request.length,
      maximumInput,
      "Origin input",
    );
    new Uint8Array(api.memory.buffer, pointer, target.length).set(request);
    const code = api[exportName]();
    if (code !== 0) throw originFailure(api, "Origin operation", code);
    const output = checkedRegion(
      api,
      api.bp52_origin_output_ptr(),
      api.bp52_origin_output_len(),
      api.bp52_origin_max_output_len(),
      "Origin output",
    );
    return JSON.parse(decoder.decode(output));
  } finally {
    request.fill(0);
    api.bp52_origin_clear();
  }
}

async function sign(secretHex, digestHex) {
  const secret = canonicalHexBytes(secretHex, 32, "Local secret key");
  const digest = canonicalHexBytes(digestHex, 32, "Authorized origin digest");
  return serialWallet(({ api, compactSignatureLength }) => {
    api.bp52_wallet_clear();
    try {
      for (let index = 0; index < secret.length; index += 1) {
        if (
          api.bp52_wallet_set_secret_byte(index, secret[index]) !== 1 ||
          api.bp52_wallet_set_sighash_byte(index, digest[index]) !== 1
        ) {
          throw new Error("Wallet rejected origin signing material.");
        }
      }
      if (api.bp52_wallet_sign_sighash_der() === 0) {
        throw new Error("Wallet could not sign the authorized origin digest.");
      }
      return hex(Uint8Array.from(
        { length: compactSignatureLength },
        (_, index) => api.bp52_wallet_compact_signature_byte(index),
      ));
    } finally {
      api.bp52_wallet_clear();
      secret.fill(0);
      digest.fill(0);
    }
  });
}

async function createSignature(input, authorizeExport, sealExport) {
  const { localSecretKeyHex, ...publicInput } = input ?? {};
  return serialOrigin(async (api) => {
    const authorization = invokeOrigin(api, authorizeExport, publicInput);
    const candidateSignatureHex = await sign(
      localSecretKeyHex,
      authorization.sighashHex,
    );
    return invokeOrigin(api, sealExport, { ...publicInput, candidateSignatureHex });
  });
}

function deriveStagingDescriptor(input) {
  const secret = canonicalHexBytes(input?.privateKeyHex, 32, "Staging secret key");
  const networkCode = input?.walletNetworkCode;
  if (!Number.isSafeInteger(networkCode) || networkCode < 0 || networkCode > 255) {
    secret.fill(0);
    throw new Error("Staging wallet network code is invalid.");
  }
  return serialWallet(({ api }) => {
    api.bp52_wallet_clear();
    try {
      for (let index = 0; index < secret.length; index += 1) {
        if (api.bp52_wallet_set_secret_byte(index, secret[index]) !== 1) {
          throw new Error("Wallet rejected staging key material.");
        }
      }
      if (api.bp52_wallet_derive_public_key() !== 1) return null;
      if (api.bp52_wallet_derive_staging_descriptor(networkCode) !== 1) {
        throw new Error("Wallet could not derive the staging descriptor.");
      }
      const addressLength = api.bp52_wallet_address_len();
      if (!Number.isSafeInteger(addressLength) || addressLength < 8 || addressLength > 128) {
        throw new Error("Wallet returned an invalid staging address length.");
      }
      return {
        address: decoder.decode(Uint8Array.from(
          { length: addressLength },
          (_, index) => api.bp52_wallet_address_byte(index),
        )),
        witnessScriptHex: hex(Uint8Array.from(
          { length: 35 },
          (_, index) => api.bp52_wallet_witness_script_byte(index),
        )),
        scriptPubKeyHex: hex(Uint8Array.from(
          { length: 34 },
          (_, index) => api.bp52_wallet_script_pubkey_byte(index),
        )),
      };
    } finally {
      api.bp52_wallet_clear();
      secret.fill(0);
    }
  });
}

export const fundingEngine = Object.freeze({
  deriveStagingDescriptor,
  buildStagingFrame(input) {
    return serialOrigin((api) => invokeOrigin(
      api,
      originExports.buildStagingFrame,
      input,
    ));
  },

  buildPackage(input) {
    return serialOrigin((api) => invokeOrigin(api, originExports.buildPackage, input));
  },

  createRefundSignature(input) {
    return createSignature(input, originExports.authorizeRefund, originExports.sealRefund);
  },

  verifyAndAssembleRefund(input) {
    return serialOrigin((api) => invokeOrigin(api, originExports.assembleRefund, input));
  },

  buildActivation(input) {
    return serialOrigin((api) => invokeOrigin(api, originExports.buildActivation, input));
  },

  createActivationSignature(input) {
    return createSignature(
      input,
      originExports.authorizeActivation,
      originExports.sealActivation,
    );
  },

  verifyAndAssembleActivation(input) {
    return serialOrigin((api) => invokeOrigin(api, originExports.assembleActivation, input));
  },

  createFundingSignature(input) {
    return createSignature(input, originExports.authorizeFunding, originExports.sealFunding);
  },

  verifyAndAssembleFunding(input) {
    return serialOrigin((api) => invokeOrigin(api, originExports.assembleFunding, input));
  },

  commitSessionNonceShare(input) {
    return serialOrigin((api) => fixedHexResult(
      invokeOrigin(api, originExports.commitSessionNonceShare, input),
      "commitment",
      "Session nonce commitment",
    ));
  },

  deriveSessionNonce(input) {
    return serialOrigin((api) => fixedHexResult(
      invokeOrigin(api, originExports.deriveSessionNonce, input),
      "sessionNonce",
      "Derived session nonce",
    ));
  },
});
