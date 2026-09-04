#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";

import { createTransactionInspector } from "../browser/chain-adapter/transaction-runtime.js";

const HOST = "127.0.0.1";
const PORT = Number.parseInt(process.argv[2] ?? "3001", 10);
const FUNDING_VALUE = 27_000;
const GENESIS = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
const CHECKPOINT_HEIGHT = 339_000;
const CHECKPOINT = "000001ce7d14b7c4eb8f989d3825b4212ea6a6a30f62df8bf6486b69a247242b";
const TIP_HEIGHT = CHECKPOINT_HEIGHT + 10;
const TIP = "11".repeat(32);
const CONFIRMED = Object.freeze({
  confirmed: true,
  block_height: TIP_HEIGHT,
  block_hash: TIP,
  block_time: 1_750_000_000,
});

if (!Number.isSafeInteger(PORT) || PORT < 1 || PORT > 65_535) {
  throw new Error("mock Esplora port must be a valid TCP port");
}

const wasmBytes = await readFile(new URL(
  "../crates/bp52-relay-server/web/wasm/transaction.wasm",
  import.meta.url,
));
const instantiated = await WebAssembly.instantiate(wasmBytes, {});
const wasmInstance = instantiated instanceof WebAssembly.Instance
  ? instantiated
  : instantiated.instance;
const inspector = createTransactionInspector({ instantiate: async () => wasmInstance });
const transactions = new Map();
const spentBy = new Map();
const fundingByAddress = new Map();
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function hex(value) {
  return Buffer.from(value).toString("hex");
}

function bech32Polymod(values) {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) {
      if ((top >>> index) & 1) checksum ^= [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3][index];
    }
  }
  return checksum >>> 0;
}

function witnessProgram(address) {
  const separator = address.lastIndexOf("1");
  const prefix = address.slice(0, separator);
  if (separator < 1 || prefix !== "tb" || address !== address.toLowerCase()) {
    throw new Error("mock funding address is not canonical testnet bech32");
  }
  const values = [...address.slice(separator + 1)].map((character) => BECH32_CHARSET.indexOf(character));
  if (values.length < 7 || values.some((value) => value < 0)) {
    throw new Error("mock funding address has invalid bech32 data");
  }
  const expandedPrefix = [
    ...[...prefix].map((character) => character.charCodeAt(0) >>> 5),
    0,
    ...[...prefix].map((character) => character.charCodeAt(0) & 31),
  ];
  if (bech32Polymod([...expandedPrefix, ...values]) !== 1 || values[0] !== 0) {
    throw new Error("mock funding address has an invalid witness checksum or version");
  }
  let accumulator = 0;
  let bits = 0;
  const output = [];
  for (const value of values.slice(1, -6)) {
    accumulator = (accumulator << 5) | value;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
    }
  }
  if (bits >= 5 || ((accumulator << (8 - bits)) & 0xff) !== 0 || output.length !== 32) {
    throw new Error("mock funding address is not a canonical P2WSH program");
  }
  return Buffer.from(output);
}

async function fundingTransaction(address) {
  const existing = fundingByAddress.get(address);
  if (existing) return existing;
  const program = witnessProgram(address);
  const raw = Buffer.concat([
    Buffer.from("0200000001", "hex"),
    Buffer.alloc(32),
    Buffer.from("ffffffff020000ffffffff01", "hex"),
    Buffer.from([FUNDING_VALUE & 0xff, FUNDING_VALUE >>> 8, 0, 0, 0, 0, 0, 0]),
    Buffer.from([34, 0, 32]),
    program,
    Buffer.alloc(4),
  ]);
  const inspected = await inspector.inspect(raw);
  const transaction = { txid: inspected.displayTxidHex, raw: Buffer.from(inspected.raw), inspected };
  fundingByAddress.set(address, transaction);
  transactions.set(transaction.txid, transaction);
  return transaction;
}

function corsHeaders(contentType) {
  return {
    "access-control-allow-origin": "http://127.0.0.1:3000",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "cache-control": "no-store",
    ...(contentType ? { "content-type": contentType } : {}),
  };
}

function send(response, status, body, contentType = "text/plain; charset=utf-8") {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  response.writeHead(status, { ...corsHeaders(contentType), "content-length": payload.byteLength });
  response.end(payload);
}

function json(response, value) {
  send(response, 200, JSON.stringify(value), "application/json");
}

async function requestBody(request, maximum = 16 * 1024 * 1024) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.byteLength;
    if (length > maximum) throw new Error("request exceeds mock Esplora bound");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === "OPTIONS") {
      response.writeHead(204, corsHeaders());
      response.end();
      return;
    }
    const url = new URL(request.url ?? "/", `http://${HOST}:${PORT}`);
    if (request.method === "GET" && url.pathname === "/blocks/tip/hash") {
      send(response, 200, TIP);
      return;
    }
    if (request.method === "GET" && url.pathname === "/fee-estimates") {
      json(response, { "1": 1, "2": 1, "6": 1 });
      return;
    }
    const blockHeight = url.pathname.match(/^\/block-height\/(\d+)$/u);
    if (request.method === "GET" && blockHeight) {
      const height = Number.parseInt(blockHeight[1], 10);
      const blockHash = height === 0
        ? GENESIS
        : height === CHECKPOINT_HEIGHT
          ? CHECKPOINT
          : height === TIP_HEIGHT
            ? TIP
            : null;
      send(response, blockHash ? 200 : 404, blockHash ?? "not found");
      return;
    }
    const block = url.pathname.match(/^\/block\/([0-9a-f]{64})$/u);
    if (request.method === "GET" && block) {
      if (block[1] !== TIP) return send(response, 404, "not found");
      json(response, { id: TIP, height: TIP_HEIGHT });
      return;
    }
    const address = url.pathname.match(/^\/address\/([a-zA-Z0-9]+)\/utxo$/u);
    if (request.method === "GET" && address) {
      const { txid } = await fundingTransaction(address[1]);
      json(response, spentBy.has(`${txid}:0`) ? [] : [{
        txid,
        vout: 0,
        value: FUNDING_VALUE,
        status: CONFIRMED,
      }]);
      return;
    }
    const raw = url.pathname.match(/^\/tx\/([0-9a-f]{64})\/raw$/u);
    if (request.method === "GET" && raw) {
      const transaction = transactions.get(raw[1]);
      send(response, transaction ? 200 : 404, transaction?.raw ?? "not found", "application/octet-stream");
      return;
    }
    const status = url.pathname.match(/^\/tx\/([0-9a-f]{64})\/status$/u);
    if (request.method === "GET" && status) {
      if (!transactions.has(status[1])) {
        return send(response, 404, "not found");
      }
      json(response, CONFIRMED);
      return;
    }
    const outspend = url.pathname.match(/^\/tx\/([0-9a-f]{64})\/outspend\/(\d+)$/u);
    if (request.method === "GET" && outspend) {
      const spending = spentBy.get(`${outspend[1]}:${Number.parseInt(outspend[2], 10)}`);
      json(response, spending ? {
        spent: true,
        txid: spending.txid,
        vin: spending.vin,
        status: CONFIRMED,
      } : { spent: false });
      return;
    }
    if (request.method === "POST" && url.pathname === "/tx") {
      const body = await requestBody(request);
      if (!/^(?:[0-9a-f]{2})+$/u.test(body)) throw new Error("broadcast body is not raw hex");
      const inspected = await inspector.inspect(Buffer.from(body, "hex"));
      const txid = inspected.displayTxidHex;
      transactions.set(txid, { raw: Buffer.from(inspected.raw), inspected });
      inspected.inputs.forEach((input, vin) => {
        const key = `${hex(input.previousOutpoint.displayTxid)}:${input.previousOutpoint.vout}`;
        spentBy.set(key, { txid, vin });
      });
      send(response, 200, txid);
      return;
    }
    send(response, 404, "not found");
  } catch (error) {
    console.error("[mock-esplora]", error);
    send(response, 500, "mock Esplora error");
  }
});

server.listen(PORT, HOST, () => {
  console.log(`BP52 mock Esplora listening on http://${HOST}:${PORT}`);
});
