#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const declarationPath = join(repositoryRoot, "toolchains", "browser-wasm-artifacts.json");
const publicDirectory = join(repositoryRoot, "apps", "web", "public", "wasm");
const publishedManifestPath = join(publicDirectory, "manifest.json");
const defaultBuildDirectory = join(
  repositoryRoot,
  "target",
  "browser-wasm",
  "wasm32-unknown-unknown",
  "release",
);

const allowedDeclarationKeys = new Set([
  "schemaVersion",
  "rustToolchain",
  "target",
  "profile",
  "artifacts",
]);
const allowedArtifactKeys = new Set([
  "name",
  "package",
  "cargoFile",
  "publicFile",
  "securityBoundary",
  "maximumBytes",
  "expectedAbiVersion",
  "requiredExports",
]);

function fail(message) {
  throw new Error(`browser Wasm artifact check failed: ${message}`);
}

function exactKeys(value, allowed, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${label} contains unknown key ${key}`);
  }
  for (const key of allowed) {
    if (!(key in value)) fail(`${label} is missing ${key}`);
  }
}

function nonemptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a nonempty string`);
  }
  return value;
}

function safeFileName(value, label) {
  const name = nonemptyString(value, label);
  if (!/^[a-z0-9][a-z0-9_.-]*$/.test(name) || name.includes("..")) {
    fail(`${label} is not a safe file name`);
  }
  return name;
}

async function readJson(path, label) {
  let text;
  try {
    text = await readFile(path, "utf8");
  } catch {
    fail(`${label} is missing at ${path}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail(`${label} is not valid JSON`);
  }
}

async function loadDeclaration() {
  const declaration = await readJson(declarationPath, "artifact declaration");
  exactKeys(declaration, allowedDeclarationKeys, "artifact declaration");
  if (declaration.schemaVersion !== 1) fail("unsupported declaration schema");
  if (declaration.rustToolchain !== "1.98.0") fail("unexpected Rust toolchain");
  if (declaration.target !== "wasm32-unknown-unknown") fail("unexpected target");
  if (declaration.profile !== "release") fail("unexpected build profile");
  if (!Array.isArray(declaration.artifacts) || declaration.artifacts.length === 0) {
    fail("artifact declaration must contain artifacts");
  }

  const names = new Set();
  const packages = new Set();
  const cargoFiles = new Set();
  const publicFiles = new Set();
  const boundaries = new Set();
  for (const [index, artifact] of declaration.artifacts.entries()) {
    const label = `artifacts[${index}]`;
    exactKeys(artifact, allowedArtifactKeys, label);
    safeFileName(artifact.name, `${label}.name`);
    nonemptyString(artifact.package, `${label}.package`);
    safeFileName(artifact.cargoFile, `${label}.cargoFile`);
    safeFileName(artifact.publicFile, `${label}.publicFile`);
    nonemptyString(artifact.securityBoundary, `${label}.securityBoundary`);
    if (!Number.isSafeInteger(artifact.maximumBytes) || artifact.maximumBytes <= 8) {
      fail(`${label}.maximumBytes must be a positive safe integer`);
    }
    if (
      artifact.expectedAbiVersion !== null &&
      (!Number.isSafeInteger(artifact.expectedAbiVersion) || artifact.expectedAbiVersion < 1)
    ) {
      fail(`${label}.expectedAbiVersion must be null or a positive safe integer`);
    }
    if (!Array.isArray(artifact.requiredExports) || artifact.requiredExports.length === 0) {
      fail(`${label}.requiredExports must be a nonempty array`);
    }
    for (const [exportIndex, exportName] of artifact.requiredExports.entries()) {
      nonemptyString(exportName, `${label}.requiredExports[${exportIndex}]`);
    }
    for (const [set, value, field] of [
      [names, artifact.name, "name"],
      [packages, artifact.package, "package"],
      [cargoFiles, artifact.cargoFile, "cargoFile"],
      [publicFiles, artifact.publicFile, "publicFile"],
      [boundaries, artifact.securityBoundary, "securityBoundary"],
    ]) {
      if (set.has(value)) fail(`${field} ${value} is duplicated`);
      set.add(value);
    }
  }
  return declaration;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateModule(bytes, artifact, label) {
  if (bytes.byteLength > artifact.maximumBytes) {
    fail(`${label} exceeds its ${artifact.maximumBytes}-byte limit`);
  }
  if (
    bytes.byteLength < 8 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d ||
    bytes[4] !== 0x01 ||
    bytes[5] !== 0x00 ||
    bytes[6] !== 0x00 ||
    bytes[7] !== 0x00
  ) {
    fail(`${label} is not a WebAssembly 1 binary`);
  }

  let module;
  try {
    module = new WebAssembly.Module(bytes);
  } catch {
    fail(`${label} does not validate as WebAssembly`);
  }
  const imports = WebAssembly.Module.imports(module);
  if (imports.length !== 0) {
    fail(`${label} unexpectedly imports ${imports[0].module}.${imports[0].name}`);
  }
  const exports = new Set(WebAssembly.Module.exports(module).map(({ name }) => name));
  for (const name of artifact.requiredExports) {
    if (!exports.has(name)) fail(`${label} is missing required export ${name}`);
  }
  if (artifact.expectedAbiVersion !== null) {
    const abiExport = `bp52_${artifact.name}_abi_version`;
    let actualAbiVersion;
    try {
      const instance = new WebAssembly.Instance(module, {});
      actualAbiVersion = instance.exports[abiExport]();
    } catch {
      fail(`${label} cannot execute ABI export ${abiExport}`);
    }
    if (actualAbiVersion !== artifact.expectedAbiVersion) {
      fail(
        `${label} has ABI ${actualAbiVersion}; expected ${artifact.expectedAbiVersion}`,
      );
    }
  }
}

async function readAndValidate(path, artifact, label) {
  let bytes;
  try {
    bytes = await readFile(path);
  } catch {
    fail(`${label} is missing at ${path}`);
  }
  validateModule(bytes, artifact, label);
  return bytes;
}

async function atomicCopy(source, destination) {
  await mkdir(dirname(destination), { recursive: true });
  const temporary = `${destination}.tmp-${process.pid}`;
  try {
    await copyFile(source, temporary);
    await chmod(temporary, 0o644);
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

async function atomicWrite(path, contents) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  try {
    await writeFile(temporary, contents, { encoding: "utf8", mode: 0o644 });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

function manifestEntry(artifact, bytes) {
  return {
    name: artifact.name,
    url: `/wasm/${artifact.publicFile}`,
    sha256: digest(bytes),
    sizeBytes: bytes.byteLength,
    securityBoundary: artifact.securityBoundary,
  };
}

async function validateBuilt(declaration, buildDirectory) {
  const entries = [];
  for (const artifact of declaration.artifacts) {
    const bytes = await readAndValidate(
      join(buildDirectory, artifact.cargoFile),
      artifact,
      `built ${artifact.name} artifact`,
    );
    entries.push(manifestEntry(artifact, bytes));
  }
  return entries;
}

async function publish(declaration, buildDirectory) {
  const entries = await validateBuilt(declaration, buildDirectory);
  for (const artifact of declaration.artifacts) {
    await atomicCopy(
      join(buildDirectory, artifact.cargoFile),
      join(publicDirectory, artifact.publicFile),
    );
  }
  const manifest = {
    schemaVersion: 1,
    target: declaration.target,
    profile: declaration.profile,
    artifacts: entries,
  };
  await atomicWrite(publishedManifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return entries;
}

async function checkPublished(declaration) {
  const manifest = await readJson(publishedManifestPath, "published manifest");
  const expectedTopLevelKeys = new Set(["schemaVersion", "target", "profile", "artifacts"]);
  exactKeys(manifest, expectedTopLevelKeys, "published manifest");
  if (
    manifest.schemaVersion !== 1 ||
    manifest.target !== declaration.target ||
    manifest.profile !== declaration.profile ||
    !Array.isArray(manifest.artifacts) ||
    manifest.artifacts.length !== declaration.artifacts.length
  ) {
    fail("published manifest does not match its declaration");
  }

  const allowedEntryKeys = new Set([
    "name",
    "url",
    "sha256",
    "sizeBytes",
    "securityBoundary",
  ]);
  const entries = [];
  for (const [index, artifact] of declaration.artifacts.entries()) {
    const entry = manifest.artifacts[index];
    exactKeys(entry, allowedEntryKeys, `published manifest artifacts[${index}]`);
    const bytes = await readAndValidate(
      join(publicDirectory, artifact.publicFile),
      artifact,
      `published ${artifact.name} artifact`,
    );
    const expected = manifestEntry(artifact, bytes);
    if (JSON.stringify(entry) !== JSON.stringify(expected)) {
      fail(`published manifest entry for ${artifact.name} is stale`);
    }
    entries.push(entry);
  }
  return entries;
}

function usage() {
  return [
    "usage:",
    "  package-browser-wasm.mjs --check",
    "  package-browser-wasm.mjs --validate-built [--from DIRECTORY]",
    "  package-browser-wasm.mjs --write [--from DIRECTORY]",
  ].join("\n");
}

let operation = "--check";
let buildDirectory = defaultBuildDirectory;
const args = process.argv.slice(2);
if (args.length > 0) operation = args.shift();
while (args.length > 0) {
  const option = args.shift();
  if (option !== "--from" || args.length === 0) throw new Error(usage());
  buildDirectory = args.shift();
}
if (!["--check", "--validate-built", "--write"].includes(operation)) {
  throw new Error(usage());
}

const declaration = await loadDeclaration();
let entries;
if (operation === "--check") {
  entries = await checkPublished(declaration);
} else if (operation === "--validate-built") {
  entries = await validateBuilt(declaration, buildDirectory);
} else {
  entries = await publish(declaration, buildDirectory);
}
for (const entry of entries) {
  console.log(`${entry.name}: ${entry.sizeBytes} bytes sha256:${entry.sha256}`);
}
