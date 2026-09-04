#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const clientDirectory = dirname(dirname(fileURLToPath(import.meta.url)));
const browserDirectory = join(clientDirectory, "browser");
const relayWebDirectory = join(
  clientDirectory,
  "crates",
  "bp52-relay-server",
  "web",
);

async function discoverTests(directory) {
  const tests = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      tests.push(...await discoverTests(path));
    } else if (entry.isFile() && entry.name.endsWith(".test.mjs")) {
      tests.push(path);
    }
  }
  return tests;
}

const tests = [
  ...await discoverTests(browserDirectory),
  ...await discoverTests(relayWebDirectory),
]
  .sort()
  .map((path) => relative(clientDirectory, path));

if (tests.length === 0) {
  throw new Error("No browser tests were discovered.");
}

process.stdout.write(`Running ${tests.length} fast browser contract files.\n`);
const child = spawn(process.execPath, ["--test", ...tests], {
  cwd: clientDirectory,
  stdio: "inherit",
});

child.once("error", (error) => {
  throw error;
});
child.once("exit", (code, signal) => {
  if (signal !== null) {
    process.stderr.write(`Browser tests terminated by ${signal}.\n`);
    process.exitCode = 1;
  } else {
    process.exitCode = code ?? 1;
  }
});
