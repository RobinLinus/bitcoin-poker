import assert from "node:assert/strict";
import test from "node:test";

import { ChainExchangePackage, ChainSetupKind } from "./chain-runtime.js";
import {
  shouldDeferUntilGraph,
  shouldGenerateLocalLamport,
} from "./setup-schedule.js";

function descriptorEvent(hasDescriptor) {
  return {
    applicable: true,
    setupKind: ChainSetupKind.DESCRIPTOR_SIGNATURE,
    localLamportBundle: new Uint8Array(),
    hasDescriptor,
  };
}

test("Lamport generation waits for both descriptor signatures", () => {
  assert.equal(shouldGenerateLocalLamport(descriptorEvent(false)), false);
  assert.equal(shouldGenerateLocalLamport(descriptorEvent(true)), true);
});

test("Lamport generation ignores unrelated or already-complete events", () => {
  assert.equal(shouldGenerateLocalLamport({
    ...descriptorEvent(true),
    setupKind: ChainSetupKind.LAMPORT_PUBLIC_BUNDLE,
  }), false);
  assert.equal(shouldGenerateLocalLamport({
    ...descriptorEvent(true),
    localLamportBundle: Uint8Array.of(1),
  }), false);
});

test("graph-bound replay waits for graph compilation", () => {
  assert.equal(shouldDeferUntilGraph({
    packageId: ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE,
    hasGraph: false,
  }), false);
  assert.equal(shouldDeferUntilGraph({
    packageId: ChainExchangePackage.GRAPH_ROOT_COMMITMENT,
    hasGraph: false,
  }), true);
  assert.equal(shouldDeferUntilGraph({
    packageId: ChainExchangePackage.PREAUTHORIZATION_OPENING,
    hasGraph: true,
  }), false);
});
