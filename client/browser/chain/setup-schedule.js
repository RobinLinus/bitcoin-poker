import { ChainExchangePackage, ChainSetupKind } from "./chain-runtime.js";

/**
 * Setup frames after the public-key exchange are graph-bound. During recovery
 * they may arrive before an omitted local bundle has been regenerated and the
 * graph compiled. That is a transient dependency, not a protocol mismatch.
 */
export function shouldDeferUntilGraph({ packageId, hasGraph }) {
  return packageId !== ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE && !hasGraph;
}

export function shouldGenerateLocalLamport({
  applicable,
  setupKind,
  localLamportBundle,
  hasDescriptor,
}) {
  return Boolean(
    applicable &&
    setupKind === ChainSetupKind.DESCRIPTOR_SIGNATURE &&
    localLamportBundle instanceof Uint8Array &&
    localLamportBundle.byteLength === 0 &&
    hasDescriptor
  );
}
