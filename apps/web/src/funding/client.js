import { WorkerRpcClient } from "../workers/rpc-client.js";

const FUNDING_METHODS = ['deriveStagingDescriptor', 'buildStagingFrame', 'buildPackage', 'createRefundSignature', 'verifyAndAssembleRefund', 'buildActivation', 'createActivationSignature', 'verifyAndAssembleActivation', 'createFundingSignature', 'verifyAndAssembleFunding', 'commitSessionNonceShare', 'deriveSessionNonce'];

export function createFundingClient() {
    const rpc = new WorkerRpcClient(
      new Worker(new URL("./worker.js", import.meta.url), {
        type: "module",
        name: "bp52-origin-secret",
      }),
      {
        timeoutMs: 15 * 60 * 1_000,
        closedError: "origin Worker is closed",
        cancelledError: "origin Worker was cancelled",
        timeoutError: (type) => `origin Worker request timed out: ${type}`,
        rejectedError: "origin Worker rejected the request",
        workerError: "origin Worker failed",
      },
    );
    return Object.freeze(
      Object.fromEntries(FUNDING_METHODS.map((name) => [
        name,
        async (input) => (await rpc.request("call", { name, input })).result,
      ])),
    );
}
