# Bitcoin Core qualification

Run `chain/scripts/bitcoin-core-regtest.sh --docker --suite dlog --require`
from the repository root. The runner uses a cached Core image, creates an isolated
regtest node, and cleans it up afterward. `--native` uses locally installed Core.

The dlog suite checks card gates, reusable reveal adaptors, showdown/payout, and
a fully prepared short-stack hand with confirmation and timeout checks.
`--suite dlog-graph` runs only the complete graph campaign; `--suite all` currently
runs the same campaigns as `dlog`. See the
[implementation status](../../client/docs/DLOG_ONCHAIN_IMPLEMENTATION.md).
