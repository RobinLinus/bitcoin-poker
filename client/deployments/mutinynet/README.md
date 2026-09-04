# Mutinynet diagnostic profile

The prototype adapter is configured for the public Esplora endpoint:

```text
https://mutinynet.com/api
```

The compiled profile pins:

- custom Signet challenge
  `512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae`;
- Signet genesis
  `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`;
- checkpoint height `339000` and block hash
  `000001ce7d14b7c4eb8f989d3825b4212ea6a6a30f62df8bf6486b69a247242b`.

The compiled exact network identifier commits to the complete challenge, but
Esplora does not expose that challenge for independent observation. The
adapter therefore verifies the shared Signet genesis, the pinned checkpoint,
and mutually consistent tip endpoints before use and immediately before
broadcasting. The checkpoint distinguishes this endpoint from another signet;
it does not make the public service trustless. The service can still censor,
delay, or equivocate about newer chain data.

Mutinynet currently uses a custom Bitcoin Inquisition build and targets
30-second blocks. Its public deployment may change independently, so a failed
profile check must stop the client rather than silently updating the pinned
checkpoint or challenge.

The browser client runs the complete research game against this deployment.
Each participant funds exactly ₿27,000; the resulting game uses ₿20,000 stacks
and ₿100/₿200 blinds. After both deposits confirm, origin construction, refund
authorization, DEAL, graph authorization, and activation advance without a
manual setup or recovery step.

Each browser remains responsible for its own durable signed artifacts and
private state. Esplora is only an observation and broadcast adapter; it is not
game storage, a wallet, or a trustless chain verifier. The independent native
application and its own deployment copy live in [`client-cli/`](../../../client-cli/).
