# Key Broker demo

A simple key broker protocol with client and server components implemented in Rust.

Client and server are respectively [RATS](https://www.rfc-editor.org/rfc/rfc9334.html#figure-1) attester and relying party.

[Veraison](https://github.com/veraison/services) is used as the verifier.

```mermaid
flowchart LR
    A[KB client] -->|Evidence fa:fa-receipt| RP[KB server]
    RP -->|Key fa:fa-key| A
    RP -->|Evidence fa:fa-receipt| V[Veraison]
    V -->|EAR fa:fa-check-square| RP
```
