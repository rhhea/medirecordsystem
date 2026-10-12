# MedChain — consent-controlled medical records

Patient uploads → backend AES-256-GCM encrypts → IPFS (CID) → CID + SHA-256 on-chain.
Doctor opens → backend verifies wallet signature → `checkAccess` on contract → decrypt → re-verify SHA-256 → access logged on-chain.

## Setup (Node 18+; Node 20 recommended)

    npm install
    cp .env.example .env

Optional but recommended: run a real IPFS node (https://docs.ipfs.tech/install/command-line/)

    ipfs init        # first time only
    ipfs daemon

If no daemon is running and `MOCK_IPFS=true`, files are stored in `backend/mock-ipfs/` instead.

## Run (3 terminals)

    npm run node        # 1. local chain, prints 20 test accounts + private keys
    npm run deploy      # 2. compile + deploy, writes backend/contract.json
    npm start           # 3. backend + UI at http://localhost:3000

## MetaMask

Use a separate browser profile. Import Hardhat accounts #1, #2, #3 using the private keys printed by `npm run node`:

| MetaMask account | Role |
|---|---|
| #1 | Patient |
| #2 | Doctor (granted access) |
| #3 | Doctor (never granted) |

Account #0 is the backend logger wallet. Do not import it into MetaMask.
The app adds/switches to the Hardhat network (chainId 31337, RPC http://127.0.0.1:8545) automatically.

If MetaMask later complains about nonces after restarting `npm run node`:
Settings → Advanced → Clear activity tab data.

## Demo script

1. **Patient (#1):** connect, upload a `.txt` file. Note the record ID.
2. **Patient:** grant account #2 access for **2 minutes**.
3. **Doctor (#2):** switch account, connect, open the record. Hash verified, file shown.
4. **Expiry:** start "Live access status" and watch the countdown reach "Expired". Open again: denied.
5. **Revoke:** patient grants #2 again (1 hour), then revokes. Doctor retries: **denied**.
6. **Unauthorized (#3):** open the record: denied.
7. **Tamper:** grant access again, press "Tamper with stored file", doctor opens: **integrity failure, file withheld**. Press "Restore original".
8. **Audit timeline:** load it. Every upload, grant, revoke, allowed and denied open, and hash mismatch is listed with its tx hash.

## Sepolia (optional)

Add a `sepolia` network to `hardhat.config.js`, deploy with `--network sepolia`, set `RPC_URL`,
`LOGGER_PRIVATE_KEY` (the deployer key) and `EXPLORER_URL=https://sepolia.etherscan.io` in `.env`.
Tx hashes in the UI then link to Etherscan. Note: Sepolia is fine for a final demo, but local is faster and reliable.

## Future work

Keys are held by the backend (fine for a demo, a single point of trust). A stronger design wraps each file's
AES key with the doctor's public key (ECIES / RSA-OAEP) and stores the wrapped key per grant, so the server never
holds a usable key.

## Notes

- `backend/db.json` holds the AES keys (demo only). Do not commit it.
- Tamper demo uses AES-GCM, so naive ciphertext edits are caught by the auth tag. The demo re-encrypts an altered
  plaintext to show the on-chain SHA-256 check catching it as well.
