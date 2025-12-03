# 🦉 Ethereum "Quiz" Honeypot Tracker

> **Automated Reconnaissance System**  
> *Scanning Etherscan V2 API for `responseHash` manipulation patterns.*

## 🕵️‍♂️ What is this?
This repository runs a scheduled GitHub Action (every 6 hours) to detect a specific class of Smart Contract Honeypots often disguised as "Quiz Games" or "Treasure Hunts" (e.g., `Owl_Treasure`, `the_BEST_Quiz`).

### The Scam Mechanism
1. **The Bait:** The contract holds a balance (e.g., 1.0 ETH) and asks a simple question (e.g., "Who is the CEO of Tesla?").
2. **The Trap:** The `Try()` function compares your answer's hash against a stored `responseHash`.
3. **The Trick:** The scammer calls `Start()` or `New()` in a private transaction (or via an internal transaction from another contract) to set the `responseHash` to something impossible to guess, or a hash that doesn't match the English answer.
4. **The Result:** Users send ETH attempting to answer, but the hash never matches, and the ETH remains locked until the admin drains it.

## 📊 Live Scam Database
*This list is automatically updated by the `honeypot-scanner.ts` script.*

<!-- SCAM_LIST_START -->
| Name | Address | Balance | Status | First Seen |
|---|---|---|---|---|
| Owl_Treasure | [0x777791...](https://etherscan.io/address/0x7777915efd4fa386104914c264242d40ec4b451a) | **0.1000** | ACTIVE | 2025-12-03 |

*Last Updated: 2025-12-03 22:38:18 UTC*
<!-- SCAM_LIST_END -->

## 🛠️ How it Works
1. **Scan:** Queries Etherscan for recent transactions matching specific method IDs (`Start`, `Try`).
2. **Verify:** Downloads source code and checks for specific variable fingerprints (`responseHash`, `isAdmin`).
3. **Track:** Stores identified contracts in `scams.json`.
4. **Report:** Updates the table above with current balances and status.

## ⚠️ Disclaimer
**DO NOT INTERACT WITH THESE CONTRACTS.**
This data is for educational and security research purposes only. These contracts are designed to steal funds.

---
*Powered by Bun, Etherscan V2, and GitHub Actions.*
