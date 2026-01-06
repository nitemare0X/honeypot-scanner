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
| x_X_Game | [0xa46c2b...](https://etherscan.io/address/0xa46c2b718adfff25098417ad0b5d208c832260b1) | **45.0000** | ACTIVE | 2025-12-30 |
| pix_quiz | [0xa9b974...](https://etherscan.io/address/0xa9b9743193e9b57a99b2ca79ba2c3879fefaff53) | **40.0000** | ACTIVE | 2026-01-02 |
| The_best_QUIZ | [0x58601b...](https://etherscan.io/address/0x58601b315360bb7d4b8d7cc291823e4cd9c43d58) | **40.0000** | ACTIVE | 2026-01-05 |
| Owl_Treasure | [0x777791...](https://etherscan.io/address/0x7777915efd4fa386104914c264242d40ec4b451a) | **0.0000** | DRAINED | 2025-12-03 |
| Owl_Treasure | [0x777784...](https://etherscan.io/address/0x77778420b93c8c6dae434f684cbff2300f847da0) | **0.0000** | DRAINED | 2025-12-04 |
| Owl_Treasure | [0x77771c...](https://etherscan.io/address/0x77771c09423b1a8c3e30271a925c33bf6d187e22) | **0.0000** | DRAINED | 2025-12-04 |
| x_x_game | [0x917113...](https://etherscan.io/address/0x9171134263d7028fb4461b2cad1cfa6211798173) | **0.0000** | DRAINED | 2025-12-04 |
| Owl_Treasure | [0x777734...](https://etherscan.io/address/0x777734e6fdddbe3550d43a30d522564bd5218324) | **0.0000** | DRAINED | 2025-12-04 |
| PI_quiz | [0x4c8909...](https://etherscan.io/address/0x4c8909037ae2ac83ffcc30a646c2b412a9bc304c) | **0.0000** | DRAINED | 2025-12-08 |
| the_BEST_QUIZ | [0xdd0f88...](https://etherscan.io/address/0xdd0f88bfdb941922ce41ac30804f01703ac3feb1) | **0.0000** | DRAINED | 2025-12-10 |
| x_x_Game | [0x40b62b...](https://etherscan.io/address/0x40b62bf104d242313c5977f50350d46b9d4300d6) | **0.0000** | DRAINED | 2025-12-12 |
| PI_Quiz | [0x532d28...](https://etherscan.io/address/0x532d2881e453701e1b6c18b60a9f9ab49d00b34a) | **0.0000** | DRAINED | 2025-12-14 |
| The_best_quiz | [0x2fd9eb...](https://etherscan.io/address/0x2fd9eb20724a6b9e2ee83ce50b45e56623b1db4c) | **0.0000** | DRAINED | 2025-12-19 |
| x_x_GAME | [0xd97021...](https://etherscan.io/address/0xd97021a680c1ca28ffc3dd9712e7cb07b403d45f) | **0.0000** | DRAINED | 2025-12-23 |
| PI_QuiZ | [0x784e49...](https://etherscan.io/address/0x784e492e7333ddc6a0ada2454599212017403d14) | **0.0000** | DRAINED | 2025-12-24 |
| The_best_Quiz | [0x201e77...](https://etherscan.io/address/0x201e779aa14cdfc1f3c2c836f199d8ef2cac03e1) | **0.0000** | DRAINED | 2025-12-24 |
| x_X_game | [0xf0f1a0...](https://etherscan.io/address/0xf0f1a033638d088ef053e48b1ed9cde2e3e6c977) | **0.0000** | DRAINED | 2025-12-25 |
| PI_QUIZ | [0x821ab5...](https://etherscan.io/address/0x821ab5215e7970480d1d9c145632e5c15d3b8bbb) | **0.0000** | DRAINED | 2025-12-26 |

*Last Updated: 2026-01-06 06:43:34 UTC*
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
