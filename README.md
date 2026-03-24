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
| go_GAME | [0xfce614...](https://etherscan.io/address/0xfce6147693c7d40c605ef7d203764fc9ee12caba) | **15.0000** | ACTIVE | 2026-03-19 |
| LETS_play | [0x92a446...](https://etherscan.io/address/0x92a4465833fa3cd98bf3e31f3ae4b14029290626) | **5.0000** | ACTIVE | 2026-03-23 |
| IS_Game | [0x2aae7b...](https://etherscan.io/address/0x2aae7b00df8dd21022a2d95f82669429145f6e6e) | **1.0000** | ACTIVE | 2026-03-20 |
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
| x_X_Game | [0xa46c2b...](https://etherscan.io/address/0xa46c2b718adfff25098417ad0b5d208c832260b1) | **0.0000** | DRAINED | 2025-12-30 |
| pix_quiz | [0xa9b974...](https://etherscan.io/address/0xa9b9743193e9b57a99b2ca79ba2c3879fefaff53) | **0.0000** | DRAINED | 2026-01-02 |
| The_best_QUIZ | [0x58601b...](https://etherscan.io/address/0x58601b315360bb7d4b8d7cc291823e4cd9c43d58) | **0.0000** | DRAINED | 2026-01-05 |
| x_X_GamE | [0x748271...](https://etherscan.io/address/0x748271209c9213a4890367a103b6970274edfbb5) | **0.0000** | DRAINED | 2026-01-07 |
| pix_Quiz | [0xf2be23...](https://etherscan.io/address/0xf2be235eee9492ac108aaae474b7823efde8527f) | **0.0000** | DRAINED | 2026-01-09 |
| The_Best_quiz | [0xeb5b40...](https://etherscan.io/address/0xeb5b4090a69a8f382e807178ee4b630266ce5f85) | **0.0000** | DRAINED | 2026-01-12 |
| x_X_GAME | [0x84bb9f...](https://etherscan.io/address/0x84bb9f507d3642cc3173292c8f0a3de229d363b3) | **0.0000** | DRAINED | 2026-01-14 |
| pix_QuiZ | [0xae074d...](https://etherscan.io/address/0xae074d8fd8f1e50d44319d5087b9f15eafb8ed26) | **0.0000** | DRAINED | 2026-01-16 |
| The_Best_Quiz | [0x1cc3c9...](https://etherscan.io/address/0x1cc3c91b6cfb11a5545dcb427d848ad1bdcdaab9) | **0.0000** | DRAINED | 2026-01-19 |
| X_x_game | [0x2c8ce6...](https://etherscan.io/address/0x2c8ce6e5d5796ca2cc97ea86c999918f0ea9ad9d) | **0.0000** | DRAINED | 2026-01-21 |
| pix_QUIZ | [0x510c27...](https://etherscan.io/address/0x510c275cff2767580ae17e7763cde0d3d9bdec42) | **0.0000** | DRAINED | 2026-01-23 |
| The_Best_QuiZ | [0x6df1c6...](https://etherscan.io/address/0x6df1c6ff8a0a8ceeed577cecef4ac06676606bef) | **0.0000** | DRAINED | 2026-01-25 |
| X_x_Game | [0xb08665...](https://etherscan.io/address/0xb0866571b84fa33d4aad454647f200aff9f0eb85) | **0.0000** | DRAINED | 2026-01-27 |
| Pix_quiz | [0xf0958d...](https://etherscan.io/address/0xf0958d212defa4489b1fde28ab2a23f967da7e26) | **0.0000** | DRAINED | 2026-01-29 |
| The_Best_QUIZ | [0x1c3c88...](https://etherscan.io/address/0x1c3c88319d656c24aa08c81c7f0495e9d0722893) | **0.0000** | DRAINED | 2026-01-31 |
| X_x_GamE | [0x8afcf9...](https://etherscan.io/address/0x8afcf9f78910635bc365be6869b8ce990c029b46) | **0.0000** | DRAINED | 2026-02-03 |
| Pix_Quiz | [0x7377dc...](https://etherscan.io/address/0x7377dcd63f6147caab4504a9549fce79bda48f04) | **0.0000** | DRAINED | 2026-02-05 |
| The_BEST_quiz | [0x05aeff...](https://etherscan.io/address/0x05aeff2e38b307b7dc234fbf8b5f9ab9e8479dcf) | **0.0000** | DRAINED | 2026-02-07 |
| The_Best_QUIZ | [0xe3819f...](https://etherscan.io/address/0xe3819fde81a182f0404ee1f4ff9de57c873c5ebc) | **0.0000** | DRAINED | 2026-02-07 |
| X_x_GAME | [0xc6571b...](https://etherscan.io/address/0xc6571b8611751d6e377762ff4a89045da40f2eb2) | **0.0000** | DRAINED | 2026-02-10 |
| Pix_QUIZ | [0xe33e35...](https://etherscan.io/address/0xe33e356e3ee7b26b151504aaf69c495c0c36a1ce) | **0.0000** | DRAINED | 2026-02-12 |
| Pix_Quiz | [0x673c1e...](https://etherscan.io/address/0x673c1e1734afb0040ad18f166b3393849a289a14) | **0.0000** | DRAINED | 2026-02-12 |
| The_BEST_Quiz | [0x04c06a...](https://etherscan.io/address/0x04c06a2cbd6b3949f6ebc7d4fa8ba311b8c49e29) | **0.0000** | DRAINED | 2026-02-14 |
| lets_play | [0x335b9e...](https://etherscan.io/address/0x335b9e3e8fbb9c08dcb575c3e33c15ac9888a911) | **0.0000** | DRAINED | 2026-02-15 |
| X_X_game | [0xc5b250...](https://etherscan.io/address/0xc5b2505f115eca8b95045fa56d4cdbe2cc732d08) | **0.0000** | DRAINED | 2026-02-17 |
| PiX_quiz | [0xc428ff...](https://etherscan.io/address/0xc428ff0d5eb8e020ffb3270b46c5478179da6e70) | **0.0000** | DRAINED | 2026-02-19 |
| lets_Play | [0x5dea32...](https://etherscan.io/address/0x5dea3268569929df1477a9eff375ff493618fa81) | **0.0000** | DRAINED | 2026-02-21 |
| X_X_Game | [0xbef07c...](https://etherscan.io/address/0xbef07c5864a8b5fe552229a223c73719d9ba4ee9) | **0.0000** | DRAINED | 2026-02-23 |
| PiX_Quiz | [0xef9f72...](https://etherscan.io/address/0xef9f72b0ba319e179285e37d942ad5effd532d61) | **0.0000** | DRAINED | 2026-02-25 |
| Lets_play | [0xa3d75d...](https://etherscan.io/address/0xa3d75d3210f61b4717cdb5e000e627eacdfb1ec1) | **0.0000** | DRAINED | 2026-02-28 |
| X_X_GAME | [0x8c328c...](https://etherscan.io/address/0x8c328c8f18d8d125c7ebb0eaf0f449b4cbc7ee42) | **0.0000** | DRAINED | 2026-02-28 |
| PiX_QuiZ | [0xd80784...](https://etherscan.io/address/0xd80784a8fbc7165843e6ab12fc1a214bea8aed48) | **0.0000** | DRAINED | 2026-03-03 |
| Lets_Play | [0x4eaeea...](https://etherscan.io/address/0x4eaeea5a2c9c5c495a9aae11c3879f214c4fe90f) | **0.0000** | DRAINED | 2026-03-06 |
| go_game | [0x0a5204...](https://etherscan.io/address/0x0a5204a3b162229a34ca8950cc99bc97ad201195) | **0.0000** | DRAINED | 2026-03-09 |
| PiX_QUIZ | [0xb53d12...](https://etherscan.io/address/0xb53d12ce8b98e306e8298c490018a1044738ff3f) | **0.0000** | DRAINED | 2026-03-12 |
| Lets_PLAY | [0x9f38c5...](https://etherscan.io/address/0x9f38c5a6650f2b6266122d8539f7fdfefe55052c) | **0.0000** | DRAINED | 2026-03-14 |
| go_Game | [0x5f7a65...](https://etherscan.io/address/0x5f7a653c05648355d1b33863f2e5dd78b22bd2cc) | **0.0000** | DRAINED | 2026-03-17 |

*Last Updated: 2026-03-24 01:42:06 UTC*
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
