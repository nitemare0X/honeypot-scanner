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
| wf_quiz | [0x68cdae...](https://etherscan.io/address/0x68cdae802e4305f78432d149ff68ec3d7c1226ed) | **5.0000** | ACTIVE | 2026-07-20 |
| Just_play | [0xdc1e5e...](https://etherscan.io/address/0xdc1e5ed1a1c2fb6fae71015c0d681c068c4da9d4) | **1.0000** | ACTIVE | 2026-07-22 |
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
| go_GAME | [0xfce614...](https://etherscan.io/address/0xfce6147693c7d40c605ef7d203764fc9ee12caba) | **0.0000** | DRAINED | 2026-03-19 |
| IS_Game | [0x2aae7b...](https://etherscan.io/address/0x2aae7b00df8dd21022a2d95f82669429145f6e6e) | **0.0000** | DRAINED | 2026-03-20 |
| LETS_play | [0x92a446...](https://etherscan.io/address/0x92a4465833fa3cd98bf3e31f3ae4b14029290626) | **0.0000** | DRAINED | 2026-03-23 |
| Go_game | [0xe065f3...](https://etherscan.io/address/0xe065f386a22ed6c9167a5a01ed49493e03d63a05) | **0.0000** | DRAINED | 2026-03-25 |
| PIX_Quiz | [0x8f1d93...](https://etherscan.io/address/0x8f1d93d7497807770de30c00142576d1ceebb4e4) | **0.0000** | DRAINED | 2026-03-28 |
| LETS_Play | [0xf327cc...](https://etherscan.io/address/0xf327cc34562ac0857c2ff033ce8d8b3713725cfd) | **0.0000** | DRAINED | 2026-03-31 |
| Go_Game | [0xcacac8...](https://etherscan.io/address/0xcacac855b2c8a15309dc18a0dd499fe9f30bdf54) | **0.0000** | DRAINED | 2026-04-01 |
| PIX_QUIZ | [0x98a4b7...](https://etherscan.io/address/0x98a4b7e0af7d6fd9f1bbf716e77084afd58250f1) | **0.0000** | DRAINED | 2026-04-04 |
| LETS_PLAY | [0x448be0...](https://etherscan.io/address/0x448be08bc2d4a13f53dae969e2fd5a24bfaf67ea) | **0.0000** | DRAINED | 2026-04-08 |
| Go_GAME | [0x8eb6b2...](https://etherscan.io/address/0x8eb6b2706d6bea86f6fa3c616dfb3c396eda50e2) | **0.0000** | DRAINED | 2026-04-10 |
| fix_quiz | [0x9e8167...](https://etherscan.io/address/0x9e8167937b9eb379afed4edd678dcd8a2852875d) | **0.0000** | DRAINED | 2026-04-13 |
| let_play | [0x9d0842...](https://etherscan.io/address/0x9d08426bb6ff60afcfef7e7f78210806598b677f) | **0.0000** | DRAINED | 2026-04-16 |
| GO_game | [0x2ee57c...](https://etherscan.io/address/0x2ee57c842357d4a91085aaaa3e4ac61aba5ec0b1) | **0.0000** | DRAINED | 2026-04-18 |
| IS_Game | [0x8b2dc5...](https://etherscan.io/address/0x8b2dc57638a4d409825cddd7075fcb37a5790012) | **0.0000** | DRAINED | 2026-04-21 |
| come_to_play | [0x41ffe3...](https://etherscan.io/address/0x41ffe3ee72dae313964d4f76df868ffcba0c1417) | **0.0000** | DRAINED | 2026-04-22 |
| GO_Game | [0xd31431...](https://etherscan.io/address/0xd314314bdbb3c1353c9175c436c58fbe757f88eb) | **0.0000** | DRAINED | 2026-04-24 |
| fix_QUIZ | [0x6530b3...](https://etherscan.io/address/0x6530b34c18b2c7c0e22f1bc327affd21c12cf202) | **0.0000** | DRAINED | 2026-04-26 |
| come_to_Play | [0x9d4c46...](https://etherscan.io/address/0x9d4c463fc172f5908e1cf2b8751448d4d74caa9b) | **0.0000** | DRAINED | 2026-04-27 |
| GO_GAME | [0x72bc9b...](https://etherscan.io/address/0x72bc9bd4bda2039f5fd95d46caa6da2262c65fae) | **0.0000** | DRAINED | 2026-04-28 |
| IS_Game | [0xe4d4e9...](https://etherscan.io/address/0xe4d4e9ebbc18007de6a2b948c8270dddea30f614) | **0.0000** | DRAINED | 2026-04-30 |
| come_to_PLAY | [0x0ad893...](https://etherscan.io/address/0x0ad893299e308fa03af4da4c88b04781e0bef4dd) | **0.0000** | DRAINED | 2026-05-02 |
| gx_game | [0x64d12e...](https://etherscan.io/address/0x64d12e67ea18ce9b2d63d96642f01d09d760ef9f) | **0.0000** | DRAINED | 2026-05-04 |
| Come_to_play | [0x885596...](https://etherscan.io/address/0x885596ee329812121e8858eaeb75c5bf89a656f4) | **0.0000** | DRAINED | 2026-05-07 |
| gx_Game | [0x246029...](https://etherscan.io/address/0x246029f37f648e733158f9490cefcded17e07057) | **0.0000** | DRAINED | 2026-05-08 |
| Fix_QUIZ | [0xcd968d...](https://etherscan.io/address/0xcd968d6d5648fde4fd95af78c4a5ac74bb09158b) | **0.0000** | DRAINED | 2026-05-10 |
| Come_to_Play | [0x7065cb...](https://etherscan.io/address/0x7065cb73f36a0a17e08a7c71a03f0190958347dd) | **0.0000** | DRAINED | 2026-05-12 |
| gx_GAME | [0x8cf1e7...](https://etherscan.io/address/0x8cf1e7981de09a7856581ac7301bd14f686bae58) | **0.0000** | DRAINED | 2026-05-13 |
| FIX_quiz | [0x9dfce5...](https://etherscan.io/address/0x9dfce5e9a2af4cb1c267bdccdfc9db3d99750e4f) | **0.0000** | DRAINED | 2026-05-14 |
| Come_to_PLAY | [0x5620b0...](https://etherscan.io/address/0x5620b08e9352b7da3243926a3c6819aa1bb2c2cb) | **0.0000** | DRAINED | 2026-05-15 |
| Gx_game | [0x969c89...](https://etherscan.io/address/0x969c890de17589ae8ce7aef9f5c3b47a3e37a0fa) | **0.0000** | DRAINED | 2026-05-16 |
| FIX_Quiz | [0xeefe22...](https://etherscan.io/address/0xeefe2236792bbeb64c5ce0683fac8133db84cea8) | **0.0000** | DRAINED | 2026-05-18 |
| COME_to_play | [0x2b659c...](https://etherscan.io/address/0x2b659c5f407b2ba3bc33bc4501fa8b911416a49a) | **0.0000** | DRAINED | 2026-05-19 |
| IS_Game | [0x16f24f...](https://etherscan.io/address/0x16f24f86a98e0e0d709564c75ddc7ccf1fcc817c) | **0.0000** | DRAINED | 2026-05-20 |
| FIX_QUIZ | [0x7578f8...](https://etherscan.io/address/0x7578f8b11a72e76b7f50afc68592e0610b0ca92f) | **0.0000** | DRAINED | 2026-05-21 |
| COME_to_Play | [0xc89264...](https://etherscan.io/address/0xc89264bed9c2de110e8fa7befe4daddf2c670d12) | **0.0000** | DRAINED | 2026-05-22 |
| Gx_GAME | [0x5dcc39...](https://etherscan.io/address/0x5dcc3949d4df9a735ba5c9d8d34519e5aa86d554) | **0.0000** | DRAINED | 2026-05-25 |
| fin_quiz | [0x5f947c...](https://etherscan.io/address/0x5f947c43bc7926527e6eedf3a1ece43884cb252b) | **0.0000** | DRAINED | 2026-05-27 |
| COME_to_PLAY | [0xc93064...](https://etherscan.io/address/0xc93064f3708e43f9e6b4da933a45b9aeced45d93) | **0.0000** | DRAINED | 2026-05-28 |
| GX_game | [0x0b75be...](https://etherscan.io/address/0x0b75be3efb1b956ee9f5dc4a94ab59572d163a96) | **0.0000** | DRAINED | 2026-05-30 |
| IS_Game | [0x93f423...](https://etherscan.io/address/0x93f423c8291de10146bdfcf364ad9da904ac563f) | **0.0000** | DRAINED | 2026-06-01 |
| COME_To_play | [0x954759...](https://etherscan.io/address/0x9547599caa1dbbbcb330f1305da951523fbcf3b7) | **0.0000** | DRAINED | 2026-06-02 |
| GX_Game | [0x739476...](https://etherscan.io/address/0x739476db1fe3d5897dfd914d32625abf54dccdd5) | **0.0000** | DRAINED | 2026-06-03 |
| IS_Game | [0x9b1115...](https://etherscan.io/address/0x9b1115a9319deac8e795632fd265b70078c9b87f) | **0.0000** | DRAINED | 2026-06-05 |
| come_to_play | [0x8cf598...](https://etherscan.io/address/0x8cf59861ee6f22e3fb5d18bcc40cc254bdbb870d) | **0.0000** | DRAINED | 2026-06-08 |
| fin_QuIZ | [0xd34706...](https://etherscan.io/address/0xd34706d97bcc83ff0994b5ce42a68838657fd979) | **0.0000** | DRAINED | 2026-06-09 |
| COME_To_PlaY | [0x69aa36...](https://etherscan.io/address/0x69aa36a411a1ad6a78a045265bd005085f744d40) | **0.0000** | DRAINED | 2026-06-09 |
| ra_quiz | [0x9ad33d...](https://etherscan.io/address/0x9ad33dfa6c15a5bd5c3eb1ab5c4de376558bea4e) | **0.0000** | DRAINED | 2026-06-11 |
| COME_TO_PLAY | [0x573bb7...](https://etherscan.io/address/0x573bb7f1aea78fbb5f9d65b74ddcfd804d594db5) | **0.0000** | DRAINED | 2026-06-12 |
| RA_Quiz | [0x9068a1...](https://etherscan.io/address/0x9068a18c3a9b21b959224bc1c4ed5f7f103d8270) | **0.0000** | DRAINED | 2026-06-15 |
| COME_TO_PLAY | [0xae51e7...](https://etherscan.io/address/0xae51e708afe11546e12ff5ad4217c4cc01068816) | **0.0000** | DRAINED | 2026-06-16 |
| w_quiz | [0xc277dc...](https://etherscan.io/address/0xc277dcb87feabec1c2c179987646bf816e033919) | **0.0000** | DRAINED | 2026-06-17 |
| play_the_game | [0x8a79f4...](https://etherscan.io/address/0x8a79f4bcb3690188e68438739eeeabdb7c0f1d6f) | **0.0000** | DRAINED | 2026-06-19 |
| come_to_play | [0x976588...](https://etherscan.io/address/0x976588dad73fed69468a276bdf93b45a74fc3e18) | **0.0000** | DRAINED | 2026-06-23 |
| w_QUIZ | [0x66052c...](https://etherscan.io/address/0x66052ce269c21ad75dcbfe60f997ed975ca01117) | **0.0000** | DRAINED | 2026-06-25 |
| COME_TO_PLAY | [0x6cca4c...](https://etherscan.io/address/0x6cca4cfbfb35b569f4a259327619c57594181535) | **0.0000** | DRAINED | 2026-06-27 |
| W_quiz | [0x59bba9...](https://etherscan.io/address/0x59bba9a3a3fda69a4272c54ff80a4c14bcda3a14) | **0.0000** | DRAINED | 2026-06-29 |
| IS_Game | [0x1030c0...](https://etherscan.io/address/0x1030c088c17ddc5a53179d96f29c0a5351196f53) | **0.0000** | DRAINED | 2026-07-01 |
| IS_Game | [0x989568...](https://etherscan.io/address/0x98956867ec53e6e63c578d3dbef743e9c2377fd4) | **0.0000** | DRAINED | 2026-07-04 |
| just_Play | [0x3da273...](https://etherscan.io/address/0x3da273a6778014bacf970ce57acf33a9996adc6d) | **0.0000** | DRAINED | 2026-07-06 |
| just_play | [0x5b93dc...](https://etherscan.io/address/0x5b93dce32c0f8917dbf27b3d8ce49026e20b752d) | **0.0000** | DRAINED | 2026-07-08 |
| W_Quiz | [0xa58374...](https://etherscan.io/address/0xa58374a0d4a0cd5df52a6b589f14e20bdf9fb226) | **0.0000** | DRAINED | 2026-07-08 |
| W_quiz | [0x7a31dc...](https://etherscan.io/address/0x7a31dca9c9a47e8bde8a222c68439a4aa8bda666) | **0.0000** | DRAINED | 2026-07-10 |
| IS_Game | [0x08996e...](https://etherscan.io/address/0x08996e607c19914715e87cde0afbe3220ab18e0c) | **0.0000** | DRAINED | 2026-07-13 |
| IS_Game | [0xfb75fe...](https://etherscan.io/address/0xfb75fe577a1c8cd7f51cf88be17b1adf59d147b5) | **0.0000** | DRAINED | 2026-07-15 |
| just_PLAY | [0x07ba2d...](https://etherscan.io/address/0x07ba2d0b55989de1435492c6815a3caefa7e325d) | **0.0000** | DRAINED | 2026-07-17 |

*Last Updated: 2026-07-24 02:17:46 UTC*
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
