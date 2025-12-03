import { format } from "date-fns";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { existsSync } from "node:fs";

// --- Configuration ---
const ETHERSCAN_V2_ENDPOINT = "https://api.etherscan.io/v2/api";
const SCAM_DB_FILE = "scams.json";

// Specific signatures for the "Quiz" scam
const FINGERPRINTS = [
    "responseHash",
    "function Try(string",
    "function Start(",
    "isAdmin"
];

interface ChainConfig {
    name: string;
    chainId: string;
    apiBase: string;
    explorer: string;
    nativeToken: string;
}

const CHAINS: Record<string, ChainConfig> = {
    ethereum: {
        name: "Ethereum",
        chainId: "1",
        apiBase: ETHERSCAN_V2_ENDPOINT,
        explorer: "https://etherscan.io",
        nativeToken: "ETH",
    },
};

interface ScamContract {
    address: string;
    chain: string;
    balance: number;
    name: string;
    first_seen: string;
    last_updated: string;
    status: "ACTIVE" | "DRAINED";
}

// --- Utils ---
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

class Scanner {
    chain: ChainConfig;
    apiKey: string;

    constructor(chainKey: string, apiKey: string) {
        this.chain = CHAINS[chainKey];
        this.apiKey = apiKey;
    }

    async request(params: Record<string, string>) {
        const url = new URL(this.chain.apiBase);
        url.searchParams.append("apikey", this.apiKey);
        url.searchParams.append("chainid", this.chain.chainId);
        for (const [k, v] of Object.entries(params)) url.searchParams.append(k, v);

        try {
            const res = await fetch(url.toString());
            await sleep(250); // Rate limit
            return await res.json();
        } catch (e) {
            console.error("Fetch error:", e);
            return { status: "0" };
        }
    }

    async getBlockNumber(): Promise<number> {
        const res = await this.request({ module: "proxy", action: "eth_blockNumber" });
        return parseInt(res.result, 16);
    }

    async getBalance(address: string): Promise<number> {
        const res = await this.request({ module: "account", action: "balance", address, tag: "latest" });
        return res.status === "1" ? Number(BigInt(res.result)) / 1e18 : 0;
    }

    // Scan recent blocks for contract interactions to find candidates
    async findCandidates(lookbackBlocks: number): Promise<string[]> {
        const currentBlock = await this.getBlockNumber();
        const startBlock = currentBlock - lookbackBlocks;
        console.log(`Scanning blocks ${startBlock} to ${currentBlock} for potential candidates...`);

        const candidates = new Set<string>();

        // Sample blocks (Scanning every block hits rate limits too fast on free tier)
        // We look at the last 10 blocks intensely
        for (let i = 0; i < 10; i++) {
            const blockNum = currentBlock - i;
            const res = await this.request({
                module: "proxy",
                action: "eth_getBlockByNumber",
                tag: "0x" + blockNum.toString(16),
                boolean: "true"
            });

            if (res.result && res.result.transactions) {
                for (const tx of res.result.transactions) {
                    // Check for contract creation (to = null) OR calls to existing contracts
                    if (tx.to) {
                        // Method ID filtering (Optional optimization)
                        // Start: 0xc76de3e9, Try: 0x5f3d328e (Try(string))
                        const input = tx.input || "";
                        if (input.startsWith("0xc76de3e9") || input.startsWith("0x5f3d328e")) {
                            candidates.add(tx.to);
                        }
                    } else if (tx.receipt && tx.receipt.contractAddress) {
                        // If we could see receipts here, we'd add contract creations
                        // Proxy endpoint usually doesn't show receipts deeply, 
                        // so we focus on interactions.
                    }
                }
            }
        }
        return Array.from(candidates);
    }

    async checkSourceCode(address: string): Promise<string | null> {
        const res = await this.request({ module: "contract", action: "getsourcecode", address });

        if (res.status === "1" && res.result[0] && res.result[0].SourceCode) {
            const source = res.result[0].SourceCode;

            // CHECK FOR THE SCAM PATTERN
            const matches = FINGERPRINTS.every(fp => source.includes(fp));

            if (matches) {
                return res.result[0].ContractName || "Unknown";
            }
        }
        return null;
    }
}

async function main() {
    const apiKey = process.env.ETHERSCAN_API_KEY;
    if (!apiKey) throw new Error("Missing ETHERSCAN_API_KEY");

    const scanner = new Scanner("ethereum", apiKey);

    // 1. Load existing Database
    let db: ScamContract[] = [];
    if (existsSync(SCAM_DB_FILE)) {
        try {
            const content = await readFile(SCAM_DB_FILE, "utf-8");
            db = JSON.parse(content);
        } catch (e) {
            console.error("Error reading DB, starting fresh.");
            db = [];
        }
    }

    console.log(`Loaded ${db.length} tracked scams.`);

    // 2. Update balances of known scams
    console.log("Updating balances...");
    for (const scam of db) {
        try {
            const bal = await scanner.getBalance(scam.address);
            scam.balance = bal;
            scam.last_updated = new Date().toISOString();
            scam.status = bal > 0.01 ? "ACTIVE" : "DRAINED";
            console.log(`  ${scam.name} (${scam.address.slice(0, 6)}...): ${bal.toFixed(4)} ETH`);
        } catch (e) {
            console.error(`  Failed to update ${scam.address}:`, e);
        }
    }

    // 3. Hunt for new targets
    // Look back ~50 blocks (approx 10 minutes of activity)
    // You can increase this if scanning less frequently
    const candidates = await scanner.findCandidates(50);
    console.log(`Analyzing ${candidates.length} candidate addresses...`);

    let newFound = 0;
    for (const address of candidates) {
        // Skip if already in DB (case insensitive check)
        if (db.find(x => x.address.toLowerCase() === address.toLowerCase())) continue;

        try {
            const name = await scanner.checkSourceCode(address);
            if (name) {
                const balance = await scanner.getBalance(address);
                console.log(`🚨 FOUND NEW SCAM: ${name} @ ${address} (${balance} ETH)`);

                db.push({
                    address,
                    chain: "ethereum",
                    balance,
                    name,
                    first_seen: new Date().toISOString(),
                    last_updated: new Date().toISOString(),
                    status: balance > 0.01 ? "ACTIVE" : "DRAINED"
                });
                newFound++;
            }
        } catch (e) {
            console.error(`  Error checking candidate ${address}:`, e);
        }
    }

    // 4. Save Database
    await writeFile(SCAM_DB_FILE, JSON.stringify(db, null, 2));

    // 5. Update README with Marker System
    const readmePath = path.join(process.cwd(), "README.md");
    let readmeContent = "";

    try {
        readmeContent = await readFile(readmePath, "utf-8");
    } catch (e) {
        console.log("README not found, creating new one.");
        // If file doesn't exist, create a basic one with markers
        readmeContent = "# Scam Tracker\n\n<!-- SCAM_LIST_START -->\n<!-- SCAM_LIST_END -->";
    }

    // Generate the Table
    let table = `\n| Name | Address | Balance | Status | First Seen |\n`;
    table += `|---|---|---|---|---|\n`;

    // Sort: Active first, then by balance desc
    db.sort((a, b) => {
        if (a.status === "ACTIVE" && b.status !== "ACTIVE") return -1;
        if (a.status !== "ACTIVE" && b.status === "ACTIVE") return 1;
        return b.balance - a.balance;
    });

    for (const s of db) {
        const link = `https://etherscan.io/address/${s.address}`;
        // Clean names to avoid breaking markdown tables
        const safeName = (s.name || "Unknown").replace(/\|/g, '-').trim();
        const dateStr = s.first_seen ? s.first_seen.split('T')[0] : "Unknown";

        table += `| ${safeName} | [${s.address.slice(0, 8)}...](${link}) | **${s.balance.toFixed(4)}** | ${s.status} | ${dateStr} |\n`;
    }

    table += `\n*Last Updated: ${format(new Date(), "yyyy-MM-dd HH:mm:ss")} UTC*\n`;

    // Regex to replace content between markers
    const markerRegex = /<!-- SCAM_LIST_START -->[\s\S]*?<!-- SCAM_LIST_END -->/;

    if (readmeContent.match(markerRegex)) {
        const newContent = readmeContent.replace(
            markerRegex,
            `<!-- SCAM_LIST_START -->${table}<!-- SCAM_LIST_END -->`
        );
        await writeFile(readmePath, newContent);
        console.log(`\nDone. Updated ${db.length} entries (Found ${newFound} new).`);
    } else {
        console.error("⚠️ Markers <!-- SCAM_LIST_START --> and <!-- SCAM_LIST_END --> not found in README.md");
        // Fallback: append if markers missing
        await writeFile(readmePath, readmeContent + "\n\n<!-- SCAM_LIST_START -->" + table + "<!-- SCAM_LIST_END -->");
    }
}

main();
