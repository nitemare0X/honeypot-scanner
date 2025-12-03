import { format } from "date-fns";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { existsSync } from "node:fs";

// --- Configuration ---
const ETHERSCAN_V2_ENDPOINT = "https://api.etherscan.io/v2/api";
const SCAM_DB_FILE = "scams.json";
const LOOKBACK_BLOCKS = 200;
const BATCH_SIZE = 5;

// Signatures to detect in Source Code
const FINGERPRINTS = [
    "responseHash",
    "function Try(string",
    "function Start(",
    "isAdmin"
];

const SUSPICIOUS_METHODS = ["0xc76de3e9", "0x5f3d328e", "0x054f1b6a"];

interface ChainConfig {
    name: string;
    chainId: string;
    apiBase: string;
}

const CHAINS: Record<string, ChainConfig> = {
    ethereum: {
        name: "Ethereum",
        chainId: "1",
        apiBase: ETHERSCAN_V2_ENDPOINT,
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

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

class Scanner {
    chain: ChainConfig;
    apiKey: string;

    constructor(chainKey: string, apiKey: string) {
        this.chain = CHAINS[chainKey];
        this.apiKey = apiKey;
    }

    async request(params: Record<string, string>, retries = 3): Promise<any> {
        const url = new URL(this.chain.apiBase);
        url.searchParams.append("apikey", this.apiKey);
        url.searchParams.append("chainid", this.chain.chainId);
        for (const [k, v] of Object.entries(params)) url.searchParams.append(k, v);

        for (let i = 0; i < retries; i++) {
            try {
                const res = await fetch(url.toString());
                const data = await res.json();
                if (data.status === "0" && data.message === "NOTOK") throw new Error(data.result);
                return data;
            } catch (e) {
                if (i === retries - 1) {
                    console.error(`Request failed after ${retries} attempts:`, e);
                    return { status: "0" };
                }
                await sleep(1000 * (i + 1));
            }
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

    async findCandidates(lookback: number): Promise<string[]> {
        const currentBlock = await this.getBlockNumber();
        const startBlock = currentBlock - lookback;
        console.log(`Scanning blocks ${startBlock} to ${currentBlock} (${lookback} blocks)...`);

        const candidates = new Set<string>();
        const blocksToScan: number[] = [];
        for (let i = 0; i < lookback; i++) blocksToScan.push(currentBlock - i);

        // Process blocks in batches to respect rate limits but go faster
        for (let i = 0; i < blocksToScan.length; i += BATCH_SIZE) {
            const batch = blocksToScan.slice(i, i + BATCH_SIZE);

            await Promise.all(batch.map(async (blockNum) => {
                const res = await this.request({
                    module: "proxy",
                    action: "eth_getBlockByNumber",
                    tag: "0x" + blockNum.toString(16),
                    boolean: "true"
                });

                if (res.result && res.result.transactions) {
                    for (const tx of res.result.transactions) {
                        if (!tx.to && !tx.input) continue;

                        const input = tx.input ? tx.input.toLowerCase() : "";

                        // Check against suspicious Method IDs
                        if (SUSPICIOUS_METHODS.some(m => input.startsWith(m))) {
                            if (tx.to) candidates.add(tx.to);
                        }
                    }
                }
            }));

            // Small delay between batches
            await sleep(1100);
            const progress = Math.min(i + BATCH_SIZE, lookback);
            const percent = ((progress / lookback) * 100).toFixed(1);
            process.stdout.write(`\rProgress: ${progress}/${lookback} blocks (${percent}%)`);
            //process.stdout.write(`\rProgress: ${Math.min(i + BATCH_SIZE, lookback)}/${lookback} blocks`);
        }
        console.log("\nScan complete.");
        return Array.from(candidates);
    }

    async checkSourceCode(address: string): Promise<string | null> {
        // 1. Get Source
        const res = await this.request({ module: "contract", action: "getsourcecode", address });

        if (res.status === "1" && res.result[0] && res.result[0].SourceCode) {
            const source = res.result[0].SourceCode;

            // 2. Check for Scam Fingerprints
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

    // --- LOAD DB ---
    let db: ScamContract[] = [];
    if (existsSync(SCAM_DB_FILE)) {
        try {
            const content = await readFile(SCAM_DB_FILE, "utf-8");
            db = JSON.parse(content);
        } catch { db = []; }
    }
    console.log(`Loaded ${db.length} tracked scams.`);

    // --- UPDATE EXISTING ---
    console.log("Updating balances of known scams...");
    for (const scam of db) {
        try {
            const bal = await scanner.getBalance(scam.address);
            scam.balance = bal;
            scam.last_updated = new Date().toISOString();
            scam.status = bal > 0.01 ? "ACTIVE" : "DRAINED";
        } catch (e) { console.error(`Failed to update ${scam.address}`); }
    }

    // --- DISCOVER NEW ---
    const candidates = await scanner.findCandidates(LOOKBACK_BLOCKS);
    console.log(`Analyzing ${candidates.length} candidate addresses...`);

    let newFound = 0;
    for (const address of candidates) {
        // Skip if already in DB (case insensitive)
        if (db.find(x => x.address.toLowerCase() === address.toLowerCase())) continue;

        try {
            // Verify source code
            const name = await scanner.checkSourceCode(address);
            if (name) {
                const balance = await scanner.getBalance(address);
                console.log(`\n🚨 FOUND NEW SCAM: ${name} @ ${address} (${balance} ETH)`);

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
            console.error(`Error checking ${address}:`, e);
        }
    }

    // --- SAVE & REPORT ---
    await writeFile(SCAM_DB_FILE, JSON.stringify(db, null, 2));

    const readmePath = path.join(process.cwd(), "README.md");
    let readmeContent = "";
    try { readmeContent = await readFile(readmePath, "utf-8"); }
    catch { readmeContent = "# Scam Tracker\n\n<!-- SCAM_LIST_START -->\n<!-- SCAM_LIST_END -->"; }

    let table = `\n| Name | Address | Balance | Status | First Seen |\n`;
    table += `|---|---|---|---|---|\n`;

    db.sort((a, b) => (b.status === "ACTIVE" ? 1 : 0) - (a.status === "ACTIVE" ? 1 : 0) || b.balance - a.balance);

    for (const s of db) {
        const link = `https://etherscan.io/address/${s.address}`;
        const safeName = (s.name || "Unknown").replace(/\|/g, '-').trim();
        const dateStr = s.first_seen ? s.first_seen.split('T')[0] : "Unknown";
        table += `| ${safeName} | [${s.address.slice(0, 8)}...](${link}) | **${s.balance.toFixed(4)}** | ${s.status} | ${dateStr} |\n`;
    }

    table += `\n*Last Updated: ${format(new Date(), "yyyy-MM-dd HH:mm:ss")} UTC*\n`;

    const markerRegex = /<!-- SCAM_LIST_START -->[\s\S]*?<!-- SCAM_LIST_END -->/;
    if (readmeContent.match(markerRegex)) {
        await writeFile(readmePath, readmeContent.replace(markerRegex, `<!-- SCAM_LIST_START -->${table}<!-- SCAM_LIST_END -->`));
    } else {
        await writeFile(readmePath, readmeContent + "\n\n<!-- SCAM_LIST_START -->" + table + "<!-- SCAM_LIST_END -->");
    }

    console.log(`\nDone. Database now has ${db.length} entries.`);
}

main();
