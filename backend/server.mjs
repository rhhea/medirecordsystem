import "dotenv/config";
import express from "express";
import multer from "multer";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
const LOGGER_KEY =
  process.env.LOGGER_PRIVATE_KEY ||
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // Hardhat #0 (test only)
const IPFS_API = process.env.IPFS_API || "http://127.0.0.1:5001";
const MOCK_IPFS = (process.env.MOCK_IPFS ?? "true") === "true";
const EXPLORER_URL = process.env.EXPLORER_URL || "";

// ---------- contract ----------
const contractFile = path.join(__dirname, "contract.json");
if (!fs.existsSync(contractFile)) {
  console.error("backend/contract.json missing. Run: npm run deploy");
  process.exit(1);
}
const deployment = JSON.parse(fs.readFileSync(contractFile, "utf8"));
const provider = new ethers.JsonRpcProvider(RPC_URL);
const loggerWallet = new ethers.Wallet(LOGGER_KEY, provider);
const contract = new ethers.Contract(deployment.address, deployment.abi, loggerWallet);

// ---------- tiny JSON "database" (DEMO ONLY: keys live on the server) ----------
const DB_FILE = path.join(__dirname, "db.json");
const db = fs.existsSync(DB_FILE)
  ? JSON.parse(fs.readFileSync(DB_FILE, "utf8"))
  : { keys: {}, tamper: {} };
const saveDb = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
const pending = new Map(); // upload token -> { key, cid, hash }

// ---------- crypto ----------
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function encrypt(plain, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]); // iv(12) | tag(16) | ciphertext
}

function decrypt(blob, key) {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]); // throws if ciphertext was modified
}

// ---------- IPFS (kubo HTTP API, with optional local mock) ----------
const MOCK_DIR = path.join(__dirname, "mock-ipfs");
fs.mkdirSync(MOCK_DIR, { recursive: true });

async function ipfsAdd(buf) {
  try {
    const fd = new FormData();
    fd.append("file", new Blob([buf]));
    const r = await fetch(`${IPFS_API}/api/v0/add?pin=true`, { method: "POST", body: fd });
    if (!r.ok) throw new Error(await r.text());
    return (await r.json()).Hash;
  } catch (e) {
    if (!MOCK_IPFS) throw new Error("IPFS add failed: " + e.message);
    console.warn("[ipfs] daemon unreachable, using mock storage");
    const cid = "mock-" + sha256(buf);
    fs.writeFileSync(path.join(MOCK_DIR, cid), buf);
    return cid;
  }
}

async function ipfsCat(cid) {
  if (cid.startsWith("mock-")) return fs.readFileSync(path.join(MOCK_DIR, cid));
  const r = await fetch(`${IPFS_API}/api/v0/cat?arg=${cid}`, { method: "POST" });
  if (!r.ok) throw new Error("IPFS cat failed: " + (await r.text()));
  return Buffer.from(await r.arrayBuffer());
}

// ---------- helpers ----------
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: e.shortMessage || e.message });
  });

const accessMessage = (id, ts) => `MedChain access request\nrecord:${id}\nts:${ts}`;

async function logOnChain(id, user, granted, integrityOk) {
  const tx = await contract.logAccess(id, user, granted, integrityOk);
  const rc = await tx.wait();
  return {
    txHash: tx.hash,
    status: rc.status,
    gasUsed: rc.gasUsed.toString(),
    gasPrice: rc.gasPrice.toString(),
    fee: ethers.formatEther(rc.gasUsed * rc.gasPrice),
    block: rc.blockNumber,
  };
}

// ---------- app ----------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

app.get("/api/config", (_req, res) =>
  res.json({
    address: deployment.address,
    abi: deployment.abi,
    chainId: deployment.chainId,
    rpc: RPC_URL,
    explorer: EXPLORER_URL,
  })
);

// Steps 1-3: hash original -> AES-256-GCM encrypt -> IPFS. Patient then sends CID+hash on-chain from MetaMask.
app.post("/api/upload", upload.single("file"), wrap(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  const plain = req.file.buffer;
  const fileHash = "0x" + sha256(plain);
  const key = crypto.randomBytes(32);
  const cid = await ipfsAdd(encrypt(plain, key));
  const token = crypto.randomUUID();
  pending.set(token, { key: key.toString("hex"), cid, fileHash });
  res.json({ token, cid, fileHash, name: req.file.originalname, size: plain.length });
}));

// After the on-chain tx confirms, bind the AES key to the record id (after verifying on-chain data matches).
app.post("/api/bind", wrap(async (req, res) => {
  const { token, recordId } = req.body;
  const p = pending.get(token);
  if (!p) return res.status(400).json({ error: "Unknown upload token" });
  const rec = await contract.records(recordId);
  if (rec.cid !== p.cid || rec.fileHash !== p.fileHash)
    return res.status(400).json({ error: "On-chain record does not match uploaded file" });
  db.keys[String(recordId)] = p.key;
  saveDb();
  pending.delete(token);
  res.json({ ok: true });
}));

// Steps 8-9: verify wallet signature -> checkAccess -> fetch+decrypt -> re-verify SHA-256 -> log on-chain.
app.post("/api/records/:id/open", wrap(async (req, res) => {
  const id = req.params.id;
  const { address, timestamp, signature } = req.body;

  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 120)
    return res.status(400).json({ error: "Signature expired, try again" });
  let who;
  try { who = ethers.verifyMessage(accessMessage(id, timestamp), signature); }
  catch { return res.status(401).json({ error: "Bad signature" }); }
  if (who.toLowerCase() !== String(address).toLowerCase())
    return res.status(401).json({ error: "Signature does not match address" });

  const rec = await contract.records(id);
  if (rec.patient === ethers.ZeroAddress) return res.status(404).json({ error: "No such record" });

  // ---- the gate: ask the smart contract ----
  const granted = await contract.checkAccess(id, who);
  if (!granted) {
    const log = await logOnChain(id, who, false, false);
    return res.status(403).json({ granted: false, error: "Access denied by smart contract", log });
  }

  const keyHex = db.keys[id];
  if (!keyHex) return res.status(500).json({ error: "No encryption key stored for this record" });

  let integrityOk = false, actualHash = null, plain = null, reason = "";
  const cidUsed = db.tamper[id] || rec.cid; // tamper demo swaps in an altered file
  try {
    const blob = await ipfsCat(cidUsed);
    plain = decrypt(blob, Buffer.from(keyHex, "hex"));
    actualHash = "0x" + sha256(plain);
    integrityOk = actualHash === rec.fileHash.toLowerCase();
    if (!integrityOk) reason = "SHA-256 of the decrypted file does not match the hash stored on-chain.";
  } catch (e) {
    reason = "Decryption failed: ciphertext was modified (" + e.message + ")";
  }

  const log = await logOnChain(id, who, true, integrityOk);
  res.json({
    granted: true,
    integrityOk,
    reason,
    name: rec.name,
    expectedHash: rec.fileHash,
    actualHash,
    cidUsed,
    originalCid: rec.cid,
    log,
    data: integrityOk ? plain.toString("base64") : null, // never serve a file that failed verification
  });
}));

// ---------- tamper demo (simulates a malicious storage node) ----------
app.post("/api/demo/tamper/:id", wrap(async (req, res) => {
  const id = req.params.id;
  const rec = await contract.records(id);
  const key = Buffer.from(db.keys[id], "hex");
  const plain = decrypt(await ipfsCat(rec.cid), key);
  const altered = Buffer.concat([plain, Buffer.from("\n[ALTERED BY ATTACKER]")]);
  const cid = await ipfsAdd(encrypt(altered, key)); // validly encrypted, but content differs
  db.tamper[id] = cid;
  saveDb();
  res.json({ ok: true, originalCid: rec.cid, tamperedCid: cid });
}));

app.post("/api/demo/restore/:id", wrap(async (req, res) => {
  delete db.tamper[req.params.id];
  saveDb();
  res.json({ ok: true });
}));

app.listen(PORT, () => {
  console.log(`MedChain backend + UI: http://localhost:${PORT}`);
  console.log(`Contract: ${deployment.address} | logger: ${loggerWallet.address}`);
});
