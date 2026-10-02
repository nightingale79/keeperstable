/*
 * store.js — a tiny, dependency-free JSON datastore.
 *
 * Everything the app keeps (users, campaigns, assets, characters, the
 * schedule, secrets) lives in ONE JSON file inside the data directory.
 * That keeps deployment painless: no database server to run, no native
 * modules to compile. At the scale of a tabletop group (a handful of
 * players, dozens of records) this is fast and completely reliable.
 *
 * Writes are serialized through a promise chain and written atomically
 * (temp file + rename) so a crash mid-write can never corrupt the file.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "data.json");
const SECRET_FILE = path.join(DATA_DIR, ".session-secret");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");

function ensureDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ---- uploaded files (character sheets) live as raw bytes on disk ----
function uploadPath(fileId) {
  var safe = String(fileId || "").replace(/[^a-zA-Z0-9_.-]/g, "");
  return path.join(UPLOAD_DIR, safe);
}
function saveFileSync(fileId, buf) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  fs.writeFileSync(uploadPath(fileId), buf);
}
function readFileSync(fileId) {
  var p = uploadPath(fileId);
  try { return fs.existsSync(p) ? fs.readFileSync(p) : null; } catch (e) { return null; }
}
function deleteFileSync(fileId) {
  try { fs.unlinkSync(uploadPath(fileId)); } catch (e) {}
}

function defaultData() {
  return {
    users: [],
    config: {
      title: "The Keeper's Table",
      tagline: "A private circle for players of Call of Cthulhu",
      inviteCode: "",
      inviteEnabled: false,
      links: [
        { icon: "📖", label: "Call of Cthulhu (Chaosium)", note: "The official publisher's page for the 7th-edition rules.", url: "https://www.chaosium.com/call-of-cthulhu-rpg/" },
        { icon: "🎲", label: "Free Quick-Start Rules", note: "Enough to run and play a first game. Add your link.", url: "" },
        { icon: "🗂", label: "Investigator Handbook", note: "Occupations, skills, and 1920s background. Add your link.", url: "" },
        { icon: "📝", label: "Blank Investigator Sheet (PDF)", note: "Your group's fillable character sheet. Add your link.", url: "" },
        { icon: "🎴", label: "Virtual Tabletop / Dice", note: "Wherever you roll — Roll20, Foundry, a Discord bot. Add your link.", url: "" },
        { icon: "📜", label: "House Rules", note: "Your table's rulings, kept somewhere shared. Add your link.", url: "" }
      ]
    },
    campaigns: [],
    assets: [],
    characters: [],
    maps: [],
    tokens: [],
    avail: [],
    polls: [],
    votes: [],
    secrets: { byCampaign: {} }
  };
}

let data = null;

function load() {
  ensureDir();
  if (fs.existsSync(DATA_FILE)) {
    try {
      data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
      // fill in any newly added top-level keys from defaults
      const d = defaultData();
      for (const k of Object.keys(d)) if (!(k in data)) data[k] = d[k];
      if (!data.config) data.config = d.config;
      for (const k of Object.keys(d.config)) if (!(k in data.config)) data.config[k] = d.config[k];
      if (!data.secrets) data.secrets = { byCampaign: {} };
    } catch (e) {
      // Corrupt file — back it up rather than lose it, start fresh.
      const bak = DATA_FILE + ".corrupt-" + Date.now();
      try { fs.renameSync(DATA_FILE, bak); } catch (_) {}
      data = defaultData();
    }
  } else {
    data = defaultData();
    saveSync();
  }
  return data;
}

function saveSync() {
  ensureDir();
  const tmp = DATA_FILE + ".tmp-" + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

// Serialize async saves so overlapping writes never race.
let chain = Promise.resolve();
function save() {
  chain = chain.then(
    () => new Promise((resolve) => {
      ensureDir();
      const tmp = DATA_FILE + ".tmp-" + process.pid;
      fs.writeFile(tmp, JSON.stringify(data, null, 2), (err) => {
        if (err) { resolve(); return; }
        fs.rename(tmp, DATA_FILE, () => resolve());
      });
    }),
    () => {}
  );
  return chain;
}

function sessionSecret() {
  ensureDir();
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  if (fs.existsSync(SECRET_FILE)) return fs.readFileSync(SECRET_FILE, "utf8").trim();
  const secret = crypto.randomBytes(32).toString("hex");
  try { fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 }); } catch (_) {}
  return secret;
}

function id(prefix) {
  return (prefix || "") + crypto.randomBytes(9).toString("base64url");
}

module.exports = {
  get data() { return data; },
  DATA_DIR,
  DATA_FILE,
  UPLOAD_DIR,
  load,
  save,
  saveSync,
  sessionSecret,
  id,
  saveFileSync,
  readFileSync,
  deleteFileSync
};
