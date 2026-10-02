/*
 * The Keeper's Table — server
 *
 * A small Express app that serves a private hub for a Call of Cthulhu
 * group. Accounts are controlled by the Keeper (the first account created,
 * and an admin panel to add more) with an optional invite code for
 * self-signup. Everything is stored in a single JSON file (see store.js).
 */
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const session = require("cookie-session");
const bcrypt = require("bcryptjs");
const store = require("./store");

store.load();

// App version + a content hash of the front-end files. The hash is appended
// to the CSS/JS URLs so a browser never serves a stale copy after a deploy.
const VERSION = "1.3.0";
const PUBLIC_DIR = path.join(__dirname, "public");
let ASSET_V = "0";
try {
  const h = crypto.createHash("sha1");
  h.update(fs.readFileSync(path.join(PUBLIC_DIR, "app.js")));
  h.update(fs.readFileSync(path.join(PUBLIC_DIR, "style.css")));
  ASSET_V = h.digest("hex").slice(0, 10);
} catch (e) { ASSET_V = String(Date.now()); }

const app = express();
app.set("trust proxy", 1); // required so secure cookies work behind a host's proxy
app.disable("x-powered-by");

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === "production";

app.use(express.json({ limit: "12mb" })); // room for base64 character-sheet uploads
app.use(
  session({
    name: "kt_sess",
    keys: [store.sessionSecret()],
    maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
    httpOnly: true,
    sameSite: "lax",
    secure: PROD
  })
);

// ---- security headers ----
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "same-origin");
  next();
});

// ---- CSRF-lite: mutating API calls must come from our own origin ----
app.use("/api", (req, res, next) => {
  if (["POST", "PUT", "DELETE", "PATCH"].includes(req.method)) {
    const origin = req.headers.origin;
    if (origin) {
      const host = req.headers.host;
      let ok = false;
      try { ok = new URL(origin).host === host; } catch (_) {}
      if (!ok) return res.status(403).json({ error: "Bad origin." });
    }
  }
  next();
});

// ---------- helpers ----------
const d = () => store.data;
function findUser(username) {
  const u = String(username || "").trim().toLowerCase();
  return d().users.find((x) => x.username.toLowerCase() === u);
}
function currentUser(req) {
  const uid = req.session && req.session.uid;
  if (!uid) return null;
  return d().users.find((x) => x.id === uid) || null;
}
function requireAuth(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Not signed in." });
  req.user = u;
  next();
}
// Role hierarchy: admin > keeper > investigator.
// Admins can do everything a Keeper can, plus manage accounts and roles.
function isAdmin(u) { return !!u && u.role === "admin"; }
function isStaff(u) { return !!u && (u.role === "admin" || u.role === "keeper"); }
// "requireKeeper" = staff (keeper OR admin) — game-running powers.
function requireKeeper(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Not signed in." });
  if (!isStaff(u)) return res.status(403).json({ error: "Keepers only." });
  req.user = u;
  next();
}
function requireAdmin(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Not signed in." });
  if (!isAdmin(u)) return res.status(403).json({ error: "Admins only." });
  req.user = u;
  next();
}
function adminCount() { return store.data.users.filter((x) => x.role === "admin").length; }
function publicUser(u) {
  return { id: u.id, username: u.username, displayName: u.displayName || u.username, role: u.role, createdAt: u.createdAt };
}
function validUsername(s) {
  return typeof s === "string" && /^[a-zA-Z0-9_.-]{3,24}$/.test(s.trim());
}
function validPassword(s) {
  return typeof s === "string" && s.length >= 6 && s.length <= 200;
}

// ---------- rate limiting (login/setup) ----------
const attempts = new Map(); // ip -> {n, first}
function rateLimit(req, res, next) {
  const ip = req.ip || "?";
  const now = Date.now();
  const rec = attempts.get(ip) || { n: 0, first: now };
  if (now - rec.first > 15 * 60 * 1000) { rec.n = 0; rec.first = now; }
  if (rec.n >= 12) return res.status(429).json({ error: "Too many attempts. Wait 15 minutes." });
  rec.n++;
  attempts.set(ip, rec);
  next();
}
function clearRate(req) {
  attempts.delete(req.ip || "?");
}

// ================= AUTH ROUTES =================

// version check — visit /api/version on your live site to confirm the deploy
app.get("/api/version", (req, res) => {
  res.json({ version: VERSION, assets: ASSET_V, features: ["roles", "investigators", "sheet-upload", "maps", "asset-images"] });
});

// tells the login page whether we need first-run setup / can self-register
app.get("/api/bootstrap", (req, res) => {
  res.json({
    needsSetup: d().users.length === 0,
    inviteEnabled: !!d().config.inviteEnabled && d().users.length > 0,
    title: d().config.title,
    tagline: d().config.tagline,
    signedIn: !!currentUser(req)
  });
});

// first-run: create the Keeper account
app.post("/api/setup", rateLimit, async (req, res) => {
  if (d().users.length > 0) return res.status(409).json({ error: "Setup already complete." });
  const { username, password, displayName } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: "Username must be 3–24 letters, numbers, or . _ -" });
  if (!validPassword(password)) return res.status(400).json({ error: "Password must be at least 6 characters." });
  const user = {
    id: store.id("u_"),
    username: username.trim(),
    displayName: (displayName || "").trim() || username.trim(),
    passHash: bcrypt.hashSync(password, 10),
    role: "admin",
    createdAt: Date.now()
  };
  d().users.push(user);
  await store.save();
  req.session.uid = user.id;
  clearRate(req);
  res.json({ ok: true, me: publicUser(user) });
});

app.post("/api/login", rateLimit, (req, res) => {
  const { username, password } = req.body || {};
  const user = findUser(username);
  if (!user || !bcrypt.compareSync(String(password || ""), user.passHash)) {
    return res.status(401).json({ error: "Wrong username or password." });
  }
  req.session.uid = user.id;
  clearRate(req);
  res.json({ ok: true, me: publicUser(user) });
});

// invite-code self-registration (investigator role)
app.post("/api/register", rateLimit, async (req, res) => {
  const cfg = d().config;
  if (!cfg.inviteEnabled) return res.status(403).json({ error: "Sign-up is closed. Ask your Keeper for an account." });
  const { username, password, displayName, inviteCode } = req.body || {};
  if (!cfg.inviteCode || String(inviteCode || "").trim() !== cfg.inviteCode) {
    return res.status(403).json({ error: "That invite code isn't right." });
  }
  if (!validUsername(username)) return res.status(400).json({ error: "Username must be 3–24 letters, numbers, or . _ -" });
  if (!validPassword(password)) return res.status(400).json({ error: "Password must be at least 6 characters." });
  if (findUser(username)) return res.status(409).json({ error: "That username is taken." });
  const user = {
    id: store.id("u_"),
    username: username.trim(),
    displayName: (displayName || "").trim() || username.trim(),
    passHash: bcrypt.hashSync(password, 10),
    role: "investigator",
    createdAt: Date.now()
  };
  d().users.push(user);
  await store.save();
  req.session.uid = user.id;
  clearRate(req);
  res.json({ ok: true, me: publicUser(user) });
});

app.post("/api/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// ================= STATE =================
function stateFor(user) {
  const isKeeper = isStaff(user); // staff (keeper or admin) see the game-running data
  const cfg = d().config;
  const out = {
    me: publicUser(user),
    config: {
      title: cfg.title,
      tagline: cfg.tagline,
      links: cfg.links || []
    },
    campaigns: d().campaigns,
    assets: d().assets.filter((a) => isKeeper || !a.hidden),
    characters: d().characters.filter((c) => isKeeper || !c.hidden),
    maps: d().maps,
    tokens: d().tokens,
    avail: d().avail,
    polls: d().polls,
    votes: d().votes
  };
  if (isKeeper) {
    out.config.inviteCode = cfg.inviteCode || "";
    out.config.inviteEnabled = !!cfg.inviteEnabled;
    out.secrets = d().secrets;
    out.users = d().users.map(publicUser);
  }
  return out;
}
app.get("/api/state", requireAuth, (req, res) => res.json(stateFor(req.user)));

// ================= ACCOUNT (self) =================
app.put("/api/account/name", requireAuth, async (req, res) => {
  const name = String((req.body || {}).displayName || "").trim().slice(0, 60);
  req.user.displayName = name || req.user.username;
  // keep availability / votes display names in sync
  d().avail.forEach((a) => { if (a.userId === req.user.id) a.name = req.user.displayName; });
  d().votes.forEach((v) => { if (v.userId === req.user.id) v.name = req.user.displayName; });
  await store.save();
  res.json({ ok: true, me: publicUser(req.user) });
});
app.put("/api/account/password", requireAuth, async (req, res) => {
  const { current, next } = req.body || {};
  if (!bcrypt.compareSync(String(current || ""), req.user.passHash)) {
    return res.status(403).json({ error: "Your current password isn't right." });
  }
  if (!validPassword(next)) return res.status(400).json({ error: "New password must be at least 6 characters." });
  req.user.passHash = bcrypt.hashSync(next, 10);
  await store.save();
  res.json({ ok: true });
});

// ================= USERS (keeper) =================
const ROLES = ["investigator", "keeper", "admin"];
app.post("/api/users", requireKeeper, async (req, res) => {
  const { username, password, displayName, role } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: "Username must be 3–24 letters, numbers, or . _ -" });
  if (!validPassword(password)) return res.status(400).json({ error: "Password must be at least 6 characters." });
  if (findUser(username)) return res.status(409).json({ error: "That username is taken." });
  let newRole = ROLES.includes(role) ? role : "investigator";
  if (newRole !== "investigator" && !isAdmin(req.user)) {
    return res.status(403).json({ error: "Only an Admin can grant the Keeper or Admin role." });
  }
  const user = {
    id: store.id("u_"),
    username: username.trim(),
    displayName: (displayName || "").trim() || username.trim(),
    passHash: bcrypt.hashSync(password, 10),
    role: newRole,
    createdAt: Date.now()
  };
  d().users.push(user);
  await store.save();
  res.json({ ok: true, user: publicUser(user) });
});
app.put("/api/users/:id", requireKeeper, async (req, res) => {
  const u = d().users.find((x) => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: "No such user." });
  const { displayName, role, password } = req.body || {};
  // Keepers may only manage Investigator accounts; Admins may manage anyone.
  if (!isAdmin(req.user) && u.role !== "investigator") {
    return res.status(403).json({ error: "Only an Admin can manage Keeper or Admin accounts." });
  }
  if (typeof displayName === "string") u.displayName = displayName.trim().slice(0, 60) || u.username;
  if (role !== undefined && ROLES.includes(role) && role !== u.role) {
    if (!isAdmin(req.user)) return res.status(403).json({ error: "Only an Admin can change roles." });
    // never leave the table without an Admin
    if (u.role === "admin" && role !== "admin" && adminCount() <= 1) {
      return res.status(400).json({ error: "There must be at least one Admin." });
    }
    u.role = role;
  }
  if (password !== undefined && password !== "") {
    if (!validPassword(password)) return res.status(400).json({ error: "Password must be at least 6 characters." });
    u.passHash = bcrypt.hashSync(password, 10);
  }
  await store.save();
  res.json({ ok: true, user: publicUser(u) });
});
app.delete("/api/users/:id", requireKeeper, async (req, res) => {
  const u = d().users.find((x) => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: "No such user." });
  if (u.id === req.user.id) return res.status(400).json({ error: "You can't delete your own account." });
  if (!isAdmin(req.user) && u.role !== "investigator") {
    return res.status(403).json({ error: "Only an Admin can delete Keeper or Admin accounts." });
  }
  if (u.role === "admin" && adminCount() <= 1) {
    return res.status(400).json({ error: "There must be at least one Admin." });
  }
  store.data.users = d().users.filter((x) => x.id !== u.id);
  store.data.avail = d().avail.filter((a) => a.userId !== u.id);
  store.data.votes = d().votes.filter((v) => v.userId !== u.id);
  await store.save();
  res.json({ ok: true });
});

// ================= CONFIG (keeper) =================
app.put("/api/config", requireKeeper, async (req, res) => {
  const b = req.body || {};
  const cfg = d().config;
  if (typeof b.title === "string") cfg.title = b.title.trim().slice(0, 80) || "The Keeper's Table";
  if (typeof b.tagline === "string") cfg.tagline = b.tagline.trim().slice(0, 200);
  if (Array.isArray(b.links)) {
    cfg.links = b.links.slice(0, 24).map((l) => ({
      icon: String(l.icon || "❖").slice(0, 4),
      label: String(l.label || "").slice(0, 80),
      note: String(l.note || "").slice(0, 200),
      url: String(l.url || "").slice(0, 500)
    }));
  }
  if (typeof b.inviteCode === "string") cfg.inviteCode = b.inviteCode.trim().slice(0, 60);
  if (typeof b.inviteEnabled === "boolean") cfg.inviteEnabled = b.inviteEnabled;
  await store.save();
  res.json({ ok: true });
});

// ================= CAMPAIGNS (keeper) =================
function cleanCampaign(b, existing) {
  return {
    id: existing ? existing.id : store.id("c_"),
    name: String(b.name || "Untitled").slice(0, 120),
    era: String(b.era || "1920s").slice(0, 60),
    status: ["active", "planning", "hiatus", "complete"].includes(b.status) ? b.status : "planning",
    icon: String(b.icon || "☗").slice(0, 4),
    synopsis: String(b.synopsis || "").slice(0, 4000),
    order: existing ? (existing.order ?? 0) : d().campaigns.length,
    example: false,
    createdAt: existing ? existing.createdAt : Date.now()
  };
}
app.post("/api/campaigns", requireKeeper, async (req, res) => {
  if (!String((req.body || {}).name || "").trim()) return res.status(400).json({ error: "A campaign needs a name." });
  const c = cleanCampaign(req.body || {}, null);
  d().campaigns.push(c);
  await store.save();
  res.json({ ok: true, campaign: c });
});
app.put("/api/campaigns/:id", requireKeeper, async (req, res) => {
  const idx = d().campaigns.findIndex((c) => c.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: "No such campaign." });
  d().campaigns[idx] = cleanCampaign(req.body || {}, d().campaigns[idx]);
  await store.save();
  res.json({ ok: true, campaign: d().campaigns[idx] });
});
app.delete("/api/campaigns/:id", requireKeeper, async (req, res) => {
  const cid = req.params.id;
  // clean up any files owned by this campaign's characters and maps
  d().characters.forEach((c) => { if (c.campaignId === cid && c.sheetFile && c.sheetFile.id) store.deleteFileSync(c.sheetFile.id); });
  d().assets.forEach((a) => { if (a.campaignId === cid && a.image && a.image.id) store.deleteFileSync(a.image.id); });
  d().maps.forEach((m) => { if (m.campaignId === cid && m.fileId) store.deleteFileSync(m.fileId); });
  store.data.campaigns = d().campaigns.filter((c) => c.id !== cid);
  store.data.assets = d().assets.filter((a) => a.campaignId !== cid);
  store.data.characters = d().characters.filter((c) => c.campaignId !== cid);
  store.data.maps = d().maps.filter((m) => m.campaignId !== cid);
  store.data.tokens = d().tokens.filter((t) => t.campaignId !== cid);
  if (d().secrets.byCampaign) delete d().secrets.byCampaign[cid];
  await store.save();
  res.json({ ok: true });
});

// ================= ASSETS (keeper) =================
function cleanAsset(b, existing) {
  return {
    id: existing ? existing.id : store.id("a_"),
    campaignId: String(b.campaignId || (existing && existing.campaignId) || ""),
    title: String(b.title || "Untitled").slice(0, 160),
    kind: String(b.kind || "Handout").slice(0, 40),
    body: String(b.body || "").slice(0, 8000),
    hidden: !!b.hidden,
    image: existing ? (existing.image || null) : null
  };
}
app.post("/api/assets", requireKeeper, async (req, res) => {
  const a = cleanAsset(req.body || {}, null);
  if (!a.campaignId) return res.status(400).json({ error: "Missing campaign." });
  d().assets.push(a);
  await store.save();
  res.json({ ok: true, asset: a });
});
app.put("/api/assets/:id", requireKeeper, async (req, res) => {
  const idx = d().assets.findIndex((a) => a.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: "No such asset." });
  d().assets[idx] = cleanAsset(req.body || {}, d().assets[idx]);
  await store.save();
  res.json({ ok: true, asset: d().assets[idx] });
});
app.delete("/api/assets/:id", requireKeeper, async (req, res) => {
  var a = d().assets.find((x) => x.id === req.params.id);
  if (a && a.image && a.image.id) store.deleteFileSync(a.image.id);
  store.data.assets = d().assets.filter((x) => x.id !== req.params.id);
  await store.save();
  res.json({ ok: true });
});
// attach / replace an image on an asset (keeper)
app.post("/api/assets/:id/image", requireKeeper, async (req, res) => {
  var a = d().assets.find((x) => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: "No such asset." });
  var b = req.body || {};
  var ext = IMG_TYPES[b.contentType];
  if (!ext) return res.status(400).json({ error: "Upload an image (PNG, JPG, WEBP, or GIF)." });
  var base64 = String(b.dataBase64 || "").replace(/^data:[^,]*,/, "");
  var buf; try { buf = Buffer.from(base64, "base64"); } catch (e) { buf = null; }
  if (!buf || !buf.length) return res.status(400).json({ error: "The image didn't come through." });
  if (buf.length > 8 * 1024 * 1024) return res.status(413).json({ error: "That image is over 8 MB. Please use a smaller one." });
  if (a.image && a.image.id) store.deleteFileSync(a.image.id);
  var fileId = store.id("ai_");
  store.saveFileSync(fileId, buf);
  a.image = { id: fileId, name: String(b.filename || ("image." + ext)).slice(0, 160), type: b.contentType };
  await store.save();
  res.json({ ok: true, asset: a });
});
app.delete("/api/assets/:id/image", requireKeeper, async (req, res) => {
  var a = d().assets.find((x) => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: "No such asset." });
  if (a.image && a.image.id) store.deleteFileSync(a.image.id);
  a.image = null;
  await store.save();
  res.json({ ok: true, asset: a });
});

// ================= CHARACTERS (keeper) =================
const STAT_KEYS = ["STR", "CON", "SIZ", "DEX", "APP", "INT", "POW", "EDU"];
function cleanChar(b, existing) {
  const stats = {};
  if (b.stats && typeof b.stats === "object") {
    STAT_KEYS.forEach((k) => { if (b.stats[k]) stats[k] = String(b.stats[k]).slice(0, 6); });
  }
  return {
    id: existing ? existing.id : store.id("ch_"),
    campaignId: String(b.campaignId || (existing && existing.campaignId) || ""),
    name: String(b.name || "Unnamed").slice(0, 120),
    kind: b.kind === "NPC" ? "NPC" : "Investigator",
    player: String(b.player || "").slice(0, 80),
    ownerId: (b.ownerId !== undefined ? (b.ownerId || null) : (existing ? existing.ownerId || null : null)),
    occupation: String(b.occupation || "").slice(0, 80),
    age: String(b.age || "").slice(0, 12),
    stats,
    hp: String(b.hp || "").slice(0, 8),
    san: String(b.san || "").slice(0, 8),
    luck: String(b.luck || "").slice(0, 8),
    mov: String(b.mov || "").slice(0, 8),
    skills: String(b.skills || "").slice(0, 4000),
    notes: String(b.notes || "").slice(0, 6000),
    hidden: !!b.hidden,
    sheetFile: existing ? (existing.sheetFile || null) : null
  };
}
app.post("/api/characters", requireKeeper, async (req, res) => {
  const c = cleanChar(req.body || {}, null);
  if (!c.campaignId) return res.status(400).json({ error: "Missing campaign." });
  d().characters.push(c);
  await store.save();
  res.json({ ok: true, character: c });
});
app.put("/api/characters/:id", requireKeeper, async (req, res) => {
  const idx = d().characters.findIndex((c) => c.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: "No such character." });
  d().characters[idx] = cleanChar(req.body || {}, d().characters[idx]);
  await store.save();
  res.json({ ok: true, character: d().characters[idx] });
});
app.delete("/api/characters/:id", requireKeeper, async (req, res) => {
  var ch = d().characters.find((c) => c.id === req.params.id);
  if (ch && ch.sheetFile && ch.sheetFile.id) store.deleteFileSync(ch.sheetFile.id);
  store.data.characters = d().characters.filter((c) => c.id !== req.params.id);
  await store.save();
  res.json({ ok: true });
});

// ---- player-owned investigators (any signed-in user) ----
function cleanOwnedChar(b, existing, userId) {
  var c = cleanChar(Object.assign({}, b, { kind: "Investigator", hidden: false }), existing);
  c.ownerId = userId;
  c.kind = "Investigator";
  c.hidden = false;
  return c;
}
app.post("/api/my/characters", requireAuth, async (req, res) => {
  var b = req.body || {};
  if (!String(b.name || "").trim()) return res.status(400).json({ error: "Your investigator needs a name." });
  if (b.campaignId && !d().campaigns.find((c) => c.id === b.campaignId)) return res.status(400).json({ error: "No such campaign." });
  var c = cleanOwnedChar(b, null, req.user.id);
  if (!c.player) c.player = req.user.displayName;
  d().characters.push(c);
  await store.save();
  res.json({ ok: true, character: c });
});
app.put("/api/my/characters/:id", requireAuth, async (req, res) => {
  var idx = d().characters.findIndex((c) => c.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: "No such investigator." });
  var ex = d().characters[idx];
  if (ex.ownerId !== req.user.id && !isStaff(req.user)) return res.status(403).json({ error: "That isn't your investigator." });
  if (req.body && req.body.campaignId && !d().campaigns.find((c) => c.id === req.body.campaignId)) return res.status(400).json({ error: "No such campaign." });
  d().characters[idx] = cleanOwnedChar(req.body || {}, ex, ex.ownerId || req.user.id);
  await store.save();
  res.json({ ok: true, character: d().characters[idx] });
});
app.delete("/api/my/characters/:id", requireAuth, async (req, res) => {
  var ch = d().characters.find((c) => c.id === req.params.id);
  if (!ch) return res.status(404).json({ error: "No such investigator." });
  if (ch.ownerId !== req.user.id && !isStaff(req.user)) return res.status(403).json({ error: "That isn't your investigator." });
  if (ch.sheetFile && ch.sheetFile.id) store.deleteFileSync(ch.sheetFile.id);
  store.data.characters = d().characters.filter((c) => c.id !== ch.id);
  await store.save();
  res.json({ ok: true });
});

// ---- character-sheet upload (owner or keeper), with best-effort auto-fill ----
var ALLOWED_SHEET = { "application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp" };
app.post("/api/my/characters/:id/sheet", requireAuth, async (req, res) => {
  var ch = d().characters.find((c) => c.id === req.params.id);
  if (!ch) return res.status(404).json({ error: "No such investigator." });
  if (ch.ownerId !== req.user.id && !isStaff(req.user)) return res.status(403).json({ error: "That isn't your investigator." });
  var b = req.body || {};
  var ext = ALLOWED_SHEET[b.contentType];
  if (!ext) return res.status(400).json({ error: "Upload a PDF or an image (PNG/JPG)." });
  var base64 = String(b.dataBase64 || "").replace(/^data:[^,]*,/, "");
  var buf;
  try { buf = Buffer.from(base64, "base64"); } catch (e) { buf = null; }
  if (!buf || !buf.length) return res.status(400).json({ error: "The file didn't come through. Try again." });
  if (buf.length > 8 * 1024 * 1024) return res.status(413).json({ error: "That file is over 8 MB. Please use a smaller one." });

  if (ch.sheetFile && ch.sheetFile.id) store.deleteFileSync(ch.sheetFile.id);
  var fileId = store.id("f_");
  store.saveFileSync(fileId, buf);
  ch.sheetFile = {
    id: fileId,
    name: String(b.filename || ("sheet." + ext)).slice(0, 160),
    type: b.contentType,
    uploadedAt: Date.now()
  };

  var filled = [];
  if (ext === "pdf" && b.autofill !== false) {
    try {
      var extracted = await extractFromPdf(buf);
      filled = applyExtracted(ch, extracted);
    } catch (e) { /* parsing is best-effort; ignore */ }
  }
  await store.save();
  res.json({ ok: true, character: ch, filled: filled });
});
app.delete("/api/my/characters/:id/sheet", requireAuth, async (req, res) => {
  var ch = d().characters.find((c) => c.id === req.params.id);
  if (!ch) return res.status(404).json({ error: "No such investigator." });
  if (ch.ownerId !== req.user.id && !isStaff(req.user)) return res.status(403).json({ error: "That isn't your investigator." });
  if (ch.sheetFile && ch.sheetFile.id) store.deleteFileSync(ch.sheetFile.id);
  ch.sheetFile = null;
  await store.save();
  res.json({ ok: true, character: ch });
});
// serve an uploaded file (character sheet or map image) to people allowed to see it
function sendStored(res, fileId, type, name) {
  var buf = store.readFileSync(fileId);
  if (!buf) return res.status(404).send("Not found.");
  res.setHeader("Content-Type", type || "application/octet-stream");
  res.setHeader("Content-Disposition", "inline; filename=\"" + String(name || "file").replace(/[^\w.\- ]/g, "_") + "\"");
  res.setHeader("Cache-Control", "private, max-age=60");
  res.send(buf);
}
app.get("/api/files/:fileId", requireAuth, (req, res) => {
  var fid = req.params.fileId;
  var ch = d().characters.find((c) => c.sheetFile && c.sheetFile.id === fid);
  if (ch) {
    var allowed = isStaff(req.user) || ch.ownerId === req.user.id || !ch.hidden;
    if (!allowed) return res.status(404).send("Not found.");
    return sendStored(res, ch.sheetFile.id, ch.sheetFile.type, ch.sheetFile.name);
  }
  var as = d().assets.find((a) => a.image && a.image.id === fid);
  if (as) {
    if (as.hidden && !isStaff(req.user)) return res.status(404).send("Not found.");
    return sendStored(res, as.image.id, as.image.type, as.image.name);
  }
  var mp = d().maps.find((m) => m.fileId === fid);
  if (mp) return sendStored(res, mp.fileId, mp.fileType, mp.name); // maps are shared with the table
  return res.status(404).send("Not found.");
});

// ================= MAPS (keeper) =================
var IMG_TYPES = { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif" };
app.post("/api/maps", requireKeeper, async (req, res) => {
  var b = req.body || {};
  if (!d().campaigns.find((c) => c.id === b.campaignId)) return res.status(400).json({ error: "No such campaign." });
  if (!IMG_TYPES[b.contentType]) return res.status(400).json({ error: "Upload an image (PNG, JPG, WEBP, or GIF)." });
  var base64 = String(b.dataBase64 || "").replace(/^data:[^,]*,/, "");
  var buf; try { buf = Buffer.from(base64, "base64"); } catch (e) { buf = null; }
  if (!buf || !buf.length) return res.status(400).json({ error: "The image didn't come through." });
  if (buf.length > 9 * 1024 * 1024) return res.status(413).json({ error: "That image is over 9 MB. Please use a smaller one." });
  var fileId = store.id("mf_");
  store.saveFileSync(fileId, buf);
  var map = { id: store.id("map_"), campaignId: b.campaignId, name: String(b.name || "Map").slice(0, 80), fileId: fileId, fileType: b.contentType, gridOn: false, createdAt: Date.now() };
  d().maps.push(map);
  await store.save();
  res.json({ ok: true, map: map });
});
app.put("/api/maps/:id", requireKeeper, async (req, res) => {
  var m = d().maps.find((x) => x.id === req.params.id);
  if (!m) return res.status(404).json({ error: "No such map." });
  if (typeof (req.body || {}).name === "string") m.name = req.body.name.slice(0, 80) || m.name;
  if (typeof (req.body || {}).gridOn === "boolean") m.gridOn = req.body.gridOn;
  await store.save();
  res.json({ ok: true, map: m });
});
app.delete("/api/maps/:id", requireKeeper, async (req, res) => {
  var m = d().maps.find((x) => x.id === req.params.id);
  if (!m) return res.status(404).json({ error: "No such map." });
  if (m.fileId) store.deleteFileSync(m.fileId);
  store.data.maps = d().maps.filter((x) => x.id !== m.id);
  store.data.tokens = d().tokens.filter((t) => t.mapId !== m.id);
  await store.save();
  res.json({ ok: true });
});

// ================= TOKENS =================
function clampUnit(n) { n = Number(n); if (!isFinite(n)) return 0.5; return Math.max(0, Math.min(1, n)); }
function validColor(c) { return /^#[0-9a-fA-F]{6}$/.test(String(c || "")) ? c : null; }
var TOKEN_COLORS = ["#c23d4a", "#4a938a", "#c8a951", "#6a5acd", "#3f7d3f", "#b5651d", "#8f2531", "#2e6f9e"];
app.post("/api/tokens", requireKeeper, async (req, res) => {
  var b = req.body || {};
  var map = d().maps.find((m) => m.id === b.mapId);
  if (!map) return res.status(400).json({ error: "No such map." });
  var t = {
    id: store.id("tk_"), campaignId: map.campaignId, mapId: map.id,
    label: String(b.label || "Pin").slice(0, 40),
    color: validColor(b.color) || TOKEN_COLORS[d().tokens.length % TOKEN_COLORS.length],
    x: clampUnit(b.x), y: clampUnit(b.y),
    ownerId: b.ownerId || null, characterId: b.characterId || null
  };
  d().tokens.push(t);
  await store.save();
  res.json({ ok: true, token: t });
});
// player places a token for one of their own investigators
app.post("/api/my/tokens", requireAuth, async (req, res) => {
  var b = req.body || {};
  var map = d().maps.find((m) => m.id === b.mapId);
  if (!map) return res.status(400).json({ error: "No such map." });
  var ch = d().characters.find((c) => c.id === b.characterId);
  if (!ch || (ch.ownerId !== req.user.id && !isStaff(req.user))) return res.status(403).json({ error: "That isn't your investigator." });
  var t = {
    id: store.id("tk_"), campaignId: map.campaignId, mapId: map.id,
    label: (ch.name || "Investigator").slice(0, 40),
    color: TOKEN_COLORS[d().tokens.length % TOKEN_COLORS.length],
    x: clampUnit(b.x), y: clampUnit(b.y),
    ownerId: ch.ownerId || req.user.id, characterId: ch.id
  };
  d().tokens.push(t);
  await store.save();
  res.json({ ok: true, token: t });
});
// move a token — allowed for staff, or the token's owner
app.put("/api/tokens/:id/move", requireAuth, async (req, res) => {
  var t = d().tokens.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "No such token." });
  if (!isStaff(req.user) && t.ownerId !== req.user.id) return res.status(403).json({ error: "You can't move that token." });
  t.x = clampUnit((req.body || {}).x);
  t.y = clampUnit((req.body || {}).y);
  await store.save();
  res.json({ ok: true, token: t });
});
app.put("/api/tokens/:id", requireKeeper, async (req, res) => {
  var t = d().tokens.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "No such token." });
  var b = req.body || {};
  if (typeof b.label === "string") t.label = b.label.slice(0, 40) || t.label;
  if (validColor(b.color)) t.color = b.color;
  if (b.ownerId !== undefined) t.ownerId = b.ownerId || null;
  await store.save();
  res.json({ ok: true, token: t });
});
app.delete("/api/tokens/:id", requireKeeper, async (req, res) => {
  store.data.tokens = d().tokens.filter((x) => x.id !== req.params.id);
  await store.save();
  res.json({ ok: true });
});
app.delete("/api/my/tokens/:id", requireAuth, async (req, res) => {
  var t = d().tokens.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "No such token." });
  if (!isStaff(req.user) && t.ownerId !== req.user.id) return res.status(403).json({ error: "That isn't your token." });
  store.data.tokens = d().tokens.filter((x) => x.id !== t.id);
  await store.save();
  res.json({ ok: true });
});

// ---- best-effort extraction of CoC 7e stats from a fillable PDF ----
function normKey(s) { return String(s || "").toLowerCase().replace(/[^a-z0-9]/g, ""); }
async function extractFromPdf(buf) {
  var pdfLib = require("pdf-lib");
  var doc = await pdfLib.PDFDocument.load(buf, { ignoreEncryption: true, updateMetadata: false });
  var form;
  try { form = doc.getForm(); } catch (e) { return {}; }
  var fields = form.getFields();
  var map = {};
  fields.forEach(function (f) {
    var isText = f.constructor && f.constructor.name === "PDFTextField";
    if (!isText) return;
    var v = "";
    try { v = f.getText() || ""; } catch (e) {}
    v = String(v).trim();
    if (v) map[normKey(f.getName())] = v;
  });
  var out = { stats: {} };
  var STR_MAP = {
    STR: ["str", "strength"], CON: ["con", "constitution"], SIZ: ["siz", "size"],
    DEX: ["dex", "dexterity"], APP: ["app", "appearance"], INT: ["int", "intelligence"],
    POW: ["pow", "power"], EDU: ["edu", "education"]
  };
  var DERIVED = {
    hp: ["hp", "hitpoints", "hitpointsmax", "maxhp", "hpmax", "hitpointsmaximum"],
    san: ["san", "sanity", "sanitypoints", "currentsanity", "sanmax", "startingsanity"],
    luck: ["luck", "luckpoints", "currentluck"],
    mov: ["mov", "move", "moverate", "movement"]
  };
  var badToken = /(half|fifth|hard|extreme|oneh|onef|damage|max)/; // avoid the derived half/fifth boxes for characteristics
  function pickNumber(cands, token) {
    // exact match first
    for (var i = 0; i < cands.length; i++) if (map[cands[i]] && /^\d{1,3}$/.test(map[cands[i]])) return map[cands[i]];
    // then any field containing the token with a clean numeric value
    var keys = Object.keys(map);
    var best = null;
    for (var j = 0; j < keys.length; j++) {
      var k = keys[j];
      if (token && k.indexOf(token) >= 0 && !badToken.test(k) && /^\d{1,3}$/.test(map[k])) {
        if (best === null || k.length < best.length) best = k;
      }
    }
    return best ? map[best] : "";
  }
  Object.keys(STR_MAP).forEach(function (key) {
    var v = pickNumber(STR_MAP[key], key.toLowerCase());
    if (v) out.stats[key] = v;
  });
  Object.keys(DERIVED).forEach(function (key) {
    var v = pickNumber(DERIVED[key], DERIVED[key][0]);
    if (v) out[key] = v;
  });
  function pickText(cands) { for (var i = 0; i < cands.length; i++) if (map[cands[i]]) return map[cands[i]]; return ""; }
  out.name = pickText(["name", "investigatorname", "investigatorsname", "charactername", "pcname", "playername"]);
  out.occupation = pickText(["occupation", "occ"]);
  out.age = pickText(["age"]);
  if (out.age && !/^\d{1,3}$/.test(out.age)) out.age = "";
  return out;
}
function applyExtracted(ch, ex) {
  var filled = [];
  if (!ch.stats) ch.stats = {};
  ["STR", "CON", "SIZ", "DEX", "APP", "INT", "POW", "EDU"].forEach(function (k) {
    if (ex.stats && ex.stats[k] && !ch.stats[k]) { ch.stats[k] = ex.stats[k]; filled.push(k); }
  });
  [["hp", "HP"], ["san", "SAN"], ["luck", "Luck"], ["mov", "MOV"]].forEach(function (pair) {
    if (ex[pair[0]] && !ch[pair[0]]) { ch[pair[0]] = ex[pair[0]]; filled.push(pair[1]); }
  });
  if (ex.name && (!ch.name || ch.name === "Unnamed")) { ch.name = ex.name.slice(0, 120); filled.push("name"); }
  if (ex.occupation && !ch.occupation) { ch.occupation = ex.occupation.slice(0, 80); filled.push("occupation"); }
  if (ex.age && !ch.age) { ch.age = ex.age.slice(0, 12); filled.push("age"); }
  return filled;
}

// ================= SECRETS (keeper) =================
app.put("/api/secrets/:campaignId", requireKeeper, async (req, res) => {
  const notes = String((req.body || {}).notes || "").slice(0, 20000);
  if (!d().secrets.byCampaign) d().secrets.byCampaign = {};
  d().secrets.byCampaign[req.params.campaignId] = notes;
  await store.save();
  res.json({ ok: true });
});

// ================= AVAILABILITY =================
// self: set my own weekly grid
app.put("/api/avail/me", requireAuth, async (req, res) => {
  const cells = sanitizeCells((req.body || {}).cells);
  let a = d().avail.find((x) => x.userId === req.user.id);
  if (!a) {
    a = { id: store.id("av_"), userId: req.user.id, name: req.user.displayName, cells };
    d().avail.push(a);
  } else {
    a.cells = cells;
    a.name = req.user.displayName;
  }
  await store.save();
  res.json({ ok: true, avail: a });
});
// keeper: add a manual roster entry (no account)
app.post("/api/avail", requireKeeper, async (req, res) => {
  const name = String((req.body || {}).name || "").trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: "Give them a name." });
  const a = { id: store.id("av_"), userId: null, name, cells: {} };
  d().avail.push(a);
  await store.save();
  res.json({ ok: true, avail: a });
});
// keeper: edit any roster entry's cells
app.put("/api/avail/:id", requireKeeper, async (req, res) => {
  const a = d().avail.find((x) => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: "No such entry." });
  if ((req.body || {}).cells) a.cells = sanitizeCells(req.body.cells);
  if (typeof (req.body || {}).name === "string") a.name = req.body.name.trim().slice(0, 60);
  await store.save();
  res.json({ ok: true, avail: a });
});
app.delete("/api/avail/:id", requireKeeper, async (req, res) => {
  store.data.avail = d().avail.filter((x) => x.id !== req.params.id);
  await store.save();
  res.json({ ok: true });
});
function sanitizeCells(cells) {
  const out = {};
  if (cells && typeof cells === "object") {
    for (const k of Object.keys(cells)) {
      if (/^[0-6]_[0-3]$/.test(k) && cells[k]) out[k] = true;
    }
  }
  return out;
}

// ================= POLLS (keeper) & VOTES =================
app.post("/api/polls", requireKeeper, async (req, res) => {
  const b = req.body || {};
  const dates = Array.isArray(b.dates)
    ? b.dates.slice(0, 12).map((x) => ({
        id: String(x.id || store.id("d_")).slice(0, 40),
        iso: String(x.iso || "").slice(0, 20),
        label: String(x.label || "").slice(0, 40)
      })).filter((x) => x.label)
    : [];
  if (!dates.length) return res.status(400).json({ error: "Add at least one date." });
  const poll = { id: store.id("poll_"), title: String(b.title || "Session dates").slice(0, 120), dates, createdAt: Date.now(), closed: false };
  d().polls.push(poll);
  await store.save();
  res.json({ ok: true, poll });
});
app.put("/api/polls/:id", requireKeeper, async (req, res) => {
  const p = d().polls.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: "No such poll." });
  if (typeof (req.body || {}).closed === "boolean") p.closed = req.body.closed;
  if (typeof (req.body || {}).title === "string") p.title = req.body.title.slice(0, 120);
  await store.save();
  res.json({ ok: true, poll: p });
});
app.delete("/api/polls/:id", requireKeeper, async (req, res) => {
  store.data.polls = d().polls.filter((x) => x.id !== req.params.id);
  store.data.votes = d().votes.filter((v) => v.pollId !== req.params.id);
  await store.save();
  res.json({ ok: true });
});
// self: cast/update my vote on a poll
app.put("/api/votes/:pollId", requireAuth, async (req, res) => {
  const poll = d().polls.find((x) => x.id === req.params.pollId);
  if (!poll) return res.status(404).json({ error: "No such poll." });
  if (poll.closed) return res.status(403).json({ error: "This poll is closed." });
  const valid = new Set(poll.dates.map((x) => x.id));
  const choices = {};
  const inc = (req.body || {}).choices || {};
  for (const k of Object.keys(inc)) {
    if (valid.has(k) && ["yes", "no", "maybe"].includes(inc[k])) choices[k] = inc[k];
  }
  let v = d().votes.find((x) => x.pollId === poll.id && x.userId === req.user.id);
  if (!v) {
    v = { id: store.id("v_"), pollId: poll.id, userId: req.user.id, name: req.user.displayName, choices };
    d().votes.push(v);
  } else {
    v.choices = choices;
    v.name = req.user.displayName;
  }
  await store.save();
  res.json({ ok: true, vote: v });
});

// ================= PAGE ROUTES =================
const PUBLIC = path.join(__dirname, "public");
// Serve the HTML shells with the asset version injected, and tell the browser
// never to cache the HTML itself — so a deploy's new CSS/JS is always fetched.
function sendPage(res, file) {
  fs.readFile(path.join(PUBLIC, file), "utf8", function (err, html) {
    if (err) return res.status(500).send("Server error.");
    res.setHeader("Cache-Control", "no-store, must-revalidate");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(html.replace(/\{\{V\}\}/g, ASSET_V));
  });
}
app.get("/", (req, res) => {
  if (!currentUser(req)) return res.redirect("/login");
  sendPage(res, "app.html");
});
app.get("/login", (req, res) => {
  if (currentUser(req)) return res.redirect("/");
  sendPage(res, "login.html");
});
app.use(express.static(PUBLIC));
app.get("*", (req, res) => res.redirect("/"));

app.listen(PORT, () => {
  console.log("The Keeper's Table is listening on port " + PORT);
  console.log("Data directory: " + store.DATA_DIR);
  if (store.data.users.length === 0) {
    console.log("No accounts yet — open the site and create your Keeper account.");
  }
});
