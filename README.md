# The Keeper's Table

A private, self-hosted web hub for a **Call of Cthulhu** group — 1920s
tarot styling, and no Claude account required for anyone. You (the Admin)
create accounts and/or hand out an invite code; everyone signs in at a
normal web address.

**Roles** (each includes the powers below it):
- **Admin** — you. Controls accounts and roles: appoints Keepers, can make
  other Admins, resets passwords. The first account created is the Admin.
- **Keeper** — runs games: campaigns, assets, characters, secrets, polls.
  Can create player accounts, but cannot change roles or manage other staff.
- **Investigator** — a player: keeps their own investigators, marks
  availability, and votes.

**What's inside**
- **Accounts & roles you control** — create each person yourself (choosing
  their role), or turn on an invite code so players can sign up. Reset
  passwords, appoint Keepers, promote Admins.
- **Resources** — editable links to the rules, quick‑start, handbook, blank
  sheet, VTT, and house rules, plus a 7th‑edition stat reference.
- **Campaigns** — create, edit, delete. Each has **Assets & Handouts**,
  **Investigators & NPCs**, and a **Map**. Assets can carry an **image**
  (handout scans, photos, portraits) shown on the card. Anything can be
  marked **Keeper‑only** (its image is hidden from players too), and each
  campaign has private **Keeper's Secrets** notes only staff can read.
- **Battle maps** (Roll20‑style) — on a campaign's **Map** tab the Keeper
  uploads a map image and drops tokens; players can place their own
  investigator and **drag** their token around. Everyone sees moves within a
  few seconds. Supports multiple maps per campaign and an optional grid.
- **My Investigators** — every player can keep multiple investigators,
  switch between them per campaign, and upload a character sheet. A fillable
  PDF has its characteristics read automatically into the "at a glance"
  block; any sheet (PDF or image) is attached for the table to view.
- **Scheduler** — a weekly availability grid with a live overlap heatmap,
  plus date polls (yes / maybe / no).

Everything is stored in one JSON file on the server. There is **no database
to install and nothing to compile** — just Node.js.

---

## The fastest way to put it online (Render.com, ~15 min)

Render is beginner‑friendly and this project includes a blueprint file
(`render.yaml`) that sets everything up, including a small **persistent disk**
so your data is never lost.

> **Cost note, honestly:** an always‑on server that *keeps* your data costs
> roughly **$7/month** on Render (a persistent disk needs a paid instance).
> Truly free tiers either put the site to sleep or wipe saved data on each
> update, which you don't want for accounts and campaigns. If ~$7/mo is fine,
> this is the smoothest path.

### Steps
1. **Put the code on GitHub.**
   - Make a free account at <https://github.com>.
   - Create a new **empty** repository (e.g. `keepers-table`).
   - Upload this folder's files to it (GitHub's "uploading an existing file"
     drag‑and‑drop works — include every file *except* the `node_modules` and
     `data` folders if they exist).
2. **Create the Render service.**
   - Make a free account at <https://render.com> and connect your GitHub.
   - Click **New → Blueprint**, pick your `keepers-table` repo, and Render
     reads `render.yaml` automatically. Confirm and **Apply**.
   - It installs and starts the app, and gives you a URL like
     `https://keepers-table-xxxx.onrender.com`.
3. **Create your Admin account.**
   - Open that URL. The first visit shows **“Create your Admin account.”**
     Pick your username and password — that account is the Admin (you).
4. **Add everyone else** (Players & Accounts → *The Emperor* card):
   - **Create account** for each person, choosing their role
     (Investigator, Keeper, or Admin), and hand them the login, **and/or**
   - Turn on an **invite code** and share it so players can self‑register
     (self‑signups are always Investigators).

That's it. Bookmark the URL and share it with your table.

---

## Alternative hosts

- **Railway** (<https://railway.app>): New Project → Deploy from GitHub repo.
  Add a **Volume** mounted at `/data`, then set a variable `DATA_DIR=/data`.
  Set `NODE_ENV=production`. Uses a monthly usage credit.
- **Any VPS / your own always‑on machine**: install Node 18+, copy the files,
  run `npm install` then `npm start`. Put it behind a reverse proxy with
  HTTPS (Caddy or Nginx). Set `DATA_DIR` to a folder you back up.

Whatever the host, the only thing that truly matters is that **`DATA_DIR`
points at storage that persists** and that the site is served over **HTTPS**
(needed for secure login cookies; `NODE_ENV=production` turns them on).

---

## Running it on your own computer (to try it first)

```bash
npm install
npm start
```

Then open <http://localhost:3000>. The first visit asks you to create the
Keeper account. Data is saved in a `data/` folder next to the code.

---

## Everyday Keeper tasks

- **Reset a password / rename / make a co‑Keeper:** Players & Accounts →
  **Manage** on that person.
- **Remove the example campaign:** Keeper's Table → **Delete example data**.
- **Change the code an old player used:** Players & Accounts → **Change /
  toggle** the invite code (or switch it off).
- **Back up your data:** copy the `data.json` file from your `DATA_DIR`.

## Security notes

- Passwords are hashed with bcrypt; they are never stored in plain text.
- Keeper‑only assets, hidden NPCs, and Keeper's Secrets are filtered out
  **on the server** — an investigator's browser never receives them.
- Always serve the site over HTTPS (all recommended hosts do this for you).

## Environment variables

See `.env.example`. All are optional; the app runs with defaults.
