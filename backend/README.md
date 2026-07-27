# CIMI Backend
**Cyber Incident Monitor — India**

Node.js/Express API that powers the CIMI frontend. It aggregates live indicator-of-compromise
(IoC) data from **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX**, and cross-references
vulnerabilities against the **CISA Known Exploited Vulnerabilities (KEV)** catalog.

## Features

- JWT-based authentication (email + password, scrypt password hashing, no external crypto deps)
- **IoC Lookup** — auto-detects IP / domain / URL / MD5 / SHA1 / SHA256 and queries all
  applicable sources in parallel, returning a blended threat score + verdict
- **Bulk IoC lookup** (up to 25 indicators per request)
- **Threat Correlation** — groups a set of indicators by shared OTX pulses/tags to surface
  likely-related campaigns
- **Log Analysis** — upload a raw log file (or paste log text), extract IPs/domains/URLs/hashes
  with regex, and auto-screen the first 15 unique indicators against live threat intel
- **Threat Intelligence Feeds** — CISA KEV catalog (search by CVE/vendor/product) + AlienVault
  OTX subscribed pulses
- **Dashboard** — KPI summary, daily verdict trend series, and geographic distribution, all
  computed from your own lookup history
- In-memory caching (15 min default, 6h for the CISA feed) to stay within free-tier API quotas
- Rate limiting, helmet security headers, CORS
- Zero database server required — durable state lives in flat JSON files under `src/data/`

## Getting an API key for each source

| Source | Free tier | Sign up |
|---|---|---|
| VirusTotal | 4 req/min, 500/day | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | 1,000 checks/day | https://www.abuseipdb.com/register |
| AlienVault OTX | Free | https://otx.alienvault.com/ |
| CISA KEV | Public, no key needed | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |

## Setup

```bash
cd cimi-backend
npm install
cp .env.example .env
# edit .env and paste in your VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY / OTX_API_KEY

npm run seed   # creates the default admin@cimi.gov.in account (prints the generated password)
npm start      # or: npm run dev
```

The API listens on `http://localhost:4000` by default (see `PORT` in `.env`).

## Authentication

```
POST /api/auth/login        { "email": "...", "password": "..." }  -> { token, user }
GET  /api/auth/me            (Authorization: Bearer <token>)
POST /api/auth/logout        (Authorization: Bearer <token>)
```

Every route below (except `/api/health`) requires `Authorization: Bearer <token>`.

## Endpoints

```
GET  /api/health

POST /api/ioc/lookup         { "indicator": "8.8.8.8" }
POST /api/ioc/bulk           { "indicators": ["8.8.8.8", "evil.com"] }
GET  /api/ioc/history?limit=50

GET  /api/dashboard/summary
GET  /api/dashboard/trends?days=7
GET  /api/dashboard/geo-distribution

GET  /api/feeds                       (combined CISA KEV + OTX pulses)
GET  /api/feeds/cisa-kev?q=<search>&limit=50&offset=0
GET  /api/feeds/otx-pulses?limit=20

POST /api/correlation/analyze         { "indicators": ["ip1","domain1", ...] }

POST /api/logs/analyze                multipart/form-data field "logFile", or JSON { "logText": "..." }
GET  /api/logs/reports?limit=20
```

## Project layout

```
cimi-backend/
├── server.js                # entry point
├── src/
│   ├── app.js                # express app + route mounting
│   ├── config/                # env-driven config
│   ├── middleware/             # auth, rate limiting, error handling
│   ├── routes/                 # one router per frontend page/feature
│   ├── services/                # one client per external API + aggregator
│   ├── utils/                    # cache, IoC regex detection, JSON storage, password hashing
│   └── data/                       # flat-file "database" (git-ignored)
└── scripts/seedUsers.js       # creates the default admin account
```

## Notes on data storage

There's no external database — `src/utils/jsonStore.js` is a tiny helper that reads/writes flat
JSON files (`users.json`, `ioc_history.json`, `log_reports.json`) under `src/data/`. This keeps the
project dependency-free and easy to run anywhere; swap it for Postgres/Mongo later by re-implementing
that one module if you outgrow it.
