# CIMI — Cyber Incident Monitor in India

A Tailwind CSS front end for a Security Operations Center dashboard: IoC lookup, threat
correlation, log analysis, and threat intelligence feeds — backed by the `cimi-backend` API.

## 🚀 Features

- **HTML5** - Modern HTML structure with best practices
- **Tailwind CSS** - Utility-first CSS framework for rapid UI development
- **Live threat intel** - talks to `cimi-backend`, which aggregates VirusTotal, AbuseIPDB,
  AlienVault OTX, and the CISA KEV catalog
- **Custom Components** - Pre-built component classes for buttons and containers
- **Responsive Design** - Mobile-first approach for all screen sizes

## 📋 Prerequisites

- Node.js (v12.x or higher)
- npm or yarn
- A running instance of `cimi-backend` (see the backend's own README)

## 🛠️ Installation

1. Install dependencies:
```bash
npm install
```

2. Point the frontend at your backend — edit `js/api.js` and set `API_BASE_URL`
   (defaults to `http://localhost:4000/api`).

3. Build the CSS and serve the `pages/` + `index.html` with any static file server, e.g.:
```bash
npm run build:css
npx serve .
```

## 📁 Project Structure

```
cimi-frontend/
├── css/
│   ├── tailwind.css   # Tailwind source file with custom utilities
│   └── main.css       # Compiled CSS (generated)
├── js/
│   └── api.js          # Shared fetch wrapper + auth/IoC/dashboard/feed calls
├── pages/               # login, dashboard, IoC lookup, correlation, log analysis, feeds
├── index.html            # Redirects to pages/login.html
├── package.json
└── tailwind.config.js
```

## 🔌 Backend

This UI expects `cimi-backend` running locally (default `http://localhost:4000`). Log in with
the account created by `npm run seed` in the backend (default `admin@cimi.gov.in`).

## 📱 Responsive Design

- `sm`: 640px and up
- `md`: 768px and up
- `lg`: 1024px and up
- `xl`: 1280px and up
- `2xl`: 1536px and up
