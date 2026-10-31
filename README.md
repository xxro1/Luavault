# LuaVault — single-host server edition

The website and its API run in **one Node.js + Express app on one host and one domain**. Express serves the HTML from `public/index.html`; browser requests such as `/api/login` and `/api/scripts` go to that same server. You do not need a separate static-site host or a separate API host.

## What is included

- Original LuaVault page design in `public/index.html`.
- Express server serving both the website and `/api/*` endpoints.
- Server-side signup/login with bcrypt password hashing.
- HTTP-only session cookies stored in SQLite.
- Community script submissions and view counts stored in SQLite.
- Protected admin login, script management, user deletion, import/export, and reset endpoints.
- Request limits and same-origin checks on write endpoints.

Built-in sample entries remain in the original page and are read-only in the admin panel. Community submissions and accounts are stored on the server.

## Run directly with Node.js

Requirements: Node.js 20+ and npm.

1. Copy `.env.example` to `.env`.
2. Set `SESSION_SECRET` to a private random string of at least 32 characters.
3. Set `ADMIN_PASSWORD` to a strong private password of at least 14 characters. Admin username is `admin`.
4. Install dependencies: `npm install`.
5. Start: `npm start`.
6. Open `http://localhost:3000`.

Admin panel: `http://localhost:3000/#admin`.

## Run as one Docker deployment

Requirements: Docker Engine and Docker Compose.

1. Copy `.env.example` to `.env` and set your own `SESSION_SECRET` and `ADMIN_PASSWORD`.
2. Run `docker compose up -d --build`.
3. Open `http://localhost:3000` (or connect your host's domain/reverse proxy to port 3000).

Docker Compose mounts a persistent volume at `/data`, so the SQLite database and sessions survive container replacement. Back up that volume regularly.

## Deploy to a Node.js host

Deploy this **entire project folder** as one Node.js web service, not just the HTML file. Use:

- Build command: `npm install`
- Start command: `npm start`
- Node version: 20 or newer
- Environment variables: `NODE_ENV=production`, `SESSION_SECRET`, `ADMIN_PASSWORD`, and optionally `DATA_DIR`

Attach persistent disk/storage and set `DATA_DIR` to its mount path. Without persistent storage, SQLite data may be lost when the host replaces its filesystem. Use HTTPS in production. Do not expose the SQLite files or `.env` publicly.

## Routes

- `GET /` serves the LuaVault website.
- `GET /healthz` is a health check.
- `GET /api/session`
- `POST /api/signup`, `POST /api/login`, `POST /api/logout`
- `GET /api/scripts`, `POST /api/scripts`, `POST /api/scripts/:id/view`
- `POST /api/admin/login`, `POST /api/admin/logout`
- `GET /api/admin/overview`, `GET /api/admin/export`, `POST /api/admin/import`
- `PATCH /api/admin/scripts/:id`, `DELETE /api/admin/scripts/:id`
- `DELETE /api/admin/users/:id`, `DELETE /api/admin/data`

## Important

The existing Cloudflare Pages `pages.dev` deployment is a static host; it will not run this Express server. For the single-host option, point your domain to the Node.js app and let Express serve the HTML and API together. I cannot deploy it to your hosting account without access to that provider, but this project is structured for a one-host deployment.
