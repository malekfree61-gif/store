# Veyro Store

Veyro is a bilingual storefront with a protected admin dashboard. The application runs as one Node.js service and stores products, inventory, discounts, orders, settings, and login sessions in SQLite.

## Run locally

Install Node.js 24 or newer, then run:

```powershell
npm install
$env:ADMIN_EMAIL="your-admin-email@example.com"
$env:ADMIN_PASSWORD="use-a-strong-private-password"
npm start
```

Open `http://localhost:3000` for the storefront or `http://localhost:3000/admin.html` for the dashboard. Product data is seeded from `public/data/db.json` on first start. The database and uploaded product images are kept under `data/`.

## Deploy on Render

`render.yaml` defines a Node 24 web service and a persistent disk for the database and uploaded images. Import this repository as a Render Blueprint, then set `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD` in the service environment before exposing the admin URL. The Starter service and persistent disk are paid Render resources; no external service is created or charged by this repository.

For a Docker host, build with `docker build -t veyro-store .` and run with a mounted `/var/data` volume plus `ADMIN_EMAIL` and `ADMIN_PASSWORD`. The server generates a session secret if `SESSION_SECRET` is omitted; set a long random value in production to keep session signing stable across restarts.

For local testing, the server listens on `127.0.0.1` by default. Deployment configurations explicitly bind it to `0.0.0.0` for the hosting proxy.

## Orders and payments

The server verifies product availability, prices, quantities, and discounts before saving an order and decrementing stock in a SQLite transaction. The admin dashboard reads from the same database. Cash on delivery and configured Vodafone Cash or InstaPay transfers are supported. Card payments require a merchant account and a server-side gateway integration; no card data is collected by this app.
