import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { URL } from "node:url";

const PORT = Number(process.env.SHOPIFY_PORT || 3001);
const APP_URL = (process.env.SHOPIFY_APP_URL || "").replace(/\/$/, "");
const REDIRECT_PATH = process.env.SHOPIFY_REDIRECT_PATH || "/auth/callback";
const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || "";
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || "";
const DEFAULT_SHOP = process.env.SHOPIFY_DEFAULT_SHOP || "";
const SCOPES =
  process.env.SHOPIFY_SCOPES ||
  "read_orders,write_orders,read_customers,read_fulfillments";

const REDIRECT_URI = `${APP_URL}${REDIRECT_PATH}`;
const SHOPIFY_API_VERSION = "2025-01";

const DATA_DIR = path.join(process.cwd(), "data");
const STATE_FILE = path.join(DATA_DIR, "oauth-states.json");
const TOKEN_FILE = path.join(DATA_DIR, "shopify-token.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function json(res, status, data) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
  });
  res.end(JSON.stringify(data, null, 2));
}

function text(res, status, body) {
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
  });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, { location });
  res.end();
}

function isValidShop(shop) {
  return /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i.test(shop || "");
}

function generateState() {
  return crypto.randomBytes(16).toString("hex");
}

function saveState(state, shop) {
  const states = readJson(STATE_FILE, {});
  states[state] = { shop, createdAt: Date.now() };
  writeJson(STATE_FILE, states);
}

function consumeState(state, shop) {
  const states = readJson(STATE_FILE, {});
  const row = states[state];
  delete states[state];
  writeJson(STATE_FILE, states);

  if (!row) return false;
  if (row.shop !== shop) return false;
  if (Date.now() - row.createdAt > 1000 * 60 * 15) return false;

  return true;
}

function verifyHmac(query) {
  const hmac = query.get("hmac");
  if (!hmac) return false;

  const entries = [];
  for (const [key, value] of query.entries()) {
    if (key === "hmac" || key === "signature") continue;
    entries.push([key, value]);
  }

  entries.sort((a, b) => a[0].localeCompare(b[0]));
  const message = entries.map(([k, v]) => `${k}=${v}`).join("&");

  const digest = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(message)
    .digest("hex");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(digest, "utf8"),
      Buffer.from(hmac, "utf8")
    );
  } catch {
    return false;
  }
}

async function exchangeCode(shop, code) {
  const response = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
    }),
  });

  const raw = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = { raw };
  }

  if (!response.ok) {
    throw new Error(`Token exchange failed (${response.status}): ${raw}`);
  }

  return parsed;
}

function getStoredToken() {
  return readJson(TOKEN_FILE, null);
}

async function shopifyGraphQL(query, variables = {}) {
  const token = getStoredToken();

  if (!token?.access_token || !token?.shop) {
    throw new Error("Shopify token not available");
  }

  const response = await fetch(
    `https://${token.shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Shopify-Access-Token": token.access_token,
      },
      body: JSON.stringify({ query, variables }),
    }
  );

  const raw = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Invalid Shopify response: ${raw}`);
  }

  if (!response.ok) {
    throw new Error(`Shopify API error (${response.status}): ${raw}`);
  }

  if (parsed.errors) {
    throw new Error(`GraphQL errors: ${JSON.stringify(parsed.errors)}`);
  }

  return parsed.data;
}

function simplifyOrders(edges) {
  return (edges || []).map(({ node }) => ({
    id: node.id,
    name: node.name,
    email: node.email,
    createdAt: node.createdAt,
    displayFinancialStatus: node.displayFinancialStatus,
    displayFulfillmentStatus: node.displayFulfillmentStatus,
    customerName: node.customer
      ? `${node.customer.firstName || ""} ${node.customer.lastName || ""}`.trim()
      : null,
    lineItems: (node.lineItems?.edges || []).map(({ node: li }) => ({
      title: li.title,
      variantTitle: li.variantTitle,
      quantity: li.quantity,
      sku: li.sku,
    })),
  }));
}

async function findOrdersByQuery(searchQuery) {
  const query = `
    query FindOrders($query: String!) {
      orders(first: 10, query: $query, sortKey: CREATED_AT, reverse: true) {
        edges {
          node {
            id
            name
            email
            createdAt
            displayFinancialStatus
            displayFulfillmentStatus
            customer {
              firstName
              lastName
            }
            lineItems(first: 20) {
              edges {
                node {
                  title
                  variantTitle
                  quantity
                  sku
                }
              }
            }
          }
        }
      }
    }
  `;

  const data = await shopifyGraphQL(query, { query: searchQuery });
  return simplifyOrders(data?.orders?.edges || []);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/health") {
    return json(res, 200, {
      ok: true,
      service: "shopify-oauth",
      appUrl: APP_URL,
      redirectUri: REDIRECT_URI,
      defaultShop: DEFAULT_SHOP,
      scopes: SCOPES,
    });
  }

  if (url.pathname === "/token-status") {
    const token = readJson(TOKEN_FILE, null);
    return json(res, 200, {
      ok: true,
      configured: Boolean(CLIENT_ID && CLIENT_SECRET),
      hasToken: Boolean(token?.access_token),
      shop: token?.shop || null,
      scopes: token?.scope || null,
      obtainedAt: token?.obtainedAt || null,
    });
  }

  if (url.pathname === "/orders/by-email") {
    try {
      const email = (url.searchParams.get("email") || "").trim();
      if (!email) {
        return json(res, 400, { ok: false, error: "email is required" });
      }

      const orders = await findOrdersByQuery(`email:${email}`);
      return json(res, 200, {
        ok: true,
        query: { email },
        count: orders.length,
        orders,
      });
    } catch (err) {
      return json(res, 500, { ok: false, error: String(err?.message || err) });
    }
  }

  if (url.pathname === "/orders/by-name") {
    try {
      const name = (url.searchParams.get("name") || "").trim();
      if (!name) {
        return json(res, 400, { ok: false, error: "name is required" });
      }

      const orders = await findOrdersByQuery(`customer_name:${name}`);
      return json(res, 200, {
        ok: true,
        query: { name },
        count: orders.length,
        orders,
      });
    } catch (err) {
      return json(res, 500, { ok: false, error: String(err?.message || err) });
    }
  }

  if (url.pathname === "/orders/by-number") {
    try {
      const order = (url.searchParams.get("order") || "").trim();
      if (!order) {
        return json(res, 400, { ok: false, error: "order is required" });
      }

      const normalized = order.startsWith("#") ? order : `#${order}`;
      const orders = await findOrdersByQuery(`name:${normalized}`);
      return json(res, 200, {
        ok: true,
        query: { order: normalized },
        count: orders.length,
        orders,
      });
    } catch (err) {
      return json(res, 500, { ok: false, error: String(err?.message || err) });
    }
  }

  if (url.pathname === "/auth/start") {
    if (!CLIENT_ID || !CLIENT_SECRET) {
      return text(res, 500, "Missing Shopify client credentials");
    }

    const shop = (url.searchParams.get("shop") || DEFAULT_SHOP || "").trim();

    if (!isValidShop(shop)) {
      return text(res, 400, "Missing or invalid ?shop=...myshopify.com");
    }

    const state = generateState();
    saveState(state, shop);

    const authUrl = new URL(`https://${shop}/admin/oauth/authorize`);
    authUrl.searchParams.set("client_id", CLIENT_ID);
    authUrl.searchParams.set("scope", SCOPES);
    authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
    authUrl.searchParams.set("state", state);

    return redirect(res, authUrl.toString());
  }

  if (url.pathname === REDIRECT_PATH) {
    const shop = url.searchParams.get("shop") || "";
    const code = url.searchParams.get("code") || "";
    const state = url.searchParams.get("state") || "";

    if (!isValidShop(shop)) return text(res, 400, "Invalid shop");
    if (!code) return text(res, 400, "Missing code");
    if (!state) return text(res, 400, "Missing state");
    if (!verifyHmac(url.searchParams)) return text(res, 400, "Invalid HMAC");
    if (!consumeState(state, shop)) {
      return text(res, 400, "Invalid or expired state");
    }

    try {
      const token = await exchangeCode(shop, code);
      writeJson(TOKEN_FILE, {
        ...token,
        shop,
        obtainedAt: new Date().toISOString(),
      });

      return text(
        res,
        200,
        "Shopify app authorized successfully. You can close this tab."
      );
    } catch (err) {
      return text(res, 500, String(err?.message || err));
    }
  }

  return text(res, 404, "Not found");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`shopify-oauth listening on :${PORT}`);
});
