
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  FRONTEND_URL,
  SESSION_SECRET
} = process.env;

const GUILD_ID = "1543790133407383634";
const PORT = process.env.PORT || 3000;

if (
  !DISCORD_CLIENT_ID ||
  !DISCORD_CLIENT_SECRET ||
  !DISCORD_REDIRECT_URI ||
  !FRONTEND_URL ||
  !SESSION_SECRET
) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

const frontend = FRONTEND_URL.replace(/\/+$/, "");
const tickets = new Map();

app.use(session({
  name: "sws_oauth",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 10 * 60 * 1000
  }
}));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", frontend);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");

  return `${body}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== "string") return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [body, signature] = parts;
  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest();

  let received;
  try {
    received = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }

  if (
    received.length !== expected.length ||
    !crypto.timingSafeEqual(received, expected)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    );

    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  const user = verifyToken(token);
  if (!user) {
    return res.status(401).json({ error: "Please sign in again." });
  }

  req.user = user;
  next();
}

app.get("/", (req, res) => {
  res.type("text").send("SWS authentication backend is running.");
});

app.get("/auth/discord", (req, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds",
    state
  });

  res.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`
  );
});

app.get("/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send("Discord authorization was cancelled.");
  }

  if (
    !code ||
    !state ||
    !req.session.oauthState ||
    typeof state !== "string" ||
    state !== req.session.oauthState
  ) {
    return res.status(400).send("Invalid OAuth state. Please try again.");
  }

  delete req.session.oauthState;

  try {
    const tokenResponse = await fetch(
      "https://discord.com/api/v10/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: DISCORD_REDIRECT_URI
        })
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error("Discord token exchange failed:", tokenData.error);
      return res.status(401).send("Discord login failed. Please try again.");
    }

    const headers = {
      Authorization: `Bearer ${tokenData.access_token}`
    };

    const [userResponse, guildResponse] = await Promise.all([
      fetch("https://discord.com/api/v10/users/@me", { headers }),
      fetch("https://discord.com/api/v10/users/@me/guilds", { headers })
    ]);

    if (!userResponse.ok || !guildResponse.ok) {
      return res.status(502).send("Could not verify your Discord account.");
    }

    const user = await userResponse.json();
    const guilds = await guildResponse.json();

    const isMember = Array.isArray(guilds) &&
      guilds.some(guild => guild.id === GUILD_ID);

    // The login code can only be exchanged once and expires quickly.
    const ticket = crypto.randomBytes(32).toString("hex");

    tickets.set(ticket, {
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar || null
      },
      isMember,
      expires: Date.now() + 60_000
    });

    return res.redirect(
      `${frontend}/?login_code=${encodeURIComponent(ticket)}`
    );
  } catch (err) {
    console.error("OAuth callback error:", err.message);
    return res.status(500).send("Authentication failed. Please try again.");
  }
});

app.post("/auth/exchange", (req, res) => {
  const { code } = req.body || {};

  if (typeof code !== "string" || code.length !== 64) {
    return res.status(400).json({ error: "Invalid login code." });
  }

  const record = tickets.get(code);
  tickets.delete(code);

  if (!record || record.expires < Date.now()) {
    return res.status(401).json({
      error: "Login code expired. Please sign in again."
    });
  }

  if (!record.isMember) {
    return res.status(403).json({
      error: "You must join KAI'S HUB before using this server.",
      member: false
    });
  }

  const token = signToken({
    sub: record.user.id,
    username: record.user.username,
    avatar: record.user.avatar,
    guildId: GUILD_ID,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  });

  res.setHeader("Cache-Control", "no-store");
  res.json({
    token,
    user: record.user,
    server: {
      id: GUILD_ID,
      name: "KAI'S HUB",
      path: "kaihub.html"
    }
  });
});

app.get("/api/me", requireAuth, (req, res) => {
  if (req.user.guildId !== GUILD_ID) {
    return res.status(403).json({ error: "Access denied." });
  }

  res.setHeader("Cache-Control", "no-store");
  res.json({
    user: {
      id: req.user.sub,
      username: req.user.username,
      avatar: req.user.avatar
    },
    server: {
      id: GUILD_ID,
      name: "KAI'S HUB"
    }
  });
});

app.get("/api/servers", requireAuth, (req, res) => {
  if (req.user.guildId !== GUILD_ID) {
    return res.status(403).json({ error: "Access denied." });
  }

  res.setHeader("Cache-Control", "no-store");
  res.json({
    servers: [{
      id: GUILD_ID,
      name: "KAI'S HUB",
      path: "kaihub.html"
    }]
  });
});

// Expire unused login codes.
setInterval(() => {
  for (const [code, record] of tickets) {
    if (record.expires < Date.now()) tickets.delete(code);
  }
}, 30_000).unref();

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SWS backend listening on port ${PORT}`);
});

