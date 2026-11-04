const express = require("express");
const cookieSession = require("cookie-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";

if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !SESSION_SECRET) {
  console.error(
    "Missing Render environment variables: ADMIN_EMAIL, ADMIN_PASSWORD, SESSION_SECRET"
  );
  process.exit(1);
}
if (SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be at least 32 characters long.");
  process.exit(1);
}
if (ADMIN_PASSWORD.length < 12) {
  console.error("ADMIN_PASSWORD must be at least 12 characters long.");
  process.exit(1);
}

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.use(
  cookieSession({
    name: "rinku_dashboard_session",
    keys: [SESSION_SECRET],
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000
  })
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: "Too many login attempts. Please wait 15 minutes and try again."
});

function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a));
  const bBuf = Buffer.from(String(b));
  return aBuf.length === bBuf.length && crypto.timingSafeEqual(aBuf, bBuf);
}

function requireLogin(req, res, next) {
  if (req.session && req.session.authenticated === true &&
      req.session.email === ADMIN_EMAIL) {
    return next();
  }
  return res.redirect("/login");
}

function loginPage(error = "") {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Private Dashboard Login</title>
<style>
:root{color-scheme:dark;font-family:system-ui,-apple-system,Segoe UI,sans-serif}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;
background:radial-gradient(700px 400px at 10% 0%,#1d3264,transparent 65%),#060b1a;color:#e6ebff}
.card{width:min(100%,410px);padding:28px;border:1px solid #34415f;border-radius:20px;
background:rgba(15,24,48,.94);box-shadow:0 20px 70px #0008}
.logo{width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,#4f8cff,#8b5cf6);margin-bottom:18px}
h1{font-size:25px;margin:0 0 6px}p{color:#9ba9ca;margin:0 0 22px}
label{display:block;font-size:13px;margin:14px 0 7px;color:#c6d0e9}
input{width:100%;padding:13px;border:1px solid #3a496c;border-radius:10px;background:#0a1128;color:#fff;font:inherit}
button{width:100%;padding:13px;margin-top:20px;border:0;border-radius:10px;
background:linear-gradient(90deg,#4f8cff,#8b5cf6);color:white;font-weight:700;font-size:15px}
.error{padding:10px;border-radius:9px;background:#4a1f32;color:#ffc5d2;margin:12px 0}
.small{text-align:center;font-size:12px;margin:18px 0 0;color:#8291b5}
</style>
</head>
<body><main class="card">
<div class="logo"></div>
<h1>Rinku's Private Dashboard</h1>
<p>Sign in to continue to your learning command center.</p>
${error ? `<div class="error" role="alert">${error}</div>` : ""}
<form method="post" action="/login">
<label for="email">Email address</label>
<input id="email" name="email" type="email" autocomplete="username" required maxlength="254">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required maxlength="200">
<button type="submit">Sign in securely</button>
</form>
<div class="small">Private access · Session expires after 8 hours</div>
</main></body></html>`;
}

app.get("/healthz", (req, res) => res.status(200).send("ok"));

app.get("/login", (req, res) => {
  if (req.session && req.session.authenticated === true &&
      req.session.email === ADMIN_EMAIL) {
    return res.redirect("/");
  }
  res.status(200).send(loginPage());
});

app.post("/login", loginLimiter, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const valid = safeEqual(email, ADMIN_EMAIL) &&
                safeEqual(password, ADMIN_PASSWORD);

  if (!valid) {
    return res.status(401).send(loginPage("Email or password is incorrect."));
  }

  req.session = { authenticated: true, email: ADMIN_EMAIL };
  return res.redirect("/");
});

app.post("/logout", requireLogin, (req, res) => {
  req.session = null;
  res.redirect("/login");
});

app.get("/", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "command-center.html"), (err) => {
    if (err && !res.headersSent) {
      res.status(404).send("Dashboard file not found. Check command-center.html is in the repository root.");
    }
  });
});

// Do not expose repository files, source code, or unknown paths.
app.use((req, res) => res.status(404).send("Not found"));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Private dashboard server listening on port ${PORT}`);
});
