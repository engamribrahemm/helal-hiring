const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");

const envPath = path.join(__dirname, ".env");
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const i = trimmed.indexOf("=");
    if (i === -1) continue;
    const key = trimmed.slice(0, i).trim();
    let value = trimmed.slice(i + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error("Missing required environment variable:", name);
    process.exit(1);
  }
  return value;
}

const AUTH_USER = requireEnv("AUTH_USER");
const AUTH_PASSWORD = requireEnv("AUTH_PASSWORD");
const SESSION_SECRET = requireEnv("SESSION_SECRET");
const COOKIE_NAME = "helal_session";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7;
const APP_FILE = path.join(__dirname, "protected", "helal-hiring.html");
const LOGIN_FILE = path.join(__dirname, "views", "login.html");
const loginTemplate = fs.readFileSync(LOGIN_FILE, "utf8");

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false, limit: "8kb" }));

const attempts = new Map();

function clientIp(req) {
  return String(req.ip || req.socket.remoteAddress || "unknown");
}

function tooManyAttempts(ip) {
  const row = attempts.get(ip);
  if (!row) return false;
  if (Date.now() > row.until) {
    attempts.delete(ip);
    return false;
  }
  return row.count >= 8;
}

function recordFailure(ip) {
  const now = Date.now();
  const row = attempts.get(ip) || { count: 0, until: now + 15 * 60 * 1000 };
  row.count += 1;
  row.until = now + 15 * 60 * 1000;
  attempts.set(ip, row);
}

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }
  return out;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) {
    crypto.timingSafeEqual(left, left);
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

function makeToken() {
  const payload = `ok.${Date.now()}`;
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

function validToken(token) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const payload = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  return parts[0] === "ok" && safeEqual(parts[2], expected);
}

function isAuthed(req) {
  return validToken(parseCookies(req)[COOKIE_NAME]);
}

function setSessionCookie(req, res) {
  const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
  const cookie = [
    `${COOKIE_NAME}=${encodeURIComponent(makeToken())}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${COOKIE_MAX_AGE}`,
  ];
  if (secure) cookie.push("Secure");
  res.setHeader("Set-Cookie", cookie.join("; "));
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`
  );
}

function sendLogin(res, error) {
  const errorHtml = error
    ? `<div class="error">${error}</div>`
    : "";
  res.set("Cache-Control", "no-store");
  res.set("X-Robots-Tag", "noindex, nofollow");
  res.type("html").send(loginTemplate.replace("{{ERROR}}", errorHtml));
}

app.get("/login", (req, res) => {
  if (isAuthed(req)) return res.redirect("/");
  sendLogin(res);
});

app.post("/login", (req, res) => {
  if (isAuthed(req)) return res.redirect("/");
  const ip = clientIp(req);
  if (tooManyAttempts(ip)) {
    return sendLogin(res, "Too many attempts. Try again in 15 minutes.");
  }
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  if (!safeEqual(username, AUTH_USER) || !safeEqual(password, AUTH_PASSWORD)) {
    recordFailure(ip);
    return sendLogin(res, "Incorrect username or password.");
  }
  attempts.delete(ip);
  setSessionCookie(req, res);
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  clearSessionCookie(res);
  res.redirect("/login");
});

app.get("/", (req, res) => {
  if (!isAuthed(req)) return res.redirect("/login");
  res.set("Cache-Control", "private, no-store");
  res.set("X-Robots-Tag", "noindex, nofollow");
  res.sendFile(APP_FILE);
});

app.use((req, res) => {
  if (!isAuthed(req)) return res.redirect("/login");
  res.status(404).type("text").send("Not found");
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log("Helal hiring portal listening on port", port);
});
