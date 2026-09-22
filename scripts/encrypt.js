const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const envPath = path.join(root, ".env");
const sourcePath = path.join(root, "protected", "helal-hiring.html");
const outPath = path.join(root, "payload.json");
const ITERATIONS = 210000;

function loadEnv() {
  const env = {};
  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const i = trimmed.indexOf("=");
    if (i === -1) continue;
    env[trimmed.slice(0, i).trim()] = trimmed.slice(i + 1).trim();
  }
  return env;
}

if (!fs.existsSync(envPath)) {
  console.error("Missing .env");
  process.exit(1);
}
if (!fs.existsSync(sourcePath)) {
  console.error("Missing protected/helal-hiring.html");
  process.exit(1);
}

const env = loadEnv();
if (!env.AUTH_USER || !env.AUTH_PASSWORD) {
  console.error("AUTH_USER and AUTH_PASSWORD are required in .env");
  process.exit(1);
}

const plaintext = fs.readFileSync(sourcePath);
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const key = crypto.pbkdf2Sync(
  `${env.AUTH_USER}:${env.AUTH_PASSWORD}`,
  salt,
  ITERATIONS,
  32,
  "sha256"
);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

fs.writeFileSync(
  outPath,
  JSON.stringify({
    v: 1,
    iter: ITERATIONS,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    data: encrypted.toString("base64"),
  })
);

console.log("Encrypted portal written to payload.json");
