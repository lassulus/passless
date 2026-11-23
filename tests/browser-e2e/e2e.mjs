// End-to-end: a real Chromium (headless) with the passless browser extension registers and
// signs in on a local WebAuthn page; the native messaging host is the passless binary on a
// passage store with a plain age identity. No npm dependencies: CDP over Node's WebSocket.
//
// Usage: node e2e.mjs <passless binary> <chromium binary> <age binary>
// Environment: KEEP=1 keeps the scratch directory.

import { execFileSync, spawn } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { createServer } from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const [passless, chromium, age] = process.argv.slice(2).map((p) => path.resolve(p));
if (!passless || !chromium || !age) {
  console.error("usage: node e2e.mjs <passless> <chromium> <age>");
  process.exit(2);
}
const here = path.dirname(fileURLToPath(import.meta.url));
const extensionDir = path.resolve(here, "../../cmd/passless/assets/browser-extension");
const extensionId = "adlnfbjbndianbljppelgaecanjmpppo";

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "passless-browser-e2e-"));
const store = path.join(scratch, "store");
const profile = path.join(scratch, "profile");
const ageLog = path.join(scratch, "age.log");
const hostLog = path.join(scratch, "host.log");

function check(condition, message) {
  if (!condition) throw new Error("FAILED: " + message);
  console.log("ok   " + message);
}

const b64u = (s) => Buffer.from(s, "base64url");
const decrypts = () =>
  fs.existsSync(ageLog) ? fs.readFileSync(ageLog, "utf8").split("\n").filter((l) => l.startsWith("-d ")) : [];

// ---- passage store with a plain age identity; `age` wrapped to log every run -------------------
fs.mkdirSync(store, { recursive: true });
const identity = path.join(scratch, "identity.txt");
execFileSync(path.join(path.dirname(age), "age-keygen"), ["-o", identity], { stdio: "ignore" });
const recipient = execFileSync(path.join(path.dirname(age), "age-keygen"), ["-y", identity]).toString().trim();
fs.writeFileSync(path.join(store, ".age-recipients"), recipient + "\n");
const ageWrapper = path.join(scratch, "age");
fs.writeFileSync(
  ageWrapper,
  `#!/bin/sh\nprintf '%s %s\\n' "$1" "$PASSLESS_AGE_TARGET" >> '${ageLog}'\nexec '${age}' "$@"\n`,
  { mode: 0o755 }
);

// ---- native messaging host: the passless binary itself, started by Chromium ---------------------
const hostWrapper = path.join(scratch, "passless-host");
// Only to capture the host's stderr in a file; Chromium passes the origin argument through.
fs.writeFileSync(hostWrapper, `#!/bin/sh\nexec '${passless}' "$@" 2>> '${hostLog}'\n`, { mode: 0o755 });
fs.mkdirSync(path.join(profile, "NativeMessagingHosts"), { recursive: true });
fs.writeFileSync(
  path.join(profile, "NativeMessagingHosts", "rs.passless.browser.json"),
  JSON.stringify({
    name: "rs.passless.browser",
    description: "passless",
    path: hostWrapper,
    type: "stdio",
    allowed_origins: [`chrome-extension://${extensionId}/`],
  })
);

// ---- the relying party: a local page ------------------------------------------------------------
const page = `<!doctype html><title>rp</title><script>
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const rnd = () => crypto.getRandomValues(new Uint8Array(32));
window.register = async (name) => {
  const challenge = rnd();
  const c = await navigator.credentials.create({ publicKey: {
    rp: { name: "e2e" }, user: { id: new TextEncoder().encode(name), name, displayName: name },
    challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
    timeout: 30000, extensions: { credProps: true } } });
  return { json: c.toJSON(), challenge: b64u(challenge), cls: c.constructor.name,
           rk: c.getClientExtensionResults().credProps?.rk };
};
window.signIn = async (ids) => {
  const challenge = rnd();
  const a = await navigator.credentials.get({ publicKey: { challenge, timeout: 30000,
    allowCredentials: ids.map((id) => ({ type: "public-key",
      id: Uint8Array.from(atob(id.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)) })),
    userVerification: "preferred" } });
  return { json: a.toJSON(), challenge: b64u(challenge), cls: a.constructor.name };
};
window.uvpaa = () => PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
</script>`;
const server = createServer((_, res) => res.end(page)).listen(0, "127.0.0.1");
await new Promise((r) => server.once("listening", r));
const origin = `http://localhost:${server.address().port}`;

// ---- Chromium -----------------------------------------------------------------------------------
const env = {
  ...process.env,
  HOME: scratch,
  XDG_CONFIG_HOME: path.join(scratch, "config"),
  XDG_RUNTIME_DIR: path.join(scratch, "run"),
  PASSLESS_BACKEND_TYPE: "passage",
  PASSLESS_PASSAGE_STORE_PATH: store,
  PASSLESS_PASSAGE_PATH: "www",
  PASSLESS_PASSAGE_IDENTITIES_FILE: identity,
  PASSLESS_PASSAGE_AGE_BINARY: ageWrapper,
  PASSLESS_PASSAGE_GIT_SYNC: "false",
  // As on the Mac with a Secure Enclave identity: signing in needs no prompt, the decrypt is
  // the check. Registration still asks; with no desktop here that prompt is approved.
  PASSLESS_USER_VERIFICATION_AUTHENTICATION: "false",
  PASSLESS_INTERACTION_MODE: "automatic",
  PASSLESS_LOG_LEVEL: "debug",
};
fs.mkdirSync(env.XDG_RUNTIME_DIR, { mode: 0o700 });
const browser = spawn(
  chromium,
  [
    "--headless=new",
    `--user-data-dir=${profile}`,
    `--load-extension=${extensionDir}`,
    `--disable-extensions-except=${extensionDir}`,
    "--remote-debugging-port=0",
    "--no-first-run",
    "--no-default-browser-check",
    "--no-sandbox",
    "about:blank",
  ],
  { env, stdio: ["ignore", "ignore", "pipe"] }
);
let browserErr = "";
browser.stderr.on("data", (d) => (browserErr += d));

async function devtoolsUrl() {
  const file = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 200; i++) {
    if (fs.existsSync(file)) {
      const [port, p] = fs.readFileSync(file, "utf8").split("\n");
      if (p) return `ws://127.0.0.1:${port}${p}`;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("Chromium did not start:\n" + browserErr);
}

const ws = new WebSocket(await devtoolsUrl());
await new Promise((r, j) => ((ws.onopen = r), (ws.onerror = j)));
let seq = 0;
const waiting = new Map();
const events = [];
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiting.has(msg.id)) {
    const { resolve, reject } = waiting.get(msg.id);
    waiting.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  } else if (msg.method) events.push(msg);
};
const cdp = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = ++seq;
    waiting.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });

let exitCode = 0;
try {
  // The extension's worker attaches the proxy when it starts.
  let worker;
  for (let i = 0; i < 100 && !worker; i++) {
    const { targetInfos } = await cdp("Target.getTargets");
    worker = targetInfos.find((t) => t.type === "service_worker" && t.url.includes(extensionId));
    if (!worker) await new Promise((r) => setTimeout(r, 100));
  }
  check(worker, "the extension's service worker runs");
  await new Promise((r) => setTimeout(r, 500));

  const { targetId } = await cdp("Target.createTarget", { url: origin });
  const { sessionId } = await cdp("Target.attachToTarget", { targetId, flatten: true });
  await cdp("Page.enable", {}, sessionId);
  await new Promise((r) => setTimeout(r, 500));
  const run = async (expression) => {
    const { result, exceptionDetails } = await cdp(
      "Runtime.evaluate",
      { expression, awaitPromise: true, returnByValue: true, userGesture: true },
      sessionId
    );
    if (exceptionDetails) throw new Error(expression + ": " + (exceptionDetails.exception?.description || exceptionDetails.text));
    return result.value;
  };

  check((await run("uvpaa()")) === true, "isUserVerifyingPlatformAuthenticatorAvailable() is answered (true)");

  // Registration.
  const reg = await run('register("alice")');
  check(reg.cls === "PublicKeyCredential", "create() resolves with a PublicKeyCredential");
  const cdj = JSON.parse(b64u(reg.json.response.clientDataJSON));
  check(cdj.type === "webauthn.create" && cdj.origin === origin && cdj.challenge === reg.challenge,
    "registration clientDataJSON has type, origin and challenge of the page");
  check(reg.rk === true, "credProps.rk = true");
  const file = path.join(store, "www", "localhost", "passkey.age");
  check(fs.existsSync(file), "the passkey is stored as www/localhost/passkey.age");
  check(decrypts().length === 0, "registration decrypted nothing");
  const plaintext = execFileSync(age, ["-d", "-i", identity, file]);
  check(plaintext.length > 0, "the stored passkey decrypts with the passage identity");
  const publicKey = createPublicKey({ key: b64u(reg.json.response.publicKey), format: "der", type: "spki" });

  // Sign-ins: one decrypt each, signature valid.
  for (let n = 1; n <= 2; n++) {
    const got = await run(`signIn([${JSON.stringify(reg.json.id)}])`);
    check(got.cls === "PublicKeyCredential" && got.json.id === reg.json.id, `sign-in ${n}: get() returns the registered credential`);
    const gcdj = JSON.parse(b64u(got.json.response.clientDataJSON));
    check(gcdj.type === "webauthn.get" && gcdj.origin === origin && gcdj.challenge === got.challenge,
      `sign-in ${n}: clientDataJSON has type, origin and challenge of the page`);
    const authData = b64u(got.json.response.authenticatorData);
    check(authData.subarray(0, 32).equals(createHash("sha256").update("localhost").digest()), `sign-in ${n}: rpIdHash of localhost`);
    check((authData[32] & 0x05) === 0x05, `sign-in ${n}: user present and verified`);
    const signed = Buffer.concat([authData, createHash("sha256").update(b64u(got.json.response.clientDataJSON)).digest()]);
    check(verify("sha256", signed, publicKey, b64u(got.json.response.signature)), `sign-in ${n}: signature verifies with the registered key`);
    check(b64u(got.json.response.userHandle).toString() === "alice", `sign-in ${n}: userHandle`);
    const d = decrypts();
    check(d.length === n, `sign-in ${n}: exactly ${n} decrypt(s) so far (${d.length})`);
    check(d[n - 1] === "-d www/localhost/passkey", `sign-in ${n}: PASSLESS_AGE_TARGET names the entry ("${d[n - 1]}")`);
  }

  // Discoverable sign-in (no allowList): still one decrypt.
  const disc = await run("signIn([])");
  check(disc.json.id === reg.json.id, "discoverable sign-in returns the passkey");
  check(decrypts().length === 3, "discoverable sign-in: one decrypt");

  // A page on another site cannot use it: RP ID checks are the browser's and the host's.
  const foreign = await run(
    'navigator.credentials.get({ publicKey: { rpId: "example.com", challenge: new Uint8Array(32), timeout: 5000 } }).then(() => "resolved", (e) => e.name)'
  );
  check(foreign === "SecurityError", `foreign rpId rejected (${foreign})`);
} catch (e) {
  console.error(e.message);
  exitCode = 1;
} finally {
  ws.close();
  browser.kill();
  server.close();
  if (fs.existsSync(hostLog)) {
    const log = fs.readFileSync(hostLog, "utf8");
    const lines = log.split("\n").filter((l) => /browser_host|Create|Get|Refusing|ERROR|WARN/.test(l));
    console.log("--- host log (excerpt) ---\n" + lines.slice(-25).join("\n"));
  }
  if (exitCode && browserErr) console.log("--- chromium stderr (tail) ---\n" + browserErr.split("\n").slice(-20).join("\n"));
  if (!process.env.KEEP) fs.rmSync(scratch, { recursive: true, force: true });
  else console.log("scratch kept: " + scratch);
  console.log(exitCode ? "E2E FAILED" : "E2E PASSED");
  process.exit(exitCode);
}
