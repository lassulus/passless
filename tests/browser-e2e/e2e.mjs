// End-to-end: a real Firefox (headless, driven by geckodriver) with the passless extension
// installed as a temporary add-on registers and signs in on a local WebAuthn page; the native
// messaging host is the passless binary on a passage store with a plain age identity.
// No npm dependencies: WebDriver over Node's fetch.
//
// Usage: node e2e.mjs <passless> <firefox> <geckodriver> <age>
// Environment: KEEP=1 keeps the scratch directory.

import { execFileSync, spawn } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { createServer } from "node:http";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const [passless, firefox, geckodriver, age] = process.argv.slice(2).map((p) => p && path.resolve(p));
if (!passless || !firefox || !geckodriver || !age) {
  console.error("usage: node e2e.mjs <passless> <firefox> <geckodriver> <age>");
  process.exit(2);
}
const here = path.dirname(fileURLToPath(import.meta.url));
const extensionDir = path.resolve(here, "../../cmd/passless/assets/firefox-extension");
const extensionId = JSON.parse(fs.readFileSync(path.join(extensionDir, "manifest.json"))).browser_specific_settings.gecko.id;

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "passless-firefox-e2e-"));
const store = path.join(scratch, "store");
const ageLog = path.join(scratch, "age.log");
const hostLog = path.join(scratch, "host.log");

function check(condition, message) {
  if (!condition) throw new Error("FAILED: " + message);
  console.log("ok   " + message);
}
const b64u = (s) => Buffer.from(s, "base64url");
const decrypts = () =>
  fs.existsSync(ageLog) ? fs.readFileSync(ageLog, "utf8").split("\n").filter((l) => l.startsWith("-d ")) : [];
const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

// ---- passage store with a plain age identity; `age` wrapped to log every run -------------------
fs.mkdirSync(store, { recursive: true });
const keygen = path.join(path.dirname(age), "age-keygen");
const identity = path.join(scratch, "identity.txt");
execFileSync(keygen, ["-o", identity], { stdio: "ignore" });
fs.writeFileSync(path.join(store, ".age-recipients"), execFileSync(keygen, ["-y", identity]));
const ageWrapper = path.join(scratch, "age");
fs.writeFileSync(
  ageWrapper,
  `#!/bin/sh\nprintf '%s %s\\n' "$1" "$PASSLESS_AGE_TARGET" >> '${ageLog}'\nexec '${age}' "$@"\n`,
  { mode: 0o755 }
);

// ---- native messaging host: the passless binary, started by Firefox ----------------------------
// The wrapper only captures the host's stderr; Firefox's arguments pass through.
const hostWrapper = path.join(scratch, "passless-host");
fs.writeFileSync(hostWrapper, `#!/bin/sh\nexec '${passless}' "$@" 2>> '${hostLog}'\n`, { mode: 0o755 });
const hostDir = path.join(scratch, ".mozilla", "native-messaging-hosts");
fs.mkdirSync(hostDir, { recursive: true });
fs.writeFileSync(
  path.join(hostDir, "rs.passless.browser.json"),
  JSON.stringify({
    name: "rs.passless.browser",
    description: "passless",
    path: hostWrapper,
    type: "stdio",
    allowed_extensions: [extensionId],
  })
);

// ---- the relying party: a local page, plus a frame from another origin -------------------------
const page = `<!doctype html><title>rp</title><script>
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const rnd = () => crypto.getRandomValues(new Uint8Array(32));
window.register = async (name) => {
  const challenge = rnd();
  const c = await navigator.credentials.create({ publicKey: {
    rp: { name: "e2e" }, user: { id: new TextEncoder().encode(name), name, displayName: name },
    challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
    timeout: 30000, extensions: { credProps: true } } });
  return { json: c.toJSON(), challenge: b64u(challenge), pkc: c instanceof PublicKeyCredential,
           attestation: c.response instanceof AuthenticatorAttestationResponse,
           rawIdMatches: b64u(c.rawId) === c.id, alg: c.response.getPublicKeyAlgorithm(),
           rk: c.getClientExtensionResults().credProps?.rk };
};
window.signIn = async (ids) => {
  const challenge = rnd();
  const a = await navigator.credentials.get({ publicKey: { challenge, timeout: 30000,
    allowCredentials: ids.map((id) => ({ type: "public-key", id: fromB64u(id) })),
    userVerification: "preferred" } });
  return { json: a.toJSON(), challenge: b64u(challenge), pkc: a instanceof PublicKeyCredential,
           assertion: a.response instanceof AuthenticatorAssertionResponse,
           userHandle: new TextDecoder().decode(a.response.userHandle) };
};
window.outcome = (p) => p.then(() => "resolved", (e) => e.name);
</script>`;
const server = createServer((req, res) => {
  res.setHeader("content-type", "text/html");
  res.end(page);
}).listen(0, "127.0.0.1");
await new Promise((r) => server.once("listening", r));
const port = server.address().port;
const origin = `http://localhost:${port}`;
const otherOrigin = `http://other.localhost:${port}`;

// ---- Firefox through geckodriver ----------------------------------------------------------------
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
const driverPort = await freePort();
const driver = spawn(geckodriver, ["--port", String(driverPort), "--binary", firefox], {
  env,
  stdio: ["ignore", "pipe", "pipe"],
});
let driverLog = "";
driver.stdout.on("data", (d) => (driverLog += d));
driver.stderr.on("data", (d) => (driverLog += d));

const base = `http://127.0.0.1:${driverPort}`;
async function wd(method, url, body) {
  const res = await fetch(base + url, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`${method} ${url}: ${JSON.stringify(json.value)}`);
  return json.value;
}
for (let i = 0; i < 100; i++) {
  try {
    await fetch(base + "/status");
    break;
  } catch {
    await new Promise((r) => setTimeout(r, 100));
  }
}

let session;
let exitCode = 0;
try {
  session = await wd("POST", "/session", {
    capabilities: {
      alwaysMatch: {
        browserName: "firefox",
        "moz:firefoxOptions": {
          args: ["-headless"],
          prefs: { "browser.shell.checkDefaultBrowser": false },
        },
      },
    },
  });
  const sid = session.sessionId;
  check(session.capabilities.browserName === "firefox", `Firefox ${session.capabilities.browserVersion} started headless`);
  const id = await wd("POST", `/session/${sid}/moz/addon/install`, { path: extensionDir, temporary: true });
  check(id === extensionId, `the extension is installed (${id})`);

  await wd("POST", `/session/${sid}/url`, { url: origin });
  const run = (expression) =>
    wd("POST", `/session/${sid}/execute/async`, {
      script: `const done = arguments[arguments.length - 1];
               Promise.resolve().then(() => ${expression}).then(done, (e) => done({ error: e.name + ": " + e.message }));`,
      args: [],
    }).then((value) => {
      if (value && value.error) throw new Error(expression + ": " + value.error);
      return value;
    });

  check((await run("PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()")) === true,
    "isUserVerifyingPlatformAuthenticatorAvailable() is true");

  // Registration.
  const reg = await run('register("alice")');
  check(reg.pkc && reg.attestation, "create() resolves with a PublicKeyCredential / AuthenticatorAttestationResponse");
  check(reg.rawIdMatches && reg.alg === -7, "rawId matches id, getPublicKeyAlgorithm() = -7");
  const cdj = JSON.parse(b64u(reg.json.response.clientDataJSON));
  check(cdj.type === "webauthn.create" && cdj.origin === origin && cdj.challenge === reg.challenge,
    "registration clientDataJSON has type, origin and challenge of the page");
  check(reg.rk === true, "credProps.rk = true");
  const file = path.join(store, "www", "localhost", "passkey.age");
  check(fs.existsSync(file), "the passkey is stored as www/localhost/passkey.age");
  check(decrypts().length === 0, "registration decrypted nothing");
  check(execFileSync(age, ["-d", "-i", identity, file]).length > 0, "the stored passkey decrypts with the passage identity");
  const publicKey = createPublicKey({ key: b64u(reg.json.response.publicKey), format: "der", type: "spki" });

  // Sign-ins: one decrypt each, signature valid.
  for (let n = 1; n <= 2; n++) {
    const got = await run(`signIn([${JSON.stringify(reg.json.id)}])`);
    check(got.pkc && got.assertion && got.json.id === reg.json.id, `sign-in ${n}: get() returns the registered credential`);
    const gcdj = JSON.parse(b64u(got.json.response.clientDataJSON));
    check(gcdj.type === "webauthn.get" && gcdj.origin === origin && gcdj.challenge === got.challenge,
      `sign-in ${n}: clientDataJSON has type, origin and challenge of the page`);
    const authData = b64u(got.json.response.authenticatorData);
    check(authData.subarray(0, 32).equals(createHash("sha256").update("localhost").digest()), `sign-in ${n}: rpIdHash of localhost`);
    check((authData[32] & 0x05) === 0x05, `sign-in ${n}: user present and verified`);
    const signed = Buffer.concat([authData, createHash("sha256").update(b64u(got.json.response.clientDataJSON)).digest()]);
    check(verify("sha256", signed, publicKey, b64u(got.json.response.signature)), `sign-in ${n}: signature verifies with the registered key`);
    check(got.userHandle === "alice", `sign-in ${n}: userHandle`);
    const d = decrypts();
    check(d.length === n, `sign-in ${n}: exactly ${n} decrypt(s) so far (${d.length})`);
    check(d[n - 1] === "-d www/localhost/passkey", `sign-in ${n}: PASSLESS_AGE_TARGET names the entry ("${d[n - 1]}")`);
  }

  const disc = await run("signIn([])");
  check(disc.json.id === reg.json.id, "discoverable sign-in (no allowCredentials) returns the passkey");
  check(decrypts().length === 3, "discoverable sign-in: one decrypt");

  // The page cannot claim another site.
  const foreign = await run(
    'outcome(navigator.credentials.get({ publicKey: { rpId: "example.com", challenge: new Uint8Array(32) } }))'
  );
  check(foreign === "SecurityError", `foreign rpId rejected (${foreign})`);
  check(decrypts().length === 3, "the refused request decrypted nothing");

  // Aborting a request rejects it with AbortError (and kills an age run already started).
  const aborted = await run(
    "(() => { const c = new AbortController(); const p = navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32) }, signal: c.signal }); c.abort(); return outcome(p); })()"
  );
  check(aborted === "AbortError", `abort rejects with AbortError (${aborted})`);

  // A frame from another origin is refused, whatever it claims.
  await run(`new Promise((resolve) => { const f = document.createElement("iframe"); f.src = ${JSON.stringify(otherOrigin)}; f.onload = resolve; document.body.append(f); })`);
  const frame = await wd("POST", `/session/${sid}/execute/sync`, { script: "return document.querySelector('iframe')", args: [] });
  const beforeFrame = decrypts().length;
  await wd("POST", `/session/${sid}/frame`, { id: frame });
  const framed = await run(`outcome(navigator.credentials.get({ publicKey: { rpId: "other.localhost", challenge: new Uint8Array(32) } }))`);
  check(framed === "NotAllowedError", `cross-origin frame refused (${framed})`);
  await wd("POST", `/session/${sid}/frame/parent`, {});
  check(decrypts().length === beforeFrame, "the cross-origin frame decrypted nothing");
} catch (e) {
  console.error(e.message);
  exitCode = 1;
} finally {
  if (session) await wd("DELETE", `/session/${session.sessionId}`).catch(() => {});
  driver.kill();
  server.close();
  if (fs.existsSync(hostLog)) {
    const lines = fs.readFileSync(hostLog, "utf8").split("\n").filter((l) => /browser_host|ERROR|WARN/.test(l));
    console.log("--- host log (excerpt) ---\n" + lines.slice(-25).join("\n"));
  }
  if (exitCode) console.log("--- geckodriver (tail) ---\n" + driverLog.split("\n").slice(-30).join("\n"));
  if (!process.env.KEEP) fs.rmSync(scratch, { recursive: true, force: true });
  else console.log("scratch kept: " + scratch);
  console.log(exitCode ? "E2E FAILED" : "E2E PASSED");
  process.exit(exitCode);
}
