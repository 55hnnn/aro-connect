// 아로 계정 연결 화면(Telegram 미니 앱).
// 입력한 값을 이 휴대폰에서 비서 PC의 공개 키로 암호화해 Telegram을 거쳐 봇으로 보낸다.
// 바깥 스크립트를 쓰지 않고, 콘텐츠 보안 정책(connect-src 'none')으로 네트워크 요청도 막는다.
// 암호화 방식은 src/secretary/connect_box.py와 짝이 맞아야 한다(X25519, HKDF-SHA256, AES-256-GCM).
"use strict";

const INFO = "aro-connect/v1 aes-256-gcm";
const AAD = "aro-connect/v1";
const MAX_DATA = 4096;
const KINDS = new Set(["text", "email", "password"]);

function b64urlToBytes(text) {
  let s = text.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const binary = atob(s);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function bytesToB64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function seal(publicKeyText, payload) {
  const subtle = globalThis.crypto.subtle;
  const recipient = b64urlToBytes(publicKeyText);
  if (recipient.length !== 32) throw new Error("PC 키의 길이가 맞지 않아요.");
  const recipientKey = await subtle.importKey("raw", recipient, { name: "X25519" }, false, []);
  const ephemeral = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephemeralPublic = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
  const shared = await subtle.deriveBits({ name: "X25519", public: recipientKey }, ephemeral.privateKey, 256);
  const base = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const salt = new Uint8Array(64);
  salt.set(ephemeralPublic, 0);
  salt.set(recipient, 32);
  const encoder = new TextEncoder();
  const key = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(INFO) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const body = encoder.encode(JSON.stringify(payload));
  const cipher = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(AAD) }, key, body),
  );
  return ["v1", bytesToB64url(ephemeralPublic), bytesToB64url(iv), bytesToB64url(cipher)].join(".");
}

function readSpec(params) {
  const service = params.get("s") || "";
  const ticket = params.get("t") || "";
  const publicKey = params.get("k") || "";
  if (!/^[a-z][a-z0-9_]{1,31}$/.test(service) || !/^[A-Za-z0-9_-]{16,64}$/.test(ticket) || !/^[A-Za-z0-9_-]{43}$/.test(publicKey)) {
    return null;
  }
  let spec;
  try {
    spec = JSON.parse(new TextDecoder().decode(b64urlToBytes(params.get("f") || "")));
  } catch (error) {
    return null;
  }
  if (!spec || typeof spec.title !== "string" || spec.title.length > 60 || !Array.isArray(spec.fields)) return null;
  if (spec.fields.length < 1 || spec.fields.length > 4) return null;
  for (const field of spec.fields) {
    if (!Array.isArray(field) || field.length !== 3) return null;
    const [name, label, kind] = field;
    if (!/^[A-Z][A-Z0-9_]{1,63}$/.test(name) || typeof label !== "string" || label.length > 40 || !KINDS.has(kind)) return null;
  }
  const note = typeof spec.note === "string" ? spec.note.slice(0, 200) : "";
  return { service, ticket, publicKey, title: spec.title, fields: spec.fields, note };
}

// Telegram 앱과 통신한다(공식 미니 앱 스크립트가 하는 일 중 필요한 부분만).
function postEvent(eventType, eventData) {
  const data = JSON.stringify(eventData || {});
  if (window.TelegramWebviewProxy !== undefined) {
    window.TelegramWebviewProxy.postEvent(eventType, data);
    return true;
  }
  if (window.external && "notify" in window.external) {
    window.external.notify(JSON.stringify({ eventType, eventData }));
    return true;
  }
  if (window.parent !== window) {
    window.parent.postMessage(JSON.stringify({ eventType, eventData }), "https://web.telegram.org");
    return true;
  }
  return false;
}

function cleanValue(kind, value) {
  const trimmed = value.trim();
  return kind === "password" ? trimmed.replace(/\s+/g, "") : trimmed;
}

function start() {
  const form = document.getElementById("form");
  const problem = document.getElementById("problem");
  const error = document.getElementById("error");
  const button = document.getElementById("send");
  const spec = readSpec(new URLSearchParams(window.location.search));
  if (!spec) {
    problem.textContent = "이 화면은 Telegram에서 아로가 보낸 [입력 화면 열기] 버튼으로 열어 주세요.";
    problem.hidden = false;
    return;
  }
  postEvent("web_app_ready", {});
  postEvent("web_app_expand", {});
  document.getElementById("title").textContent = `${spec.title} 연결`;
  document.getElementById("note").textContent = spec.note;
  const holder = document.getElementById("fields");
  const inputs = [];
  spec.fields.forEach(([name, label, kind], index) => {
    const id = `field${index}`;
    const caption = document.createElement("label");
    caption.htmlFor = id;
    caption.textContent = label;
    const input = document.createElement("input");
    input.id = id;
    input.type = kind;
    input.autocomplete = "off";
    input.autocapitalize = "off";
    input.spellcheck = false;
    input.maxLength = 512;
    holder.append(caption, input);
    inputs.push({ name, label, kind, input });
  });
  form.hidden = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    const values = {};
    for (const { name, label, kind, input } of inputs) {
      const value = cleanValue(kind, input.value);
      if (!value) {
        error.textContent = `${label} 칸이 비어 있어요.`;
        error.hidden = false;
        input.focus();
        return;
      }
      values[name] = value;
    }
    button.disabled = true;
    try {
      const data = await seal(spec.publicKey, { s: spec.service, t: spec.ticket, v: values });
      if (data.length > MAX_DATA) throw new Error("입력이 너무 길어요.");
      if (!postEvent("web_app_data_send", { data })) throw new Error("Telegram 안에서 열어야 보낼 수 있어요.");
      for (const { input } of inputs) input.value = "";
    } catch (failure) {
      error.textContent = failure instanceof Error ? failure.message : "보내지 못했어요.";
      error.hidden = false;
      button.disabled = false;
    }
  });
}

if (typeof module === "object" && module.exports) {
  module.exports = { seal, readSpec, b64urlToBytes, bytesToB64url };
} else {
  start();
}
