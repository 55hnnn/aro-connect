// 아로 브라우저 넘겨받기 화면(Telegram 미니 앱).
// 아로 PC의 Edge 화면을 받아 그리고, 누르기와 글자 입력을 PC로 보낸다.
// 길은 Cloudflare 임시 터널이지만, 오가는 메시지는 이 화면과 PC가 나눈 열쇠로 암호화되어 터널은 내용을 볼 수 없다.
// 짝이 맞아야 하는 쪽: src/secretary/browser/takeover.py (X25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA256)
"use strict";

const PROTOCOL = "aro-takeover/v1";
const INFO = "aro-takeover/v1 aes-256-gcm";
const AAD = "aro-takeover/v1";
const FROM_PHONE = 1;
const FROM_PC = 2;
const KIND_JSON = 0x10;
const KIND_FRAME = 0x20;
const HOST = /^[a-z0-9-]{1,63}\.trycloudflare\.com$/;
const TAP_SLOP = 10;
const encoder = new TextEncoder();

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

async function helloMac(secret, sessionId, phonePublicText) {
  const key = await globalThis.crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const message = encoder.encode(`${PROTOCOL}|${sessionId}|${phonePublicText}`);
  return new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, message));
}

// 이 화면의 일회용 키를 만들고, PC 공개 키와 나눈 비밀로 AES-GCM 열쇠를 뽑는다.
async function makeKeys(pcPublicText) {
  const subtle = globalThis.crypto.subtle;
  const pcPublic = b64urlToBytes(pcPublicText);
  if (pcPublic.length !== 32) throw new Error("PC 키의 길이가 맞지 않아요.");
  const pcKey = await subtle.importKey("raw", pcPublic, { name: "X25519" }, false, []);
  const pair = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const phonePublic = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const shared = await subtle.deriveBits({ name: "X25519", public: pcKey }, pair.privateKey, 256);
  const base = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const salt = new Uint8Array(64);
  salt.set(pcPublic, 0);
  salt.set(phonePublic, 32);
  const aesKey = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(INFO) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return { phonePublic, phonePublicText: bytesToB64url(phonePublic), aesKey };
}

// 메시지 잠그기. 논스 = 방향(1바이트) + 0 세 바이트 + 순서 번호(8바이트). 받는 쪽은 순서가 하나씩만 늘어야 받는다.
class Channel {
  constructor(aesKey) {
    this.key = aesKey;
    this.sent = 0;
    this.received = 0;
  }

  async seal(plaintext) {
    this.sent += 1;
    const nonce = new Uint8Array(12);
    nonce[0] = FROM_PHONE;
    new DataView(nonce.buffer).setBigUint64(4, BigInt(this.sent));
    const cipher = new Uint8Array(
      await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: encoder.encode(AAD) }, this.key, plaintext),
    );
    const out = new Uint8Array(12 + cipher.length);
    out.set(nonce, 0);
    out.set(cipher, 12);
    return out;
  }

  async open(data) {
    const bytes = new Uint8Array(data);
    if (bytes.length < 28) throw new Error("메시지가 짧아요.");
    const nonce = bytes.slice(0, 12);
    const counter = Number(new DataView(nonce.buffer).getBigUint64(4));
    if (nonce[0] !== FROM_PC || nonce[1] || nonce[2] || nonce[3] || counter !== this.received + 1) {
      throw new Error("메시지 순서가 맞지 않아요.");
    }
    const plain = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(AAD) },
      this.key,
      bytes.slice(12),
    );
    this.received = counter;
    return new Uint8Array(plain);
  }
}

// 휴대폰에서 보내는 메시지는 PAD 바이트 단위로 공백을 채운다. 암호문 길이로 입력한 글자 수(비밀번호 길이 등)를 짐작하지 못하게 한다.
const PAD = 512;

function jsonMessage(payload) {
  const body = encoder.encode(JSON.stringify(payload));
  const size = Math.ceil((1 + body.length) / PAD) * PAD;
  const out = new Uint8Array(size).fill(0x20);
  out[0] = KIND_JSON;
  out.set(body, 1);
  return out;
}

function readParams(search, hash) {
  const params = new URLSearchParams(search);
  const host = params.get("h") || "";
  const sessionId = params.get("s") || "";
  const pcPublic = params.get("k") || "";
  const secret = params.get("t") || "";
  if (!HOST.test(host) || !/^[A-Za-z0-9_-]{16,64}$/.test(sessionId) || !/^[A-Za-z0-9_-]{43}$/.test(pcPublic) || !/^[A-Za-z0-9_-]{43}$/.test(secret)) {
    return null;
  }
  const initData = new URLSearchParams((hash || "").replace(/^#/, "")).get("tgWebAppData") || "";
  if (!initData) return null;
  return { host, sessionId, pcPublic, secret: b64urlToBytes(secret), reason: (params.get("r") || "").slice(0, 80), initData };
}

// Telegram 앱과 통신한다(공식 미니 앱 스크립트가 하는 일 중 필요한 부분만, connect.js와 같다).
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

function start() {
  const status = document.getElementById("status");
  const problem = document.getElementById("problem");
  const canvas = document.getElementById("screen");
  const controls = document.getElementById("controls");
  const spec = readParams(window.location.search, window.location.hash);
  const fail = (text) => {
    problem.textContent = text;
    problem.hidden = false;
    status.textContent = "연결이 끊겼어요";
  };
  if (!spec) {
    fail("이 화면은 Telegram에서 아로가 보낸 [브라우저 열기] 버튼으로 열어 주세요.");
    return;
  }
  postEvent("web_app_ready", {});
  postEvent("web_app_expand", {});
  if (spec.reason) document.getElementById("reason").textContent = spec.reason;

  let channel = null;
  let sending = Promise.resolve();
  let receiving = Promise.resolve();
  let ws = null;
  const context = canvas.getContext("2d");

  const send = (payload) => {
    if (!channel || !ws || ws.readyState !== WebSocket.OPEN) return;
    // 보낸 순서와 순서 번호가 어긋나지 않게 하나씩 잠가 보낸다.
    sending = sending.then(async () => ws.send(await channel.seal(jsonMessage(payload)))).catch(() => {});
  };

  const handle = async (data) => {
    const plain = await channel.open(data);
    if (plain[0] === KIND_FRAME && plain.length > 5) {
      const view = new DataView(plain.buffer, plain.byteOffset);
      const width = view.getUint16(1);
      const height = view.getUint16(3);
      const bitmap = await createImageBitmap(new Blob([plain.slice(5)], { type: "image/jpeg" }));
      if (canvas.width !== bitmap.width || canvas.height !== bitmap.height) {
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
      }
      canvas.dataset.cssWidth = String(width);
      canvas.dataset.cssHeight = String(height);
      context.drawImage(bitmap, 0, 0);
      bitmap.close();
      return;
    }
    if (plain[0] === KIND_JSON) {
      const message = JSON.parse(new TextDecoder().decode(plain.slice(1)));
      if (message.type === "ready") {
        status.textContent = "연결됨. 화면을 눌러 조작하고, 끝나면 '다 했어요'를 눌러 주세요.";
        canvas.hidden = false;
        controls.hidden = false;
      } else if (message.type === "note") {
        status.textContent = String(message.text || "").slice(0, 120);
      } else if (message.type === "bye") {
        status.textContent = "넘겨받기가 끝났어요. 아로가 이어서 해요.";
        controls.hidden = true;
        setTimeout(() => postEvent("web_app_close", {}), 1500);
      }
    }
  };

  // 이번 넘겨받기의 터널 주소 하나로만 연결을 좁힌다(콘텐츠 보안 정책은 겹쳐서 모두 적용된다).
  const pin = document.createElement("meta");
  pin.httpEquiv = "Content-Security-Policy";
  pin.content = `connect-src wss://${spec.host}`;
  document.head.appendChild(pin);

  (async () => {
    const keys = await makeKeys(spec.pcPublic);
    const mac = await helloMac(spec.secret, spec.sessionId, keys.phonePublicText);
    ws = new WebSocket(`wss://${spec.host}/ws`);
    ws.binaryType = "arraybuffer";
    ws.onopen = async () => {
      ws.send(JSON.stringify({ v: 1, s: spec.sessionId, p: keys.phonePublicText, m: bytesToB64url(mac) }));
      channel = new Channel(keys.aesKey);
      sending = sending.then(async () => ws.send(await channel.seal(jsonMessage({ type: "auth", initData: spec.initData }))));
    };
    ws.onmessage = (event) => {
      if (!(event.data instanceof ArrayBuffer) || !channel) return;
      receiving = receiving.then(() => handle(event.data)).catch(() => {
        fail("화면을 받지 못했어요. 창을 닫고 아로에게 다시 부탁해 주세요.");
        ws.close();
      });
    };
    ws.onclose = () => {
      if (problem.hidden && !/아로가 이어서/.test(status.textContent)) status.textContent = "연결이 끝났어요.";
      controls.hidden = true;
    };
  })().catch(() => fail("연결하지 못했어요. 잠시 뒤 아로에게 다시 부탁해 주세요."));

  // 누르기와 밀기: 짧게 누르면 그 자리를 누르고, 위아래로 밀면 화면을 굴린다.
  let touch = null;
  canvas.addEventListener("pointerdown", (event) => {
    touch = { x: event.clientX, y: event.clientY, time: event.timeStamp };
    event.preventDefault();
  });
  canvas.addEventListener("pointerup", (event) => {
    if (!touch) return;
    const rect = canvas.getBoundingClientRect();
    const dx = event.clientX - touch.x;
    const dy = event.clientY - touch.y;
    if (Math.abs(dx) < TAP_SLOP && Math.abs(dy) < TAP_SLOP) {
      const x = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
      const y = Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height));
      send({ type: "tap", x, y });
    } else if (Math.abs(dy) >= Math.abs(dx)) {
      const cssHeight = Number(canvas.dataset.cssHeight || 780);
      const amount = Math.max(-3000, Math.min(3000, (-dy * cssHeight) / rect.height));
      send({ type: "scroll", dy: amount });
    }
    touch = null;
    event.preventDefault();
  });

  const input = document.getElementById("text");
  document.getElementById("typing").addEventListener("submit", (event) => {
    event.preventDefault();
    const value = input.value;
    if (value) send({ type: "text", value: value.slice(0, 300) });
    input.value = "";
  });
  document.getElementById("backspace").addEventListener("click", () => send({ type: "key", key: "Backspace" }));
  document.getElementById("enter").addEventListener("click", () => send({ type: "key", key: "Enter" }));
  document.getElementById("done").addEventListener("click", () => {
    send({ type: "done" });
    status.textContent = "아로에게 넘겼어요. 이어서 진행할게요.";
    sending.then(() => setTimeout(() => postEvent("web_app_close", {}), 800));
  });
}

if (typeof module === "object" && module.exports) {
  module.exports = { makeKeys, helloMac, Channel, jsonMessage, readParams, b64urlToBytes, bytesToB64url, PROTOCOL };
} else {
  start();
}
