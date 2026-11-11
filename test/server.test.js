// Starts server.js on a free port and checks who receives which event.
// Run: npm test
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { createHmac, randomUUID } = require("node:crypto");
const path = require("node:path");
const { io } = require("socket.io-client");

const SECRET = "test-secret-that-is-at-least-32-characters-long";
const ORIGIN = "http://localhost:3001";
const PORT = 3900 + Math.floor(Math.random() * 90);
const URL = `http://127.0.0.1:${PORT}`;
const A = "a".repeat(24);
const B = "b".repeat(24);
const C = "c".repeat(24);
let child;
const opened = [];

function token(userId, secret = SECRET) {
  const exp = Math.floor(Date.now() / 1000) + 300;
  const sig = createHmac("sha256", secret).update(`socket:${userId}.${exp}`).digest("base64url");
  return `${userId}.${exp}.${sig}`;
}

function connect(userId, { secret, register = true } = {}) {
  return new Promise((resolve, reject) => {
    const socket = io(URL, {
      transports: ["websocket"],
      extraHeaders: { Origin: ORIGIN },
      auth: { token: token(userId, secret) },
      reconnection: false,
      forceNew: true,
    });
    opened.push(socket);
    socket.on("connect", () => {
      if (register) socket.emit("register-user");
      // register-user answers with the online list
      if (register) socket.once("active-users", () => resolve(socket));
      else resolve(socket);
    });
    socket.on("connect_error", reject);
  });
}

// resolves with the payload, or with the string "none" when nothing arrives in time
function next(socket, event, ms = 400) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.off(event, on);
      resolve("none");
    }, ms);
    const on = (payload) => {
      clearTimeout(timer);
      resolve(payload);
    };
    socket.once(event, on);
  });
}

before(async () => {
  child = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    env: { ...process.env, PORT: String(PORT), AUTH_SECRET: SECRET, CORS_ORIGINS: ORIGIN, NODE_ENV: "production" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  await new Promise((resolve) => child.stdout.on("data", (d) => String(d).includes("running") && resolve()));
});

after(() => {
  for (const s of opened) s.disconnect();
  child?.kill("SIGTERM");
});

test("a wrong ticket is refused", async () => {
  await assert.rejects(connect(A, { secret: "x".repeat(40) }), /unauthorized/);
});

test("a direct message reaches the receiver and the sender's other tab only, as ids", async () => {
  const a1 = await connect(A);
  const a2 = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const got = Promise.all([next(a1, "private-message"), next(a2, "private-message"), next(b, "private-message"), next(c, "private-message")]);
  a1.emit("private-message", JSON.stringify({ sender_id: A, receiver_id: B, is_group: 0, message: "secret text" }));
  const [toSendingTab, toOtherTab, toReceiver, toStranger] = await got;
  assert.equal(toSendingTab, "none");
  assert.deepEqual(toOtherTab, { sender_id: A, receiver_id: B, is_group: 0 });
  assert.deepEqual(toReceiver, { sender_id: A, receiver_id: B, is_group: 0 });
  assert.equal(toStranger, "none");
  [a1, a2, b, c].forEach((s) => s.disconnect());
});

test("a message claiming another sender is ignored", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const got = next(b, "private-message");
  a.emit("private-message", JSON.stringify({ sender_id: C, receiver_id: B, is_group: 0 }));
  assert.equal(await got, "none");
  [a, b].forEach((s) => s.disconnect());
});

test("a group message goes to the listed members only", async () => {
  const group = "d".repeat(24);
  const a = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const got = Promise.all([next(b, "private-message"), next(c, "private-message")]);
  a.emit("private-message", JSON.stringify({ sender_id: A, receiver_id: group, is_group: 1, recipient_ids: [B] }));
  const [toMember, toOutsider] = await got;
  assert.deepEqual(toMember, { sender_id: A, receiver_id: group, is_group: 1 });
  assert.equal(toOutsider, "none");
  [a, b, c].forEach((s) => s.disconnect());
});

test("a deleted message's text never travels", async () => {
  const id = "e".repeat(24);
  const a = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const got = Promise.all([next(b, "message-deleted"), next(c, "message-deleted")]);
  a.emit("message-deleted", JSON.stringify({ _id: id, sender: { _id: A, name: "A" }, receiver: { _id: B }, message: { message: "secret" } }));
  const [toReceiver, toStranger] = await got;
  assert.deepEqual(toReceiver, { _id: id, sender: { _id: A }, receiver: { _id: B } });
  assert.equal(toStranger, "none");
  [a, b, c].forEach((s) => s.disconnect());
});

test("a group deletion reaches every selected member without message content", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const deletedId = "e".repeat(24);
  const messageId = "f".repeat(24);
  const deliveries = Promise.all([next(b, "message-deleted"), next(c, "message-deleted")]);
  a.emit("message-deleted", {
    _id: deletedId,
    message_id: messageId,
    sender: { _id: A },
    receiver: { _id: "d".repeat(24) },
    recipient_ids: [B],
    message: "must not be sent",
  });
  const [toMember, toOutsider] = await deliveries;
  assert.equal(toMember.message_id, messageId);
  assert.equal(toMember.message, undefined);
  assert.equal(toOutsider, "none");
  [a, b, c].forEach((socket) => socket.disconnect());
});

test("message reactions require a signed event and reach only listed recipients", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const event = {
    actor_id: A,
    message_id: "e".repeat(24),
    recipient_ids: [B],
    reactions: [{ user_id: A, emoji: "👍" }],
  };
  const unsigned = Promise.all([next(b, "message-reaction"), next(c, "message-reaction")]);
  a.emit("message-reaction", event);
  assert.deepEqual(await unsigned, ["none", "none"]);

  const signedEvent = { ...event, issuedAt: Date.now() };
  signedEvent.signature = createHmac("sha256", SECRET)
    .update(JSON.stringify({ event, issuedAt: signedEvent.issuedAt }))
    .digest("base64url");
  const received = Promise.all([next(b, "message-reaction"), next(c, "message-reaction")]);
  a.emit("message-reaction", signedEvent);
  const [toRecipient, toOutsider] = await received;
  assert.deepEqual(toRecipient, { message_id: event.message_id, reactions: event.reactions });
  assert.equal(toOutsider, "none");
  [a, b, c].forEach((socket) => socket.disconnect());
});

test("leaving a group is announced to its members only", async () => {
  const group = "d".repeat(24);
  const a = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const got = Promise.all([next(b, "leave-group"), next(c, "leave-group")]);
  a.emit("leave-group", JSON.stringify({ _id: group, user_id: A, message: "A left", groupMembers: [B] }));
  const [toMember, toOutsider] = await got;
  assert.equal(toMember.message, "A left");
  assert.equal(toOutsider, "none");
  [a, b, c].forEach((s) => s.disconnect());
});

test("typing status is routed only to the selected recipient", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const got = Promise.all([next(b, "typing-status"), next(c, "typing-status")]);
  a.emit("typing-status", {
    sender_id: A,
    sender_name: "A",
    receiver_id: B,
    is_group: false,
    typing: true,
  });
  const [toRecipient, toStranger] = await got;
  assert.deepEqual(toRecipient, {
    sender_id: A,
    sender_name: "A",
    receiver_id: B,
    is_group: false,
    typing: true,
  });
  assert.equal(toStranger, "none");
  [a, b, c].forEach((s) => s.disconnect());
});

test("seen receipts require a valid signature and reach only the message sender", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const messageId = "e".repeat(24);
  const event = {
    actor_id: B,
    actor_name: "B",
    actor_photo: "",
    message_ids: [messageId],
    recipient_ids: [A],
  };
  const invalid = Promise.all([next(a, "messages-seen"), next(c, "messages-seen")]);
  b.emit("messages-seen", event);
  assert.deepEqual(await invalid, ["none", "none"]);

  const signedEvent = { ...event, issuedAt: Date.now() };
  signedEvent.signature = createHmac("sha256", SECRET)
    .update(JSON.stringify({ event, issuedAt: signedEvent.issuedAt }))
    .digest("base64url");
  const deliveries = Promise.all([next(a, "messages-seen"), next(c, "messages-seen")]);
  b.emit("messages-seen", signedEvent);
  const [toSender, toStranger] = await deliveries;
  assert.deepEqual(toSender, {
    actor_id: B,
    actor_name: "B",
    actor_photo: "",
    message_ids: [messageId],
  });
  assert.equal(toStranger, "none");
  [a, b, c].forEach((s) => s.disconnect());
});

test("call: every tab rings, answering on one stops the other, hanging up ends it", async () => {
  const a = await connect(A);
  const b1 = await connect(B);
  const b2 = await connect(B);
  const callId = randomUUID();
  const rings = Promise.all([next(b1, "call:invite"), next(b2, "call:invite")]);
  a.emit("call:invite", { callId, recipients: [B], callerName: "A", isVideo: true });
  const [ring1, ring2] = await rings;
  assert.equal(ring1.callId, callId);
  assert.equal(ring2.callId, callId);

  const after = Promise.all([next(b2, "call:end"), next(a, "call:participant"), next(b1, "call:participant")]);
  b1.emit("call:accept", { callId, callerId: A });
  const [stopRinging, peerForA, peerForB] = await after;
  assert.equal(stopRinging.reason, "answered-elsewhere");
  assert.equal(peerForA.userId, B);
  assert.equal(peerForB.userId, A);

  // signalling goes to the answering tab only
  const signal = Promise.all([next(b1, "call:signal"), next(b2, "call:signal")]);
  a.emit("call:signal", { callId, to: B, signal: { description: { type: "offer", sdp: "x" } } });
  const [toCallTab, toOtherTab] = await signal;
  assert.equal(toCallTab.from, A);
  assert.equal(toOtherTab, "none");

  const ended = next(b1, "call:end");
  a.emit("call:end", { callId });
  assert.equal((await ended).callId, callId);
  [a, b1, b2].forEach((s) => s.disconnect());
});

test("call: a caller receives a busy result when every recipient is already ringing", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const c = await connect(C);
  const incoming = next(b, "call:invite");
  a.emit("call:invite", { callId: randomUUID(), recipients: [B], callerName: "A" });
  await incoming;

  const unavailable = next(c, "call:unavailable");
  c.emit("call:invite", { callId: randomUUID(), recipients: [B], callerName: "C" });
  assert.equal((await unavailable).reason, "busy");
  [a, b, c].forEach((socket) => socket.disconnect());
});

test("call: hanging up before an answer stops the ringing", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const callId = randomUUID();
  const ring = next(b, "call:invite");
  a.emit("call:invite", { callId, recipients: [B], callerName: "A" });
  await ring;
  const stop = next(b, "call:end");
  a.emit("call:end", { callId });
  assert.equal((await stop).callId, callId);
  [a, b].forEach((s) => s.disconnect());
});

test("call: when everyone declines the caller's call ends", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const callId = randomUUID();
  const ring = next(b, "call:invite");
  a.emit("call:invite", { callId, recipients: [B], callerName: "A" });
  await ring;
  const got = Promise.all([next(a, "call:rejected"), next(a, "call:end")]);
  b.emit("call:reject", { callId, callerId: A });
  const [rejected, ended] = await got;
  assert.equal(rejected.userId, B);
  assert.equal(ended.reason, "declined");
  [a, b].forEach((s) => s.disconnect());
});

test("call: the caller's tab closing ends the call for the other side", async () => {
  const a = await connect(A);
  const b = await connect(B);
  const callId = randomUUID();
  const ring = next(b, "call:invite");
  a.emit("call:invite", { callId, recipients: [B], callerName: "A" });
  await ring;
  const joined = next(a, "call:participant");
  b.emit("call:accept", { callId, callerId: A });
  await joined;
  const ended = next(b, "call:end");
  a.disconnect();
  assert.equal((await ended).callId, callId);
  b.disconnect();
});

test("presence: a user stays online while another tab is open", async () => {
  const a1 = await connect(A);
  const a2 = await connect(A);
  const b = await connect(B);
  const firstClose = next(b, "active-users");
  a1.disconnect();
  assert.equal(await firstClose, "none");
  const secondClose = next(b, "active-users");
  a2.disconnect();
  assert.ok(!(await secondClose).includes(A));
  b.disconnect();
});

test("presence: logout takes every tab offline immediately", async () => {
  const a1 = await connect(A);
  const a2 = await connect(A);
  const b = await connect(B);
  const updatedPresence = next(b, "active-users");
  const firstDisconnected = next(a1, "disconnect");
  const secondDisconnected = next(a2, "disconnect");
  a1.emit("user-logout");
  assert.ok(!(await updatedPresence).includes(A));
  assert.notEqual(await firstDisconnected, "none");
  assert.notEqual(await secondDisconnected, "none");
  b.disconnect();
});

test("a flood of events is cut off", async () => {
  const a = await connect(A);
  const b = await connect(B);
  let received = 0;
  b.on("private-message", () => received++);
  for (let i = 0; i < 1000; i++) a.emit("private-message", JSON.stringify({ sender_id: A, receiver_id: B, is_group: 0 }));
  await new Promise((r) => setTimeout(r, 600));
  assert.ok(received < 400, `received ${received}`);
  [a, b].forEach((s) => s.disconnect());
});
