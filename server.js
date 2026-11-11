require("dotenv").config();

const express = require("express");
const { createHmac, timingSafeEqual } = require("crypto");
const { createServer } = require("http");
const { Server } = require("socket.io");

const app = express();
const server = createServer(app);
const localOrigins = ["http://localhost:3001", "http://127.0.0.1:3001"];
const configuredOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const allowedOrigins = configuredOrigins.length
  ? configuredOrigins
  : process.env.NODE_ENV === "production"
    ? []
    : localOrigins;
if (!allowedOrigins.length) {
  throw new Error("Set CORS_ORIGINS to the exact frontend origin(s) before starting in production.");
}
for (const origin of allowedOrigins) {
  if (new URL(origin).origin !== origin) {
    throw new Error(`CORS_ORIGINS must contain exact origins without paths or trailing slashes: ${origin}`);
  }
}
if (
  process.env.NODE_ENV === "production" &&
  (!process.env.AUTH_SECRET || process.env.AUTH_SECRET.length < 32)
) {
  throw new Error("Set AUTH_SECRET to the same value as the frontend, at least 32 characters long.");
}
const allowedOriginSet = new Set(allowedOrigins);
const isAllowedOrigin = (origin) => !origin || allowedOriginSet.has(origin);
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => callback(null, isAllowedOrigin(origin)),
    credentials: false,
  },
  allowRequest: (request, callback) => callback(null, isAllowedOrigin(request.headers.origin)),
  maxHttpBufferSize: 100 * 1024, // events carry ids and call signalling only
  pingTimeout: 20000,
});

// users who registered and still have at least one open tab
const onlineUsers = new Set();
const calls = new Map();
const MAX_CALL_PARTICIPANTS = 8;
// an unanswered call stops ringing after this long
const CALL_MAX_RING_MS = 60 * 1000;
// per socket: a burst of events (a group call sends many ICE candidates at once), then a steady rate
const EVENT_BURST = 300;
const EVENT_RATE = 30;
// most users one event may be sent to (groups are limited to 100 members)
const MAX_RECIPIENTS = 200;
const objectIdPattern = /^[a-f\d]{24}$/i;
const isEmoji = (value) =>
  typeof value === "string" &&
  value.length <= 32 &&
  /[\p{Extended_Pictographic}\p{Regional_Indicator}\u20e3]/u.test(value);

app.get("/", (_request, response) => {
  response.status(200).json({ status: "ok", service: "socket-server" });
});

function decodeSession(cookieHeader) {
  const token = (cookieHeader || "")
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("auth="))
    ?.slice(5);
  if (!token) return null;

  const [userId, expiration, signature, ...rest] = token.split(".");
  if (
    rest.length ||
    !/^[a-f\d]{24}$/i.test(userId || "") ||
    !/^\d+$/.test(expiration || "") ||
    Number(expiration) <= Math.floor(Date.now() / 1000)
  ) return null;

  const secret =
    process.env.AUTH_SECRET ||
    (process.env.NODE_ENV !== "production" && "local-development-only-secret-change-before-deploy");
  if (!secret || (process.env.NODE_ENV === "production" && secret.length < 32)) return null;

  try {
    const expected = createHmac("sha256", secret).update(`${userId}.${expiration}`).digest();
    const provided = Buffer.from(signature.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    return expected.length === provided.length && timingSafeEqual(expected, provided) ? userId : null;
  } catch {
    return null;
  }
}

function decodeSocketToken(token) {
  if (typeof token !== "string") return null;

  const [userId, expiration, signature, ...rest] = token.split(".");
  if (
    rest.length ||
    !/^[a-f\d]{24}$/i.test(userId || "") ||
    !/^\d+$/.test(expiration || "") ||
    Number(expiration) <= Math.floor(Date.now() / 1000)
  ) return null;

  const secret =
    process.env.AUTH_SECRET ||
    (process.env.NODE_ENV !== "production" && "local-development-only-secret-change-before-deploy");
  if (!secret || (process.env.NODE_ENV === "production" && secret.length < 32)) return null;

  try {
    const expected = createHmac("sha256", secret)
      .update(`socket:${userId}.${expiration}`)
      .digest();
    const provided = Buffer.from(signature.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    return expected.length === provided.length && timingSafeEqual(expected, provided)
      ? userId
      : null;
  } catch {
    return null;
  }
}

function parsePayload(data) {
  try {
    return typeof data === "string" ? JSON.parse(data) : data;
  } catch {
    return null;
  }
}

const userRoom = (userId) => `user:${userId}`;
const isObjectId = (value) => typeof value === "string" && objectIdPattern.test(value);

// Every tab of a user joins user:<id>, so an event reaches all of that user's tabs.
function emitToUser(userId, event, payload) {
  if (isObjectId(userId)) io.to(userRoom(userId)).emit(event, payload);
}

// Rooms for a list of user ids (strings, or objects with user_id), deduplicated and capped.
function roomsFor(ids) {
  const rooms = new Set();
  for (const item of Array.isArray(ids) ? ids : []) {
    const id = typeof item === "string" ? item : item?.user_id != null ? String(item.user_id) : null;
    if (isObjectId(id)) rooms.add(userRoom(id));
    if (rooms.size >= MAX_RECIPIENTS) break;
  }
  return [...rooms];
}

const isOnline = (userId) => Boolean(io.sockets.adapter.rooms.get(userRoom(userId))?.size);

io.use((socket, next) => {
  const userId =
    decodeSocketToken(socket.handshake.auth?.token) ||
    decodeSession(socket.request.headers.cookie);
  if (!userId) return next(new Error("unauthorized"));
  socket.data.userId = userId;
  next();
});

io.on("connection", (socket) => {
  const userId = socket.data.userId;
  socket.join(userRoom(userId));

  socket.on("register-user", () => {
    onlineUsers.add(userId);
    const active = Array.from(onlineUsers);
    socket.emit("active-users", active);
    socket.broadcast.emit("active-users", active);
  });

  socket.on("new-user", (data) => {
    const payload = parsePayload(data);
    if (payload?._id === userId) socket.broadcast.emit("new-user", payload);
  });

  socket.on("user-updated", (data) => {
    const payload = parsePayload(data);
    if (payload?._id === userId) socket.broadcast.emit("user-updated", payload);
  });

  socket.on("user-logout", () => {
    onlineUsers.delete(userId);
    socket.broadcast.emit("user-offline", { user_id: userId, last_seen_at: new Date().toISOString() });
    socket.broadcast.emit("active-users", Array.from(onlineUsers));
    // A logout applies to the whole signed-in user, not just the current tab.
    setImmediate(() => io.in(userRoom(userId)).disconnectSockets(true));
  });

  // Only ids travel here; the app loads the message itself through its authorised API.
  // A direct message goes to the receiver; a group message to the members the app lists.
  // The sender's other tabs get it too (the sending tab reloads on its own).
  socket.on("private-message", (data) => {
    const payload = parsePayload(data);
    if (payload?.sender_id !== userId || !isObjectId(payload.receiver_id)) return;
    const isGroup = payload.is_group == 1;
    const event = { sender_id: userId, receiver_id: payload.receiver_id, is_group: isGroup ? 1 : 0 };
    if (isGroup && !Array.isArray(payload.recipient_ids)) {
      // older app version without the member list: ids only, to everyone
      socket.broadcast.emit("private-message", event);
      return;
    }
    const recipients = isGroup ? payload.recipient_ids : [payload.receiver_id];
    socket.to(roomsFor([userId, ...recipients])).emit("private-message", event);
  });

  socket.on("typing-status", (data) => {
    const payload = parsePayload(data);
    if (
      payload?.sender_id !== userId ||
      !isObjectId(payload.receiver_id) ||
      typeof payload.is_group !== "boolean" ||
      typeof payload.typing !== "boolean"
    ) return;
    const recipients = payload.is_group
      ? Array.isArray(payload.recipient_ids) ? payload.recipient_ids : []
      : [payload.receiver_id];
    socket.to(roomsFor(recipients.filter((id) => id !== userId))).emit("typing-status", {
      sender_id: userId,
      sender_name: String(payload.sender_name || "Someone").slice(0, 80),
      receiver_id: payload.receiver_id,
      is_group: payload.is_group,
      typing: payload.typing,
    });
  });

  socket.on("messages-seen", (data) => {
    const payload = parsePayload(data);
    const secret =
      process.env.AUTH_SECRET ||
      (process.env.NODE_ENV !== "production" && "local-development-only-secret-change-before-deploy");
    const { signature, issuedAt, ...event } = payload || {};
    if (
      !secret ||
      typeof signature !== "string" ||
      !Number.isSafeInteger(issuedAt) ||
      Math.abs(Date.now() - issuedAt) > 30_000 ||
      event?.actor_id !== userId ||
      !Array.isArray(event.message_ids) ||
      !event.message_ids.length ||
      event.message_ids.length > 200 ||
      event.message_ids.some((id) => !isObjectId(id)) ||
      !Array.isArray(event.recipient_ids) ||
      !event.recipient_ids.length ||
      event.recipient_ids.length > MAX_RECIPIENTS ||
      event.recipient_ids.some((id) => !isObjectId(id))
    ) return;
    const expected = createHmac("sha256", secret)
      .update(JSON.stringify({ event, issuedAt }))
      .digest();
    let provided;
    try {
      provided = Buffer.from(signature, "base64url");
    } catch {
      return;
    }
    if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) return;
    socket.to(roomsFor(event.recipient_ids)).emit("messages-seen", {
      actor_id: userId,
      actor_name: String(event.actor_name || "Someone").slice(0, 80),
      actor_photo: String(event.actor_photo || "").slice(0, 180),
      message_ids: event.message_ids,
    });
  });

  // Only the ids of the removed message, never its text or attachment.
  socket.on("message-deleted", (data) => {
    const payload = parsePayload(data);
    const receiverId = payload?.receiver?._id;
    if (payload?.sender?._id !== userId || !isObjectId(payload._id)) return;
    const recipients = Array.isArray(payload.recipient_ids)
      ? payload.recipient_ids
      : [receiverId];
    socket.to(roomsFor([userId, ...recipients])).emit("message-deleted", {
      _id: payload._id,
      ...(isObjectId(payload.message_id) ? { message_id: payload.message_id } : {}),
      sender: { _id: userId },
      receiver: { _id: isObjectId(receiverId) ? receiverId : null },
    });
  });

  socket.on("message-reaction", (data) => {
    const payload = parsePayload(data);
    const secret =
      process.env.AUTH_SECRET ||
      (process.env.NODE_ENV !== "production" && "local-development-only-secret-change-before-deploy");
    const { signature, issuedAt, ...event } = payload || {};
    if (!secret || typeof signature !== "string" || !Number.isSafeInteger(issuedAt) || Math.abs(Date.now() - issuedAt) > 30_000) return;
    const expected = createHmac("sha256", secret)
      .update(JSON.stringify({ event, issuedAt }))
      .digest();
    let provided;
    try {
      provided = Buffer.from(signature, "base64url");
    } catch {
      return;
    }
    if (
      expected.length !== provided.length ||
      !timingSafeEqual(expected, provided) ||
      event?.actor_id !== userId ||
      !isObjectId(event.message_id) ||
      !Array.isArray(event.recipient_ids) ||
      !Array.isArray(event.reactions) ||
      event.reactions.some((reaction) => !isObjectId(reaction?.user_id) || !isEmoji(reaction?.emoji))
    ) return;
    socket.to(roomsFor(event.recipient_ids)).emit("message-reaction", {
      message_id: event.message_id,
      reactions: event.reactions.slice(0, MAX_RECIPIENTS),
    });
  });

  socket.on("add-group", (data) => {
    const payload = parsePayload(data);
    if (payload?.created_by !== userId || !Array.isArray(payload.group_members)) return;
    for (const member of payload.group_members.slice(0, MAX_RECIPIENTS)) {
      emitToUser(String(member?.user_id), "add-group", payload);
    }
  });

  socket.on("update-group", (data) => {
    const payload = parsePayload(data);
    if (payload?.causer_id !== userId || !Array.isArray(payload.response)) return;
    for (const result of payload.response.slice(0, MAX_RECIPIENTS)) {
      emitToUser(String(result?.user_id), "update-group", { ...payload, res: result });
    }
  });

  // Group notices go to the group's members only (the list the app received from its API).
  socket.on("delete-group", (data) => {
    const payload = parsePayload(data);
    if (payload?.deleted_by !== userId || !isObjectId(payload._id)) return;
    const event = { _id: payload._id, deleted_by: userId, message: String(payload.message || "").slice(0, 200) };
    socket.to(roomsFor([userId, ...(payload.groupMembers || [])])).emit("delete-group", event);
  });

  socket.on("leave-group", (data) => {
    const payload = parsePayload(data);
    if (payload?.user_id !== userId || !isObjectId(payload._id)) return;
    const event = { _id: payload._id, user_id: userId, message: String(payload.message || "").slice(0, 200) };
    socket.to(roomsFor([userId, ...(payload.groupMembers || [])])).emit("leave-group", event);
  });

  // ---- calls: the server only relays signalling; audio and video flow browser to browser (or via TURN).
  // A call remembers which tab of each participant is in it, so other tabs stop ringing and
  // closing an unrelated tab does not end the call.
  socket.on("call:invite", (data) => {
    const invite = parsePayload(data);
    if (
      !invite ||
      typeof invite.callId !== "string" ||
      !/^[a-f\d-]{36}$/i.test(invite.callId) ||
      calls.has(invite.callId) ||
      !Array.isArray(invite.recipients) ||
      invite.recipients.length < 1 ||
      invite.recipients.length > MAX_CALL_PARTICIPANTS - 1
    ) return;

    if (findCallForUser(userId)) {
      socket.emit("call:busy", { callId: invite.callId, userId });
      return;
    }

    const invited = new Set([userId]);
    const availableRecipients = [];
    let busyRecipients = 0;
    for (const recipientId of invite.recipients) {
      if (!isObjectId(recipientId) || recipientId === userId || !onlineUsers.has(recipientId)) continue;
      if (findCallForUser(recipientId)) {
        busyRecipients += 1;
        socket.emit("call:busy", { callId: invite.callId, userId: recipientId });
        continue;
      }
      invited.add(recipientId);
      availableRecipients.push(recipientId);
    }
    if (invited.size === 1) {
      socket.emit("call:unavailable", { callId: invite.callId, reason: busyRecipients ? "busy" : "offline" });
      return;
    }
    const timer = setTimeout(() => endCall(invite.callId, null, "no-answer"), CALL_MAX_RING_MS);
    calls.set(invite.callId, {
      callerId: userId,
      invited,
      accepted: new Set([userId]),
      rejected: new Set(),
      sockets: new Map([[userId, socket.id]]),
      timer,
    });
    for (const recipientId of availableRecipients) {
      emitToUser(recipientId, "call:invite", {
        callId: invite.callId,
        callerId: userId,
        callerName: String(invite.callerName || "Someone").slice(0, 80),
        conversationName: String(invite.conversationName || "").slice(0, 80),
        conversationId: isObjectId(invite.conversationId) ? invite.conversationId : "",
        isGroup: Boolean(invite.isGroup),
        isVideo: Boolean(invite.isVideo),
      });
    }
    socket.emit("call:ringing", { callId: invite.callId });
  });

  socket.on("call:accept", (data) => {
    const invite = parsePayload(data);
    const call = calls.get(invite?.callId);
    if (!call?.invited.has(userId) || call.callerId !== invite.callerId || call.accepted.has(userId)) return;
    clearTimeout(call.timer); // someone answered: the call now lasts until it is ended
    call.timer = null;
    call.accepted.add(userId);
    call.sockets.set(userId, socket.id);
    // the user's other tabs stop ringing
    socket.to(userRoom(userId)).emit("call:end", { callId: invite.callId, userId, reason: "answered-elsewhere" });
    emitToCallMember(call, call.callerId, "call:accepted", { callId: invite.callId, userId });
    for (const peerId of call.accepted) {
      if (peerId === userId) continue;
      emitToCallMember(call, peerId, "call:participant", { callId: invite.callId, userId });
      socket.emit("call:participant", { callId: invite.callId, userId: peerId });
    }
  });

  socket.on("call:reject", (data) => {
    const invite = parsePayload(data);
    const call = calls.get(invite?.callId);
    if (!call?.invited.has(userId) || call.callerId !== invite.callerId || call.accepted.has(userId)) return;
    call.rejected.add(userId);
    socket.to(userRoom(userId)).emit("call:end", { callId: invite.callId, userId, reason: "declined-elsewhere" });
    emitToCallMember(call, call.callerId, "call:rejected", { callId: invite.callId, userId });
    // nobody answered and everybody declined: the caller's screen closes
    const waiting = [...call.invited].filter((id) => !call.accepted.has(id) && !call.rejected.has(id));
    if (call.accepted.size === 1 && !waiting.length) endCall(invite.callId, userId, "declined");
  });

  socket.on("call:signal", (data) => {
    const payload = parsePayload(data);
    const call = calls.get(payload?.callId);
    if (
      !call?.accepted.has(userId) ||
      call.sockets.get(userId) !== socket.id ||
      !call.accepted.has(payload.to) ||
      !payload.signal ||
      typeof payload.signal !== "object"
    ) return;
    emitToCallMember(call, payload.to, "call:signal", {
      callId: payload.callId,
      from: userId,
      signal: payload.signal,
    });
  });

  socket.on("call:end", (data) => {
    const payload = parsePayload(data);
    const call = calls.get(payload?.callId);
    if (!call?.accepted.has(userId) || call.sockets.get(userId) !== socket.id) return;
    leaveCall(payload.callId, userId);
  });

  // The socket has already left its rooms here.
  socket.on("disconnect", () => {
    for (const [callId, call] of calls) {
      if (call.sockets.get(userId) === socket.id) leaveCall(callId, userId);
    }
    if (isOnline(userId)) return; // another tab of this user is still open
    if (onlineUsers.delete(userId)) {
      socket.broadcast.emit("user-offline", { user_id: userId, last_seen_at: new Date().toISOString() });
      socket.broadcast.emit("active-users", Array.from(onlineUsers));
    }
  });

  // ---- flood protection: events beyond what a person (or a call setting up) could send are dropped
  let tokens = EVENT_BURST;
  let refilledAt = Date.now();
  socket.use((_packet, next) => {
    const now = Date.now();
    tokens = Math.min(EVENT_BURST, tokens + ((now - refilledAt) / 1000) * EVENT_RATE);
    refilledAt = now;
    if (tokens < 1) return next(new Error("rate limited"));
    tokens -= 1;
    next();
  });
});

function emitToCallMember(call, memberId, event, payload) {
  const socketId = call.sockets.get(memberId);
  if (socketId) io.to(socketId).emit(event, payload);
  else emitToUser(memberId, event, payload);
}

function findCallForUser(userId) {
  for (const call of calls.values()) {
    if (call.invited.has(userId) && !call.rejected.has(userId)) return call;
  }
  return null;
}

// One participant leaves; with fewer than two people left the call ends for everyone.
function leaveCall(callId, userId) {
  const call = calls.get(callId);
  if (!call) return;
  const stillRinging = call.accepted.size === 1 && call.callerId === userId;
  if (stillRinging || call.accepted.size <= 2) {
    endCall(callId, userId);
    return;
  }
  call.accepted.delete(userId);
  call.sockets.delete(userId);
  for (const participantId of call.accepted) {
    emitToCallMember(call, participantId, "call:left", { callId, userId });
  }
}

// Ends the call for every participant and stops the ringing for everyone who was invited.
function endCall(callId, userId, reason = "ended") {
  const call = calls.get(callId);
  if (!call) return;
  clearTimeout(call.timer);
  calls.delete(callId);
  for (const memberId of call.invited) {
    if (memberId === userId && reason === "ended") continue;
    emitToCallMember(call, memberId, "call:end", { callId, userId, reason });
  }
}

// graceful restart: open sockets are told to reconnect (the browser does so on its own)
function shutdown() {
  io.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

const port = Number(process.env.PORT || 3002);
server.listen(port, () => {
  console.log(`Socket server is running on port ${port}.`);
});
