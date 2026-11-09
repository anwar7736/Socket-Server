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
  maxHttpBufferSize: 1e6,
  pingTimeout: 20000,
});

const users = new Map();
const calls = new Map();
const MAX_CALL_PARTICIPANTS = 8;

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

function emitToUser(userId, event, payload) {
  const socketId = users.get(userId);
  if (socketId) io.to(socketId).emit(event, payload);
}

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
  socket.on("register-user", () => {
    users.set(userId, socket.id);
    socket.join(`user:${userId}`);
    socket.emit("active-users", Array.from(users.keys()));
    socket.broadcast.emit("active-users", Array.from(users.keys()));
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
    if (users.get(userId) === socket.id) users.delete(userId);
    socket.broadcast.emit("active-users", Array.from(users.keys()));
  });

  socket.on("private-message", (data) => {
    const payload = parsePayload(data);
    if (payload?.sender_id === userId) socket.broadcast.emit("private-message", payload);
  });

  socket.on("message-deleted", (data) => {
    const payload = parsePayload(data);
    if (payload?.sender?._id === userId) socket.broadcast.emit("message-deleted", payload);
  });

  socket.on("add-group", (data) => {
    const payload = parsePayload(data);
    if (payload?.created_by !== userId || !Array.isArray(payload.group_members)) return;
    for (const member of payload.group_members) {
      emitToUser(member.user_id, "add-group", payload);
    }
  });

  socket.on("update-group", (data) => {
    const payload = parsePayload(data);
    if (payload?.causer_id !== userId || !Array.isArray(payload.response)) return;
    for (const result of payload.response) {
      emitToUser(result.user_id, "update-group", { ...payload, res: result });
    }
  });

  socket.on("delete-group", (data) => {
    const payload = parsePayload(data);
    if (payload?.deleted_by === userId) socket.broadcast.emit("delete-group", payload);
  });

  socket.on("leave-group", (data) => {
    const payload = parsePayload(data);
    if (payload?.user_id === userId) socket.broadcast.emit("leave-group", payload);
  });

  socket.on("call:invite", (data) => {
    const invite = parsePayload(data);
    if (
      !invite ||
      typeof invite.callId !== "string" ||
      !/^[a-f\d-]{36}$/i.test(invite.callId) ||
      !Array.isArray(invite.recipients) ||
      invite.recipients.length < 1 ||
      invite.recipients.length > MAX_CALL_PARTICIPANTS - 1
    ) return;

    const invited = new Set([userId]);
    for (const recipientId of invite.recipients) {
      if (typeof recipientId !== "string" || !users.has(recipientId)) continue;
      invited.add(recipientId);
      emitToUser(recipientId, "call:invite", {
        callId: invite.callId,
        callerId: userId,
        callerName: String(invite.callerName || "Someone").slice(0, 80),
        conversationName: String(invite.conversationName || "").slice(0, 80),
        isVideo: Boolean(invite.isVideo),
      });
    }
    if (invited.size === 1) {
      socket.emit("call:unavailable", { callId: invite.callId });
      return;
    }
    const timer = setTimeout(() => calls.delete(invite.callId), 5 * 60 * 1000);
    calls.set(invite.callId, { invited, accepted: new Set([userId]), timer });
  });

  socket.on("call:accept", (data) => {
    const invite = parsePayload(data);
    const call = calls.get(invite?.callId);
    if (!call?.invited.has(userId) || !call.invited.has(invite.callerId)) return;
    call.accepted.add(userId);
    emitToUser(invite.callerId, "call:accepted", { callId: invite.callId, userId });
    for (const peerId of call.accepted) {
      if (peerId === userId) continue;
      emitToUser(peerId, "call:participant", { callId: invite.callId, userId });
      emitToUser(userId, "call:participant", { callId: invite.callId, userId: peerId });
    }
  });

  socket.on("call:reject", (data) => {
    const invite = parsePayload(data);
    const call = calls.get(invite?.callId);
    if (!call?.invited.has(userId) || !call.invited.has(invite.callerId)) return;
    emitToUser(invite.callerId, "call:rejected", { callId: invite.callId, userId });
  });

  socket.on("call:signal", (data) => {
    const payload = parsePayload(data);
    const call = calls.get(payload?.callId);
    if (
      !call?.accepted.has(userId) ||
      !call.accepted.has(payload.to) ||
      !payload.signal ||
      !users.has(payload.to)
    ) return;
    emitToUser(payload.to, "call:signal", {
      callId: payload.callId,
      from: userId,
      signal: payload.signal,
    });
  });

  socket.on("call:end", (data) => {
    const payload = parsePayload(data);
    const call = calls.get(payload?.callId);
    if (!call?.accepted.has(userId)) return;
    for (const participantId of call.accepted) {
      if (participantId !== userId) {
        emitToUser(participantId, "call:end", { callId: payload.callId, userId });
      }
    }
    clearTimeout(call.timer);
    calls.delete(payload.callId);
  });

  socket.on("disconnect", () => {
    if (users.get(userId) === socket.id) {
      users.delete(userId);
      socket.broadcast.emit("active-users", Array.from(users.keys()));
    }
    for (const [callId, participants] of calls) {
      if (!participants.accepted.has(userId)) continue;
      clearTimeout(participants.timer);
      calls.delete(callId);
      for (const participantId of participants.accepted) {
        if (participantId !== userId) {
          emitToUser(participantId, "call:end", { callId, userId });
        }
      }
    }
  });
});

const port = Number(process.env.PORT || 3002);
server.listen(port, () => {
  console.log(`Socket server is running on port ${port}.`);
});
