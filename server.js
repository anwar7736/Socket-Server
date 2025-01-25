const express = require("express");
const { createServer } = require("http");
const { join } = require("path");
const { Server } = require("socket.io");
const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

const users = {};

app.get("/", function () {
  console.log("Socket server is running");
});

io.on("connection", (socket) => {
  socket.on("register-user", (userId) => {
    users[userId] = socket.id;
    socket.emit("active-users", Object.keys(users));
    socket.broadcast.emit("active-users", Object.keys(users));
  });

  socket.on("new-user", (data) => {
    const parsedData = JSON.parse(data);
    socket.broadcast.emit("new-user", parsedData);
  });

  socket.on("user-updated", (data) => {
    const parsedData = JSON.parse(data);
    socket.broadcast.emit("user-updated", parsedData);
  });

  socket.on("user-logout", (userId) => {
    delete users[userId];
    socket.broadcast.emit("active-users", Object.keys(users));
  });

  socket.on("private-message", (data) => {
    const parsedData = JSON.parse(data);
    io.emit("private-message", parsedData);
  });

  socket.on("message-deleted", (data) => {
    const parsedData = JSON.parse(data);
    io.to(users[parsedData?.receiver[0]?._id]).emit(
      "message-deleted",
      parsedData
    );
  });

  socket.on("add-group", (data) => {
    const parsedData = JSON.parse(data);
    parsedData.group_members?.map((user) => {
      io.to(users[user?.user_id]).emit("add-group", parsedData);
    });
  });

  socket.on("update-group", (data) => {
    const parsedData = JSON.parse(data);
    parsedData?.response?.map((res) => {
      io.to(users[res.user_id]).emit("update-group", { ...parsedData, res });
    });
  });

  socket.on("delete-group", (data) => {
    const parsedData = JSON.parse(data);
    socket.broadcast.emit("delete-group", parsedData);
  });

  socket.on("leave-group", (data) => {
    const parsedData = JSON.parse(data);
    socket.broadcast.emit("leave-group", parsedData);
  });

  socket.on("disconnect", () => {
    for (const userId in users) {
      if (users[userId] === socket.id) {
        delete users[userId];
        socket.broadcast.emit("active-users", Object.keys(users));
        break;
      }
    }
  });
});

server.listen(5000, () => {
  console.log(`Socket server is running.`);
});
