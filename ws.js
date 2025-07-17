require("dotenv").config();
const WebSocket = require("ws");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const http = require("http");
const HEARTBEAT_INTERVAL = 30000;

const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "blurbboard",
  password: process.env.DB_PASSWORD || "postgres",
  port: process.env.DB_PORT || 5432,
});

const generateRandomId = () => Math.floor(100000 + Math.random() * 900000);

const authenticateToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return null;
  }
};

const sanitizeContent = (content) => {
  if (!content) return content;

  const sanitized = content
    .normalize("NFKC")
    .replace(/[\u202E\u202D\u202A-\u202C\u200E\u200F]/g, "")
    .replace(
      /[\u0300-\u036F\u0347\u035F\uFEFF\u200B-\u200F\u2060-\u206F]+/g,
      ""
    )
    .replace(/[^\p{L}\p{N}\p{P}\p{S}\s]/gu, "");

  if (!sanitized.trim()) {
    throw new Error("Message contains only invalid characters");
  }

  return sanitized;
};

const lastRequestTimes = {};

const enforceCooldown = (ip) => {
  const now = Date.now();
  const cooldown = 5000;

  if (lastRequestTimes[ip] && now - lastRequestTimes[ip] < cooldown) {
    throw new Error("Too fast! Cooldown time is 5 seconds.");
  }

  lastRequestTimes[ip] = now;
};

const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200);
    res.end();
  } else {
    res.writeHead(404);
    res.end();
  }
});

const wss = new WebSocket.Server({ server });

const clients = new Map();

wss.on("connection", (ws, req) => {
  console.log("New client connected");

  ws.isAlive = true;

  ws.on("pong", () => {
    ws.isAlive = true;
    console.log("Received pong from client");
  });
  const ip = req.socket.remoteAddress;
  let user = null;

  ws.on("message", async (message) => {
    try {
      const data = JSON.parse(message);

      if (data.t === "hi") {
        try {
          enforceCooldown(ip);

          if (!data.token) {
            throw new Error("Token is required");
          }

          user = authenticateToken(data.token);
          if (!user) {
            throw new Error("Invalid token");
          }

          clients.set(ws, user);

          ws.send(
            JSON.stringify({
              t: "hi",
              success: true,
            })
          );
        } catch (err) {
          ws.send(
            JSON.stringify({
              t: "hi",
              success: false,
              error: err.message,
            })
          );
        }
      } else if (data.t === "post") {
        try {
          if (!user) {
            throw new Error("Not authenticated");
          }

          enforceCooldown(ip);

          if (!data.message || !data.message.content) {
            throw new Error("Message content is required");
          }

          const { content, parentId } = data.message;

          if (content.length > 500) {
            throw new Error(
              "Your message is too long, the maximum is 500 characters"
            );
          }

          const sanitizedContent = sanitizeContent(content);
          const msgId = generateRandomId();
          const timestamp = new Date().toISOString();

          await pool.query(
            "INSERT INTO messages (id, content, timestamp, author, parent_id) VALUES ($1, $2, $3, $4, $5)",
            [msgId, sanitizedContent, timestamp, user.id, parentId || null]
          );

          const userResult = await pool.query(
            "SELECT username FROM users WHERE id = $1",
            [user.id]
          );

          if (userResult.rows.length === 0) {
            throw new Error("User not found");
          }

          const authorName = userResult.rows[0].username;

          const newMessage = {
            id: msgId,
            content: sanitizedContent,
            timestamp,
            authorId: user.id,
            authorName,
            parentId: parentId || null,
          };

          const broadcastMsg = JSON.stringify({
            t: "nm",
            message: newMessage,
          });

          wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
              client.send(broadcastMsg);
            }
          });

          ws.send(
            JSON.stringify({
              t: "post",
              success: true,
            })
          );
        } catch (err) {
          ws.send(
            JSON.stringify({
              t: "post",
              success: false,
              error: err.message,
            })
          );
        }
      }
    } catch (err) {
      ws.send(
        JSON.stringify({
          t: "error",
          error: "Invalid message format",
        })
      );
    }
  });

  ws.on("close", () => {
    clients.delete(ws);
  });
});

setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      console.log("Terminating dead connection");
      return ws.terminate();
    }

    ws.isAlive = false;
    ws.ping();
    console.log("Sent ping to client");
  });
}, HEARTBEAT_INTERVAL);

const port = process.env.WS_PORT || 8080;
server.listen(port, () => {
  console.log(`WebSocket server running on ws://localhost:${port}`);
});
