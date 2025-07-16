require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "blurbboard",
  password: process.env.DB_PASSWORD || "postgres",
  port: process.env.DB_PORT || 5432,
});

app.use(express.json());

const generateRandomId = () => Math.floor(100000 + Math.random() * 900000);

const generateAuthToken = (user) => {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET
  );
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const sanitizeContent = (req, res, next) => {
  if (req.body.content) {
    req.body.content = req.body.content
      .normalize("NFKC")
      .replace(/[\u202E\u202D\u202A-\u202C\u200E\u200F]/g, "")
      .replace(
        /[\u0300-\u036F\u0347\u035F\uFEFF\u200B-\u200F\u2060-\u206F]+/g,
        ""
      )
      .replace(/[^\p{L}\p{N}\p{P}\p{S}\s]/gu, "");

    if (!req.body.content.trim()) {
      return res
        .status(400)
        .json({ error: "Message contains only invalid characters" });
    }
  }
  next();
};

const lastRequestTimes = {};

const enforceCooldown = (req, res, next) => {
  const userId = req.ip;
  const now = Date.now();
  const cooldown = 5000;

  if (lastRequestTimes[userId] && now - lastRequestTimes[userId] < cooldown) {
    return res.sendStatus(429);
  }

  lastRequestTimes[userId] = now;
  next();
};

app.post("/api/users/register", enforceCooldown, async (req, res) => {
  if (req.body.username) {
    if (req.body.username.length > 20) {
      return res.status(400).json({
        error: "Your username is too long, the maximum is 20 characters",
      });
    }
    req.body.username = req.body.username
      .normalize("NFKC")
      .replace(/[\u202E\u202D\u202A-\u202C\u200E\u200F]/g, "")
      .replace(
        /[\u0300-\u036F\u0347\u035F\uFEFF\u200B-\u200F\u2060-\u206F]+/g,
        ""
      )
      .replace(/[^\p{L}\p{N}\p{P}\p{S}\s]/gu, "");

    if (!req.body.username.trim()) {
      return res
        .status(400)
        .json({ error: "Username contains only invalid characters" });
    }
  }
  const { username, password } = req.body;

  try {
    const userCheck = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const userId = generateRandomId();

    const idCheck = await pool.query("SELECT * FROM users WHERE id = $1", [
      userId,
    ]);
    while (idCheck.rows.length > 0) {
      userId = generateRandomId();
      idCheck = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
    }
    const createdAt = new Date().toISOString();

    const saltRounds = 10;
    const hash = await bcrypt.hash(password, saltRounds);

    await pool.query("BEGIN");
    await pool.query(
      "INSERT INTO users (id, username, created_at) VALUES ($1, $2, $3)",
      [userId, username, createdAt]
    );
    await pool.query("INSERT INTO passwords (user_id, hash) VALUES ($1, $2)", [
      userId,
      hash,
    ]);
    await pool.query("COMMIT");

    const token = generateAuthToken({ id: userId, username });

    res.status(201).json({ token, username });
  } catch (err) {
    await pool.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/users/login", enforceCooldown, async (req, res) => {
  const { username, password } = req.body;

  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = userResult.rows[0];

    const passwordResult = await pool.query(
      "SELECT hash FROM passwords WHERE user_id = $1",
      [user.id]
    );
    if (passwordResult.rows.length === 0) {
      return res.status(500).json({ error: "Internal server error" });
    }

    const match = await bcrypt.compare(password, passwordResult.rows[0].hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = generateAuthToken(user);

    res.json({ token, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/msgs", async (req, res) => {
  try {
    const page = parseInt(req.query.p) || 1;
    const limit = 10;

    const countQuery = `
      SELECT COUNT(*) 
      FROM messages 
      WHERE parent_id IS NULL
    `;
    const { rows: countRows } = await pool.query(countQuery);
    const totalTopLevelMessages = parseInt(countRows[0].count, 10);
    const totalPages = Math.ceil(totalTopLevelMessages / limit);
    const offset = Math.min((page - 1) * limit, totalTopLevelMessages);

    const topLevelQuery = `
      SELECT id
      FROM messages
      WHERE parent_id IS NULL
      ORDER BY timestamp DESC
      LIMIT $1 OFFSET $2
    `;
    const { rows: topLevelRows } = await pool.query(topLevelQuery, [
      limit,
      offset,
    ]);
    const topLevelIds = topLevelRows.map((row) => row.id);

    let messages = [];
    if (topLevelIds.length > 0) {
      const messagesQuery = `
        WITH RECURSIVE message_thread AS (
          SELECT 
            id, 
            content, 
            timestamp, 
            parent_id, 
            author,
            id AS root_id
          FROM messages
          WHERE id = ANY($1)
          UNION ALL
          SELECT 
            m.id, 
            m.content, 
            m.timestamp, 
            m.parent_id, 
            m.author,
            mt.root_id
          FROM messages m
          JOIN message_thread mt ON m.parent_id = mt.id
        )
        SELECT
          mt.id,
          mt.content,
          mt.timestamp,
          mt.parent_id AS "parentId",
          mt.author AS "authorId",
          u.username AS "authorName",
          mt.root_id AS "rootId"
        FROM message_thread mt
        JOIN users u ON mt.author = u.id
        ORDER BY
          (SELECT timestamp FROM messages WHERE id = mt.root_id) DESC,
          mt.root_id,
          mt.timestamp ASC
      `;
      const { rows } = await pool.query(messagesQuery, [topLevelIds]);
      messages = rows;
    }

    res.json({
      page,
      totalPages,
      messages,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post(
  "/api/msgs",
  enforceCooldown,
  authenticateToken,
  sanitizeContent,
  async (req, res) => {
    const { content, parentId } = req.body;
    const userId = req.user.id;

    if (content.length > 500) {
      return res.status(400).json({
        error: "Your message is too long, the maximum is 500 characters",
      });
    }

    try {
      const msgId = generateRandomId();

      const idCheck = await pool.query("SELECT * FROM messages WHERE id = $1", [
        msgId,
      ]);
      while (idCheck.rows.length > 0) {
        msgId = generateRandomId();
        idCheck = await pool.query("SELECT * FROM users WHERE id = $1", [
          msgId,
        ]);
      }
      const timestamp = new Date().toISOString();

      await pool.query(
        "INSERT INTO messages (id, content, timestamp, author, parent_id) VALUES ($1, $2, $3, $4, $5)",
        [msgId, content, timestamp, userId, parentId]
      );

      res.status(201).json({
        success: true,
        message: {
          id: msgId,
          content,
          timestamp,
          authorId: req.user.id,
          authorName: req.user.username,
          parentId,
        },
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get("/api", (req, res) => {
  res.json({ message: "Hello from Express API!" });
});

app.get("/api/health", (req, res) => res.sendStatus(200));

app.get("/api/users/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    const userResult = await pool.query(
      "SELECT id, username, created_at FROM users WHERE id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userResult.rows[0];
    res.json({
      id: user.id,
      username: user.username,
      createdAt: user.created_at,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(port, () => {
  console.log(`API running on http://localhost:${port}/api`);
});
