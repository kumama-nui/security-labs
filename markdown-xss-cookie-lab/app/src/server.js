const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const MarkdownIt = require("markdown-it");
const sanitizeHtml = require("sanitize-html");

const app = express();
const port = Number(process.env.PORT || 3000);
const botUrl = process.env.BOT_URL || "http://bot:5000/visit";
const safeMode = String(process.env.SAFE_MODE || "false").toLowerCase() === "true";

const sessions = new Map();
const latestConversation = {
  id: "conv-1",
  subscribers: []
};

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

function htmlPage(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(title)}</title>
</head>
<body>
${body}
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sessionKey(req, res) {
  if (req.cookies.admin_session === "1") {
    return "admin";
  }

  let visitorId = req.cookies.visitor_id;
  if (!visitorId) {
    visitorId = crypto.randomBytes(12).toString("hex");
    res.cookie("visitor_id", visitorId, {
      httpOnly: true,
      sameSite: "Lax",
      secure: false
    });
  }
  return `user:${visitorId}`;
}

function getSession(req, res) {
  const key = sessionKey(req, res);
  if (!sessions.has(key)) {
    sessions.set(key, {
      greeting: "",
      csrfToken: crypto.randomBytes(16).toString("hex")
    });
  }
  return sessions.get(key);
}

function allowedMarkdownUrl(url) {
  try {
    const parsed = new URL(url, "http://example.test");
    return ["http:", "https:", "mailto:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function renderMarkdown(input) {
  const md = new MarkdownIt({
    html: false,
    linkify: false,
    typographer: false
  });

  if (safeMode) {
    md.validateLink = allowedMarkdownUrl;
  } else {
    // Intentional vulnerable point: the lab allows javascript: Markdown links.
    md.validateLink = () => true;
  }

  const rendered = md.render(input || "");

  if (!safeMode) {
    return rendered;
  }

  // SAFE_MODE fix: sanitize rendered Markdown and allow only safe link schemes.
  return sanitizeHtml(rendered, {
    allowedTags: [
      "p",
      "a",
      "strong",
      "em",
      "code",
      "pre",
      "ul",
      "ol",
      "li",
      "blockquote",
      "br"
    ],
    allowedAttributes: {
      a: ["href", "title"]
    },
    allowedSchemes: ["http", "https", "mailto"]
  });
}

function isAdmin(req) {
  return req.cookies.admin_session === "1";
}

function normalizeReportedUrl(input) {
  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    return null;
  }

  if (parsed.protocol !== "http:") {
    return null;
  }

  const host = parsed.hostname;
  const portValue = parsed.port || (parsed.protocol === "http:" ? "80" : "");
  const pathAndQuery = `${parsed.pathname}${parsed.search}${parsed.hash}`;

  if (host === "localhost" && portValue === "3000") {
    return `http://app:3000${pathAndQuery}`;
  }

  if (host === "localhost" && portValue === "4000") {
    return `http://attacker:4000${pathAndQuery}`;
  }

  if (host === "app" && portValue === "3000") {
    return `http://app:3000${pathAndQuery}`;
  }

  if (host === "attacker" && portValue === "4000") {
    return `http://attacker:4000${pathAndQuery}`;
  }

  return null;
}

app.get("/", (req, res) => {
  res.send(htmlPage("Markdown XSS Lab", `<h1>Markdown XSS Lab</h1>
<ul>
  <li><a href="/help/search">/help/search</a></li>
  <li><a href="/report">/report</a></li>
</ul>`));
});

app.get("/help/search", (req, res) => {
  const session = getSession(req, res);
  const renderedGreeting = session.greeting ? renderMarkdown(session.greeting) : "";
  const csrfField = safeMode
    ? `<input type="hidden" name="csrf" value="${escapeHtml(session.csrfToken)}">`
    : "";

  res.send(htmlPage("Search Help", `<h1>Search Help</h1>
<form method="post" action="/help/search">
  ${csrfField}
  <p><label>query <input name="query" value="${escapeHtml(req.query.q || "")}"></label></p>
  <p><label>greeting <textarea name="greeting" rows="5" cols="60">${escapeHtml(session.greeting || "")}</textarea></label></p>
  <button type="submit">Save</button>
</form>
<div class="assistant-message">
${renderedGreeting}
</div>`));
});

app.post("/help/search", (req, res) => {
  const session = getSession(req, res);

  if (safeMode && req.body.csrf !== session.csrfToken) {
    res.status(403).send("invalid csrf token");
    return;
  }

  // Intentional vulnerable point in default mode: no CSRF check protects this state change.
  session.greeting = String(req.body.greeting || "");
  const query = String(req.body.query || "");
  res.redirect(`/help/search?q=${encodeURIComponent(query)}`);
});

app.get("/report", (req, res) => {
  res.send(htmlPage("Report URL", `<h1>Report URL</h1>
<form method="post" action="/report">
  <p><label>url <input name="url" size="80"></label></p>
  <button type="submit">Report</button>
</form>`));
});

app.post("/report", async (req, res) => {
  const normalized = normalizeReportedUrl(req.body.url || "");
  if (!normalized) {
    res.status(400).send("URL rejected by allowlist");
    return;
  }

  try {
    const botResponse = await fetch(botUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({ url: normalized })
    });
    if (!botResponse.ok) {
      res.status(502).type("text/plain").send("bot failed to visit reported URL");
      return;
    }

    res
      .status(200)
      .type("text/plain")
      .send("reported\ncheck /loot or the bot logs after a few seconds");
  } catch (error) {
    res.status(502).type("text/plain").send(`bot error: ${error.message}`);
  }
});

app.get("/api/me", (req, res) => {
  if (isAdmin(req)) {
    res.json({
      role: "admin",
      email: "admin@example.test"
    });
    return;
  }

  res.json({
    role: "user",
    email: "user@example.test"
  });
});

app.get("/api/conversations/latest", (req, res) => {
  res.json(latestConversation);
});

app.post("/api/conversations/latest/subscribers", (req, res) => {
  if (!isAdmin(req)) {
    res.status(403).json({ error: "admin required" });
    return;
  }

  const email = String(req.body.email || "");
  if (!email) {
    res.status(400).json({ error: "email required" });
    return;
  }

  if (!latestConversation.subscribers.includes(email)) {
    latestConversation.subscribers.push(email);
  }

  res.json(latestConversation);
});

app.listen(port, () => {
  console.log(`app listening on ${port} safeMode=${safeMode}`);
});
