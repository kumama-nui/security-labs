const express = require("express");
const puppeteer = require("puppeteer-core");

const app = express();
const port = Number(process.env.PORT || 5000);
const flag = process.env.FLAG || "FLAG{local_markdown_xss_cookie_lab}";
const safeMode = String(process.env.SAFE_MODE || "false").toLowerCase() === "true";

app.use(express.json());

function normalizeAllowedUrl(input) {
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
  const portValue = parsed.port || "80";
  const pathAndQuery = `${parsed.pathname}${parsed.search}${parsed.hash}`;

  if (host === "localhost" && portValue === "3000") {
    return `http://app.security-lab.test:3000${pathAndQuery}`;
  }

  if (host === "localhost" && portValue === "4000") {
    return `http://attacker.security-lab.test:4000${pathAndQuery}`;
  }

  if (host === "app" && portValue === "3000") {
    return `http://app.security-lab.test:3000${pathAndQuery}`;
  }

  if (host === "attacker" && portValue === "4000") {
    return `http://attacker.security-lab.test:4000${pathAndQuery}`;
  }

  return null;
}

async function visit(url) {
  const targetUrl = normalizeAllowedUrl(url);
  if (!targetUrl) {
    throw new Error("URL rejected by bot allowlist");
  }

  const log = {
    requestedUrl: url,
    visitUrl: targetUrl,
    currentUrl: "",
    foundLink: false,
    clicked: false,
    error: null
  };

  const browser = await puppeteer.launch({
    headless: "new",
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium",
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  });

  try {
    const page = await browser.newPage();

    await page.setCookie(
      {
        name: "admin_session",
        value: "1",
        url: "http://app.security-lab.test:3000",
        httpOnly: true,
        secure: false,
        sameSite: "Lax"
      },
      {
        name: "flag",
        value: flag,
        url: "http://app.security-lab.test:3000",
        // SAFE_MODE hardening: HttpOnly limits cookie theft, but does not stop XSS itself.
        httpOnly: safeMode,
        secure: false,
        sameSite: "Lax"
      }
    );

    await page.goto(targetUrl, {
      waitUntil: "domcontentloaded",
      timeout: 10000
    });

    await page
      .waitForFunction(() => window.location.href.includes("/help/search"), { timeout: 7000 })
      .catch(() => {});

    log.currentUrl = page.url();

    const link = await page.$(".assistant-message a");
    log.foundLink = Boolean(link);

    if (link) {
      await link.click();
      log.clicked = true;
    }

    await new Promise((resolve) => setTimeout(resolve, 2000));
    log.currentUrl = page.url();
  } catch (error) {
    log.error = error.message;
    log.currentUrl = log.currentUrl || "unknown";
  } finally {
    await browser.close();
  }

  if (log.error || !log.foundLink || !log.clicked) {
    console.error("[bot]", JSON.stringify(log));
  } else {
    console.log("[bot]", JSON.stringify(log));
  }

  return log;
}

app.post("/visit", async (req, res) => {
  try {
    const result = await visit(req.body.url || "");
    res.json(result);
  } catch (error) {
    console.error("[bot]", error.message);
    res.status(400).json({
      error: error.message
    });
  }
});

app.listen(port, () => {
  console.log(`bot listening on ${port} safeMode=${safeMode}`);
});
