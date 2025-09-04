const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Serve frontend from "public"
app.use(express.static(path.join(__dirname, "public")));

// Simple phishing detector API
app.post("/api/scan", (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  let score = 0;
  let reasons = [];

  try {
    const parsed = new URL(url);

    // Rule 1: Must use HTTPS
    if (parsed.protocol !== "https:") {
      score += 20;
      reasons.push("Not using HTTPS");
    }

    // Rule 2: IP address as domain
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) {
      score += 30;
      reasons.push("Domain is an IP address");
    }

    // Rule 3: Too many subdomains
    if (parsed.hostname.split(".").length > 3) {
      score += 10;
      reasons.push("Too many subdomains");
    }

    // Rule 4: Suspicious keywords
    const suspiciousWords = ["login", "verify", "account", "secure", "update"];
    if (suspiciousWords.some(w => url.toLowerCase().includes(w))) {
      score += 20;
      reasons.push("Contains suspicious keywords");
    }

    // Verdict
    let verdict = "No major flags";
    if (score >= 75) verdict = "Likely Phishing 🚨";
    else if (score >= 50) verdict = "Suspicious ⚠️";
    else if (score >= 25) verdict = "Caution ⚠️";

    res.json({ url, score, reasons, verdict });
  } catch (err) {
    res.status(400).json({ error: "Invalid URL format" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
