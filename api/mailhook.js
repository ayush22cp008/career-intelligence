const { timingSafeEqual } = require("node:crypto");

const MAX_BODY_BYTES = 1_000_000;
const MAX_TEXT_LENGTH = 250_000;
const MAX_HTML_LENGTH = 500_000;
const MAX_SUBJECT_LENGTH = 500;

const ALLOWED_SENDERS = new Map([
  ["jobalerts-noreply@linkedin.com", "linkedin"],
  ["jobs-noreply@linkedin.com", "linkedin"],
  ["donotreply@jobalert.indeed.com", "indeed"],
  ["donotreply@match.indeed.com", "indeed"],
  ["naukrialerts@naukri.com", "naukri"],
  ["info@naukri.com", "naukri"],
  ["team@hi.wellfound.com", "wellfound"],
]);

function sendJson(res, status, body) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.status(status).json(body);
}

function hasValidBearer(req, expected) {
  const authorization = req.headers.authorization || "";
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!match) return false;

  const received = Buffer.from(match[1], "utf8");
  const configured = Buffer.from(expected, "utf8");
  return (
    received.length === configured.length &&
    timingSafeEqual(received, configured)
  );
}

function firstString(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") return "";
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      if (Array.isArray(value)) return value.join(" ");
      return typeof value === "string" ? value : "";
    }
  }
  return "";
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return sendJson(res, 405, { ok: false, error: "Method not allowed." });
  }

  const sharedSecret = process.env.MAKE_MAILHOOK_SHARED_SECRET;
  if (!sharedSecret || sharedSecret.length < 32) {
    return sendJson(res, 503, {
      ok: false,
      error: "Mailhook receiver is not configured.",
    });
  }

  if (!hasValidBearer(req, sharedSecret)) {
    return sendJson(res, 401, { ok: false, error: "Unauthorized." });
  }

  const contentType = req.headers["content-type"] || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return sendJson(res, 415, {
      ok: false,
      error: "Content-Type must be application/json.",
    });
  }

  let payload = req.body;
  if (typeof payload === "string" || Buffer.isBuffer(payload)) {
    try {
      payload = JSON.parse(payload.toString());
    } catch {
      return sendJson(res, 400, { ok: false, error: "Malformed JSON." });
    }
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return sendJson(res, 400, { ok: false, error: "A JSON object is required." });
  }

  let bodyBytes;
  try {
    bodyBytes = Buffer.byteLength(JSON.stringify(payload), "utf8");
  } catch {
    return sendJson(res, 400, { ok: false, error: "Invalid JSON payload." });
  }
  if (bodyBytes > MAX_BODY_BYTES) {
    return sendJson(res, 413, { ok: false, error: "Payload is too large." });
  }

  const email = payload.email && typeof payload.email === "object"
    ? payload.email
    : payload;

  // Supports both the normalized shape and Make's Custom mailhook field names.
  const senderEmail = firstString(
    email.senderEmail,
    email["Sender: Email"],
    email.sender && email.sender.email,
    email.from && email.from.email,
    email.fromEmail
  ).toLowerCase();

  const subject = firstString(email.subject, email.Subject);
  const text = firstString(email.text, email.Text, email["Body Plain"]);
  const html = firstString(email.html, email.HTML, email["HTML Content"]);
  const headers = email.headers || email.Headers;

  const messageId = firstString(
    email.messageId,
    email["Headers: message-id"],
    getHeader(headers, "message-id")
  );

  if (!senderEmail || !subject || subject.length > MAX_SUBJECT_LENGTH) {
    return sendJson(res, 422, {
      ok: false,
      error: "A valid sender email and subject are required.",
    });
  }

  const platform = ALLOWED_SENDERS.get(senderEmail);
  if (!platform) {
    return sendJson(res, 403, {
      ok: false,
      error: "Sender is not on the approved job-alert allowlist.",
    });
  }

  if (text.length > MAX_TEXT_LENGTH || html.length > MAX_HTML_LENGTH) {
    return sendJson(res, 413, {
      ok: false,
      error: "Email body exceeds the permitted size.",
    });
  }

  if (!text && !html) {
    return sendJson(res, 422, {
      ok: false,
      error: "The email must contain text or HTML content.",
    });
  }

  // Gate 0 is not closed. This endpoint validates transport only:
  // it deliberately does not log, parse, persist, or forward email content.
  return sendJson(res, 202, {
    ok: true,
    accepted: true,
    mode: "transport-test-only",
    stored: false,
    platform,
    senderEmail,
    messageId: messageId || null,
  });
};

module.exports.config = {
  api: {
    bodyParser: {
      sizeLimit: "1mb",
    },
  },
};
