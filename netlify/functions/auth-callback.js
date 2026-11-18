
const crypto = require("node:crypto");

const SITE_URL = "https://sugarblueprintstudio.netlify.app";

exports.handler = async (event) => {
  const params = event.queryStringParameters || {};
  const code = params.code;
  const state = params.state;

  const cookies = event.headers.cookie || event.headers.Cookie || "";
  const savedState = cookies
    .split(";")
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith("oauth_state="))
    ?.slice("oauth_state=".length);

  const clearCookie =
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/.netlify/functions; Max-Age=0";

  const respond = (statusCode, body) => ({
    statusCode,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Set-Cookie": clearCookie
    },
    body
  });

  if (params.error) {
    return respond(400, "GitHub authorization was cancelled or denied.");
  }

  if (!code || !state || !savedState) {
    return respond(400, "Missing authorization code or login state.");
  }

  const expected = Buffer.from(savedState, "utf8");
  const received = Buffer.from(state, "utf8");

  if (
    expected.length !== received.length ||
    !crypto.timingSafeEqual(expected, received)
  ) {
    return respond(403, "Invalid login state. Please try signing in again.");
  }

  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return respond(500, "GitHub OAuth credentials are not configured.");
  }

  try {
    const response = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: `${SITE_URL}/.netlify/functions/auth-callback`
        })
      }
    );

    const result = await response.json();

    if (!response.ok || !result.access_token) {
      return respond(400, "GitHub could not complete authorization.");
    }

    const payload = JSON.stringify({
      token: result.access_token,
      provider: "github"
    }).replace(/</g, "\\u003c");

    const origin = JSON.stringify(SITE_URL);

    return respond(200, `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>GitHub Login</title></head>
<body>
<p>Completing your login...</p>
<script>
(function () {
  const message = "authorization:github:success:" + ${JSON.stringify(payload)};
  const target = ${origin};

  function receive(event) {
    if (event.origin !== target || event.data !== "authorizing:github") {
      return;
    }
    window.removeEventListener("message", receive);
    event.source.postMessage(message, event.origin);
    window.close();
  }

  window.addEventListener("message", receive);

  if (window.opener) {
    window.opener.postMessage("authorizing:github", target);
  } else {
    document.body.textContent =
      "Login window lost its connection. Close this tab and try again.";
  }
})();
</script>
</body>
</html>`);
  } catch (error) {
    console.error("GitHub OAuth callback failed:", error.message);
    return respond(500, "An error occurred while completing GitHub login.");
  }
};

