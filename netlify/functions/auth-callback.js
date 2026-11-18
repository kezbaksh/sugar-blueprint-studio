
const SITE_ORIGIN = "https://sugarblueprintstudio.netlify.app";

const headers = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
};

function response(message, token = null) {
  const payload = token
    ? { token, provider: "github" }
    : { error: message };

  const eventName = token ? "authorization:github:success" : "authorization:github:error";

  const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GitHub Login</title></head>
<body>
<p>Completing your secure login...</p>
<script>
(function () {
  const eventName = ${JSON.stringify(eventName)};
  const payload = ${JSON.stringify(payload).replace(/</g, "\\u003c")};
  const origin = ${JSON.stringify(SITE_ORIGIN)};

  function receiveMessage(event) {
    if (event.origin !== origin || event.data !== "authorizing:github") return;
    window.opener.postMessage(
      "authorization:github:" + (eventName.endsWith("success") ? "success" : "error") + ":" + JSON.stringify(payload),
      origin
    );
    window.removeEventListener("message", receiveMessage);
    window.close();
  }

  window.addEventListener("message", receiveMessage);
  if (window.opener) {
    window.opener.postMessage("authorizing:github", origin);
  } else {
    document.body.textContent = "Login window was not opened by the dashboard.";
  }
})();
</script>
</body></html>`;

  return { statusCode: 200, headers, body: html };
}

exports.handler = async (event) => {
  const { code, state, error } = event.queryStringParameters || {};

  if (error) return response("GitHub authorization was cancelled.");
  if (!code || !state) return response("Missing login information.");

  const cookies = event.headers.cookie || "";
  const match = cookies.match(/(?:^|;\s*)oauth_state=([^;]+)/);

  if (!match || match[1] !== state) {
    return response("Login verification failed. Please try again.");
  }

  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return response("GitHub OAuth credentials are missing.");
  }

  try {
    const result = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: SITE_ORIGIN + "/.netlify/functions/auth-callback"
      })
    });

    if (!result.ok) return response("GitHub login request failed.");

    const data = await result.json();

    if (!data.access_token) {
      return response("GitHub did not provide an access token.");
    }

    return response(null, data.access_token);
  } catch {
    return response("Unable to complete GitHub login.");
  }
};
