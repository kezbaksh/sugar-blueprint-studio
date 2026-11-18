
exports.handler = async () => {
  const clientId = process.env.GITHUB_CLIENT_ID;

  if (!clientId) {
    return {
      statusCode: 500,
      body: "GitHub OAuth is not configured yet."
    };
  }

  const authorizeUrl = new URL(
    "https://github.com/login/oauth/authorize"
  );

  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set(
    "redirect_uri",
    "https://sugarblueprintstudio.netlify.app/.netlify/functions/auth-callback"
  );
  authorizeUrl.searchParams.set("scope", "repo");

  return {
    statusCode: 302,
    headers: {
      Location: authorizeUrl.toString(),
      "Cache-Control": "no-store"
    },
    body: ""
  };
};
