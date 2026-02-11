// # Copyright (c) Liam Suorsa
(function(){
    var script = document.currentScript || document.getElementById('gtag-init');
    var measurementId = script ? script.getAttribute('data-measurement-id') : '';
    if(!measurementId){
        return;
    }

    window.dataLayer = window.dataLayer || [];
    function gtag(){window.dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', measurementId);
})();
// # Copyright (c) Liam Suorsa
