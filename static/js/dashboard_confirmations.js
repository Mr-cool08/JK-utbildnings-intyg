// # Copyright (c) Liam Suorsa
(function(){
    function dubbelBekraftelse(selector, forstaText, andraText){
        var formular = document.querySelectorAll(selector);
        formular.forEach(function(form){
            form.addEventListener('submit', function(event){
                if(!confirm(forstaText)){
                    event.preventDefault();
                    return;
                }
                if(!confirm(andraText)){
                    event.preventDefault();
                }
            });
        });
    }

    dubbelBekraftelse('[data-remove-connection]', 'Vill du ta bort kopplingen?', 'Är du helt säker? Företagskontot tappar åtkomst till dina intyg.');

    var taBortIntygFormular = document.querySelectorAll('[data-delete-pdf]');
    taBortIntygFormular.forEach(function(form){
        form.addEventListener('submit', function(event){
            if(!confirm('Är du säker på att du vill ta bort intyget? Detta går inte att ångra.')){
                event.preventDefault();
            }
        });
    });
})();
// # Copyright (c) Liam Suorsa
