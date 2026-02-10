// # Copyright (c) Liam Suorsa
(function(){
    var formular = document.querySelectorAll('[data-supervisor-remove]');
    formular.forEach(function(form){
        form.addEventListener('submit', function(event){
            if(!confirm('Vill du ta bort kopplingen till användaren?')){
                event.preventDefault();
                return;
            }
            if(!confirm('Bekräfta borttagningen. Företagskontot förlorar åtkomst till intygen.')){
                event.preventDefault();
            }
        });
    });
})();
// # Copyright (c) Liam Suorsa
