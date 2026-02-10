// # Copyright (c) Liam Suorsa
// Show an immediate toast when the user submits the application form to improve UX.
// This does not change server behaviour — it only displays a local "sending" state
// while the browser performs the normal form submission/redirect.
(function(){
    var form = document.querySelector('.apply-form');
    if(!form) return;
    form.addEventListener('submit', function onSubmit(){
        try{
            // disable the submit button to avoid double submits
            var btn = form.querySelector('button[type=submit]');
            if(btn) { btn.disabled = true; btn.setAttribute('aria-disabled', 'true'); }

            // create or reuse toast container
            var container = document.querySelector('.toast-container');
            if(!container){
                container = document.createElement('div');
                container.className = 'toast-container';
                container.setAttribute('aria-live','polite');
                container.setAttribute('aria-atomic','true');
                document.body.appendChild(container);
            }

            // create a sending toast
            var toast = document.createElement('div');
            toast.className = 'toast info';
            toast.setAttribute('role','status');
            var msg = document.createElement('div');
            msg.className = 'toast-message';
            msg.textContent = 'Skickar ansökan…';
            var close = document.createElement('button');
            close.className = 'toast-close';
            close.setAttribute('aria-label','Stäng meddelande');
            close.textContent = '×';
            close.addEventListener('click', function(){ container.removeChild(toast); if(btn) btn.disabled = false; });
            toast.appendChild(msg);
            toast.appendChild(close);
            container.appendChild(toast);
            // animate in and auto-remove after 6s
            requestAnimationFrame(function(){ toast.classList.add('show'); });
            setTimeout(function(){ if(toast.parentNode) toast.parentNode.removeChild(toast); }, 6000);
        } catch(err){ return; }
        // allow the form to submit normally (do not call preventDefault)
    });
})();
// # Copyright (c) Liam Suorsa
