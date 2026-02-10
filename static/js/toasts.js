// # Copyright (c) Liam Suorsa
// Small script to show toasts and auto-hide them. Runs immediately — degrades gracefully if JS disabled.
(function(){
    function initToasts(){
        var container = document.querySelector('.toast-container');
        if(!container) return;
        var toasts = Array.prototype.slice.call(container.querySelectorAll('.toast'));
        toasts.forEach(function(t){
            // expose visually
            requestAnimationFrame(function(){ t.classList.add('show'); });
            // auto hide after 4s
            var hideTimer = setTimeout(function(){ hideToast(t); }, 4000);
            // allow manual close
            var btn = t.querySelector('.toast-close');
            if(btn){
                btn.addEventListener('click', function(){ clearTimeout(hideTimer); hideToast(t); });
            }
        });
    }
    function hideToast(t){
        t.classList.remove('show');
        // remove from DOM after transition
        t.addEventListener('transitionend', function(){ if(t.parentNode) t.parentNode.removeChild(t); });
    }
    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', initToasts);
    } else {
        initToasts();
    }
})();
// # Copyright (c) Liam Suorsa
