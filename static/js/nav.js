// # Copyright (c) Liam Suorsa and Mika Suorsa
'use strict';

window.addEventListener('DOMContentLoaded', () => {
    const toggle = document.querySelector('.nav-toggle');
    const navLinks = document.querySelector('.nav-links');

    if (!toggle || !navLinks) {
        return;
    }

    toggle.addEventListener('click', () => {
        const expanded = toggle.getAttribute('aria-expanded') === 'true';
        toggle.setAttribute('aria-expanded', String(!expanded));
        navLinks.classList.toggle('nav-links-open', !expanded);
    });

    navLinks.addEventListener('click', (event) => {
        if (!navLinks.classList.contains('nav-links-open')) {
            return;
        }

        const target = event.target;
        if (target instanceof HTMLAnchorElement) {
            toggle.setAttribute('aria-expanded', 'false');
            navLinks.classList.remove('nav-links-open');
        }
    });
});
