// # Copyright (c) Liam Suorsa and Mika Suorsa
'use strict';

window.addEventListener('DOMContentLoaded', () => {
    setupNavigationToggle();
    setupMotionEffects();
    setupCheckmarkAnimations();
});

function setupNavigationToggle() {
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
}

function setupMotionEffects() {
    const motionCandidates = document.querySelectorAll(
        '[data-motion], [data-motion-group], [data-motion-child]'
    );
    if (!motionCandidates.length || !document.body) {
        return;
    }

    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (reducedMotionQuery.matches) {
        return;
    }

    document.body.classList.add('has-motion');

    const motionTargets = [];
    const registeredElements = new Set();

    const registerTarget = (element, motionType, delayMs) => {
        if (!(element instanceof HTMLElement) || registeredElements.has(element)) {
            return;
        }
        registeredElements.add(element);
        element.classList.add('motion-ready');
        if (motionType === 'hero') {
            element.classList.add('motion-hero');
        }
        if (delayMs > 0) {
            element.style.setProperty('--motion-delay', `${delayMs}ms`);
        }
        motionTargets.push(element);
    };

    document.querySelectorAll('[data-motion]').forEach((element, index) => {
        const delayMs = Math.min(index * 45, 240);
        const motionType = element.dataset.motion || 'section';
        registerTarget(element, motionType, delayMs);
    });

    document.querySelectorAll('[data-motion-group]').forEach((group) => {
        const groupName = group.dataset.motionGroup || '';
        const baseDelay = groupName.startsWith('hero') ? 95 : 70;
        const children = Array.from(group.querySelectorAll('[data-motion-child]'));
        children.forEach((child, index) => {
            const delayMs = Math.min(index * baseDelay, 560);
            registerTarget(child, 'child', delayMs);
        });
    });

    const standaloneChildren = Array.from(document.querySelectorAll('[data-motion-child]')).filter(
        (element) => !element.closest('[data-motion-group]')
    );
    standaloneChildren.forEach((element, index) => {
        const delayMs = Math.min(index * 60, 300);
        registerTarget(element, 'child', delayMs);
    });

    if (!motionTargets.length) {
        return;
    }

    const showElement = (element) => {
        element.classList.add('is-visible');
    };

    if (!('IntersectionObserver' in window)) {
        motionTargets.forEach(showElement);
        return;
    }

    const observer = new IntersectionObserver(
        (entries, activeObserver) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                    return;
                }
                showElement(entry.target);
                activeObserver.unobserve(entry.target);
            });
        },
        {
            root: null,
            threshold: 0.14,
            rootMargin: '0px 0px -10% 0px',
        }
    );

    motionTargets.forEach((element) => {
        if (element.getBoundingClientRect().top <= window.innerHeight * 0.92) {
            showElement(element);
            return;
        }
        observer.observe(element);
    });
}


function setupCheckmarkAnimations() {
    const checkmarks = Array.from(document.querySelectorAll('.hero-check'));
    if (!checkmarks.length || !document.body) {
        return;
    }

    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (
        reducedMotionQuery.matches ||
        !('IntersectionObserver' in window) ||
        !('requestAnimationFrame' in window)
    ) {
        return;
    }

    let initializationScheduled = false;

    const initialize = () => {
        if (initializationScheduled || document.body.classList.contains('has-checkmark-motion')) {
            return;
        }

        const drawCheckmark = (checkmark) => {
            checkmark.classList.add('is-drawn');
        };

        let observer;
        try {
            observer = new IntersectionObserver(
                (entries, activeObserver) => {
                    entries.forEach((entry) => {
                        if (!entry.isIntersecting) {
                            return;
                        }
                        drawCheckmark(entry.target);
                        activeObserver.unobserve(entry.target);
                    });
                },
                {
                    root: null,
                    threshold: 0.6,
                    rootMargin: '0px 0px -5% 0px',
                }
            );
        } catch {
            return;
        }

        initializationScheduled = true;

        requestAnimationFrame(() => {
            if (reducedMotionQuery.matches) {
                observer.disconnect();
                return;
            }

            document.body.classList.add('has-checkmark-motion');

            requestAnimationFrame(() => {
                if (reducedMotionQuery.matches) {
                    document.body.classList.remove('has-checkmark-motion');
                    observer.disconnect();
                    return;
                }

                try {
                    checkmarks.forEach((checkmark) => observer.observe(checkmark));
                } catch {
                    document.body.classList.remove('has-checkmark-motion');
                    observer.disconnect();
                }
            });
        });
    };

    const baseStylesheet = document.querySelector(
        'link[rel="stylesheet"][href*="/static/css/base.css"]'
    );
    if (!(baseStylesheet instanceof HTMLLinkElement)) {
        return;
    }

    if (!baseStylesheet.sheet || baseStylesheet.media === 'print') {
        baseStylesheet.addEventListener('load', initialize, { once: true });
        return;
    }

    initialize();
}
