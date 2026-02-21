// # Copyright (c) Liam Suorsa and Mika Suorsa
(function () {
  const form = document.querySelector('.apply-form');
  if (!form) {
    return;
  }

  const controls = form.querySelectorAll('input, textarea');

  function markValidity(control) {
    if (!control) return;
    const isValid = control.checkValidity();
    control.classList.toggle('input-error', !isValid);
    control.setAttribute('aria-invalid', String(!isValid));
  }

  controls.forEach((control) => {
    control.addEventListener('blur', () => markValidity(control));
    control.addEventListener('input', () => {
      if (control.classList.contains('input-error')) {
        markValidity(control);
      }
    });
    control.addEventListener('change', () => markValidity(control));
  });

  form.addEventListener('submit', (e) => {
    let hasInvalidControl = false;

    controls.forEach((control) => {
      markValidity(control);
      if (!control.checkValidity()) {
        hasInvalidControl = true;
      }
    });

    if (hasInvalidControl) {
      e.preventDefault();
    }
  });
})();
