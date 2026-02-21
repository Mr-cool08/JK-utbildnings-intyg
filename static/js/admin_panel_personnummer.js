// # Copyright (c) Liam Suorsa and Mika Suorsa
(() => {
  const storage = window.AdminPanelStorage;
  if (!storage) return;

  document.querySelectorAll('[data-personnummer-target="true"]').forEach((input) => {
    input.addEventListener('blur', (event) => {
      storage.storeLastPersonnummer(event.target.value);
    });
  });
})();
// # Copyright (c) Liam Suorsa and Mika Suorsa
