// # Copyright (c) Liam Suorsa and Mika Suorsa
(() => {
  const STORAGE_KEY = 'admin_last_personnummer';

  function storeLastPersonnummer(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) {
      try {
        window.sessionStorage.removeItem(STORAGE_KEY);
      } catch (err) {}
      return;
    }
    try {
      window.sessionStorage.setItem(STORAGE_KEY, trimmed);
    } catch (err) {}
  }

  function loadLastPersonnummer() {
    try {
      return window.sessionStorage.getItem(STORAGE_KEY) || '';
    } catch (err) {
      return '';
    }
  }

  window.AdminPanelStorage = {
    storeLastPersonnummer,
    loadLastPersonnummer,
  };
})();
// # Copyright (c) Liam Suorsa and Mika Suorsa
