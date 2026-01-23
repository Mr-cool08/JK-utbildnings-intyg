// # Copyright (c) Liam Suorsa
(() => {
  const resetForm = document.getElementById('resetForm');
  const resetAccountType = document.getElementById('resetAccountType');
  const resetPersonnummerRow = document.getElementById('resetPersonnummerRow');
  const resetMessage = document.getElementById('resetMessage');
  const verifyCertificateForm = document.getElementById('verifyCertificateForm');
  const verifyCertificateMessage = document.getElementById('verifyCertificateMessage');
  const deleteAccountForm = document.getElementById('deleteAccountForm');
  const deleteAccountMessage = document.getElementById('deleteAccountMessage');
  const deleteAccountDialog = document.getElementById('deleteAccountDialog');
  const deleteAccountPersonnummerPreview = document.getElementById(
    'deleteAccountPersonnummerPreview',
  );
  const confirmDeleteAccountBtn = document.getElementById('confirmDeleteAccount');
  const cancelDeleteAccountBtn = document.getElementById('cancelDeleteAccount');
  const fillLastPersonnummerBtn = document.getElementById('fillLastPersonnummerBtn');
  const copyLastPersonnummerBtn = document.getElementById('copyLastPersonnummerBtn');
  const clearAdminFormsBtn = document.getElementById('clearAdminFormsBtn');
  const adminToolsMessage = document.getElementById('adminToolsMessage');
  const csrfToken = document.querySelector('[data-csrf-token]')?.dataset.csrfToken || '';
  const storage = window.AdminPanelStorage;

  function setMessageElement(element, text, isError) {
    if (!element) return;
    element.textContent = text || '';
    element.classList.toggle('error', Boolean(isError));
    element.style.display = text ? '' : 'none';
  }

  function setMessageWithLink(element, text, link) {
    if (!element) return;
    element.textContent = '';
    element.classList.remove('error');
    if (text) {
      element.appendChild(document.createTextNode(text));
    }
    if (link) {
      const spacer = document.createTextNode(' ');
      element.appendChild(spacer);
      const anchor = document.createElement('a');
      anchor.href = link;
      anchor.textContent = 'Öppna återställningslänken';
      anchor.target = '_blank';
      anchor.rel = 'noopener';
      element.appendChild(anchor);
    }
    element.style.display = text || link ? '' : 'none';
  }

  function getLastPersonnummer() {
    const stored = storage ? storage.loadLastPersonnummer() : '';
    if (!stored) {
      setMessageElement(
        adminToolsMessage,
        'Sök först upp ett personnummer via PDF-översikten eller något av formulären.',
        true,
      );
      return '';
    }
    return stored;
  }

  function formatDeleteSummary(summary) {
    if (!summary || typeof summary !== 'object') {
      return '';
    }
    const parts = [];
    if (summary.users) {
      parts.push(`${summary.users} konto`);
    }
    if (summary.pending_users) {
      parts.push(`${summary.pending_users} väntande konto`);
    }
    if (summary.pdfs) {
      parts.push(`${summary.pdfs} PDF:er`);
    }
    if (summary.supervisor_connections) {
      parts.push(`${summary.supervisor_connections} kopplingar`);
    }
    if (summary.supervisor_link_requests) {
      parts.push(`${summary.supervisor_link_requests} kopplingsförfrågningar`);
    }
    if (summary.password_resets) {
      parts.push(`${summary.password_resets} återställningar`);
    }
    if (summary.company_users) {
      parts.push(`${summary.company_users} företagsanvändare`);
    }
    if (summary.applications) {
      parts.push(`${summary.applications} ansökningar`);
    }
    if (!parts.length) {
      return '';
    }
    return `Raderade: ${parts.join(', ')}.`;
  }

  async function deleteAccount(personnummer) {
    setMessageElement(deleteAccountMessage, 'Raderar konto…', false);
    try {
      const res = await fetch('/admin/api/radera-konto', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {})
        },
        body: JSON.stringify({
          personnummer,
          ...(csrfToken ? { csrf_token: csrfToken } : {})
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Kunde inte radera kontot.');
      }
      const summaryText = formatDeleteSummary(data.data);
      setMessageElement(
        deleteAccountMessage,
        summaryText
          ? `${data.message || 'Kontot har raderats.'} ${summaryText}`
          : data.message || 'Kontot har raderats.',
        false,
      );
      if (deleteAccountForm) {
        deleteAccountForm.reset();
      }
    } catch (err) {
      setMessageElement(deleteAccountMessage, err.message, true);
    }
  }

  let pendingDeletePersonnummer = '';

  if (deleteAccountForm) {
    deleteAccountForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const input = document.getElementById('deletePersonnummer');
      const personnummer = input ? input.value.trim() : '';
      if (!personnummer) {
        setMessageElement(deleteAccountMessage, 'Ange ett personnummer.', true);
        return;
      }
      if (storage) {
        storage.storeLastPersonnummer(personnummer);
      }
      pendingDeletePersonnummer = personnummer;
      if (deleteAccountPersonnummerPreview) {
        deleteAccountPersonnummerPreview.textContent = personnummer;
      }
      if (deleteAccountDialog && typeof deleteAccountDialog.showModal === 'function') {
        deleteAccountDialog.showModal();
        return;
      }
      if (
        window.confirm(
          'Är du säker på att du vill radera kontot? Alla kopplade data tas bort.',
        )
      ) {
        deleteAccount(personnummer);
      } else {
        pendingDeletePersonnummer = '';
        if (deleteAccountPersonnummerPreview) {
          deleteAccountPersonnummerPreview.textContent = '';
        }
      }
    });
  }

  if (confirmDeleteAccountBtn) {
    confirmDeleteAccountBtn.addEventListener('click', () => {
      const personnummer = pendingDeletePersonnummer;
      if (deleteAccountDialog && deleteAccountDialog.open) {
        deleteAccountDialog.close();
      }
      if (personnummer) {
        deleteAccount(personnummer);
      }
    });
  }

  if (cancelDeleteAccountBtn) {
    cancelDeleteAccountBtn.addEventListener('click', () => {
      if (deleteAccountDialog && deleteAccountDialog.open) {
        deleteAccountDialog.close();
      }
      pendingDeletePersonnummer = '';
    });
  }

  if (deleteAccountDialog) {
    deleteAccountDialog.addEventListener('close', () => {
      pendingDeletePersonnummer = '';
    });
  }

  if (resetForm) {
    const resetPersonnummerInput = document.getElementById('resetPersonnummer');
    const resetEmailInput = document.getElementById('resetEmail');

    const updateResetFields = () => {
      if (!resetAccountType || !resetPersonnummerRow || !resetPersonnummerInput || !resetEmailInput) {
        return;
      }
      const type = resetAccountType.value;
      const isForetagskonto = type === 'foretagskonto';
      resetPersonnummerRow.hidden = isForetagskonto;
      resetPersonnummerInput.required = !isForetagskonto;
      resetEmailInput.placeholder = isForetagskonto ? 'foretagskonto@example.com' : 'user@example.com';
    };

    if (resetAccountType) {
      resetAccountType.addEventListener('change', updateResetFields);
    }
    updateResetFields();

    resetForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!resetMessage) return;
      setMessageElement(resetMessage, 'Skickar återställningslänk…', false);
      const personnummer = resetPersonnummerInput ? resetPersonnummerInput.value.trim() : '';
      const email = resetEmailInput ? resetEmailInput.value.trim() : '';
      const accountType = resetAccountType ? resetAccountType.value : 'standard';
      if (storage && personnummer) {
        storage.storeLastPersonnummer(personnummer);
      }
      try {
        const res = await fetch('/admin/api/skicka-aterstallning', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ personnummer, email, account_type: accountType })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte skicka återställning.');
        }
        setMessageWithLink(resetMessage, data.message || 'Återställningsmejl skickat.', data.link);
      } catch (err) {
        setMessageElement(resetMessage, err.message, true);
      }
    });
  }

  if (verifyCertificateForm) {
    setMessageElement(verifyCertificateMessage, '', false);
    verifyCertificateForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!verifyCertificateMessage) return;
      const personnummerInput = document.getElementById('verifyPersonnummer');
      const personnummer = personnummerInput ? personnummerInput.value.trim() : '';
      if (!personnummer) {
        setMessageElement(verifyCertificateMessage, 'Ange personnummer.', true);
        return;
      }
      if (storage) {
        storage.storeLastPersonnummer(personnummer);
      }
      setMessageElement(verifyCertificateMessage, 'Verifierar…', false);
      try {
        const res = await fetch(`/verify_certificate/${encodeURIComponent(personnummer)}`);
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte verifiera certifikat.');
        }
        if (data.verified) {
          setMessageElement(verifyCertificateMessage, 'Standardkontots certifikat är verifierat.', false);
        } else {
          setMessageElement(verifyCertificateMessage, 'Standardkontots certifikat är inte verifierat.', true);
        }
      } catch (err) {
        setMessageElement(verifyCertificateMessage, err.message, true);
      }
    });
  }

  if (fillLastPersonnummerBtn) {
    fillLastPersonnummerBtn.addEventListener('click', () => {
      const personnummer = getLastPersonnummer();
      if (!personnummer) return;
      const targets = document.querySelectorAll('[data-personnummer-target="true"]');
      targets.forEach((input) => {
        input.value = personnummer;
      });
      setMessageElement(adminToolsMessage, 'Personnummer ifyllda.', false);
    });
  }

  if (copyLastPersonnummerBtn) {
    copyLastPersonnummerBtn.addEventListener('click', async () => {
      const personnummer = getLastPersonnummer();
      if (!personnummer) return;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(personnummer);
        } else {
          const tempInput = document.createElement('input');
          tempInput.value = personnummer;
          document.body.appendChild(tempInput);
          tempInput.select();
          document.execCommand('copy');
          document.body.removeChild(tempInput);
        }
        setMessageElement(adminToolsMessage, 'Personnummer kopierat.', false);
      } catch (err) {
        setMessageElement(adminToolsMessage, 'Kunde inte kopiera personnummer.', true);
      }
    });
  }

  if (clearAdminFormsBtn) {
    clearAdminFormsBtn.addEventListener('click', () => {
      document.querySelectorAll('form').forEach((form) => form.reset());
      [
        resetMessage,
        verifyCertificateMessage,
        deleteAccountMessage,
      ].forEach((element) => {
        if (element) {
          setMessageElement(element, '', false);
        }
      });
      setMessageElement(adminToolsMessage, 'Formulär rensade.', false);
    });
  }
})();
// # Copyright (c) Liam Suorsa
