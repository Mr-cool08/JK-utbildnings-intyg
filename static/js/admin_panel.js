// # Copyright (c) Liam Suorsa
(function () {
  const pdfLookupForm = document.getElementById('pdfLookupForm');
  const pdfLookupMessage = document.getElementById('pdfLookupMessage');
  const pdfResults = document.getElementById('pdfResults');
  const pdfResultBody = document.getElementById('pdfResultBody');
  const resetForm = document.getElementById('resetForm');
  const resetAccountType = document.getElementById('resetAccountType');
  const resetPersonnummerRow = document.getElementById('resetPersonnummerRow');
  const resetMessage = document.getElementById('resetMessage');
  const createSupervisorForm = document.getElementById('createSupervisorForm');
  const createSupervisorMessage = document.getElementById('createSupervisorMessage');
  const linkSupervisorForm = document.getElementById('linkSupervisorForm');
  const linkSupervisorMessage = document.getElementById('linkSupervisorMessage');
  const supervisorOverviewForm = document.getElementById('supervisorOverviewForm');
  const supervisorOverviewMessage = document.getElementById('supervisorOverviewMessage');
  const supervisorOverviewCard = document.getElementById('supervisorOverviewCard');
  const supervisorOverviewBody = document.getElementById('supervisorOverviewBody');
  const supervisorOverviewTitle = document.getElementById('supervisorOverviewTitle');
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

  function normalizeCategories(list) {
    if (!Array.isArray(list)) return [];
    const normalized = [];
    const seen = new Set();
    list.forEach((entry) => {
      let slug;
      let label;
      if (Array.isArray(entry) && entry.length >= 2) {
        [slug, label] = entry;
      } else if (entry && typeof entry === 'object') {
        ({ slug, label } = entry);
      }
      if (typeof slug === 'string' && typeof label === 'string') {
        const trimmedSlug = slug.trim();
        const trimmedLabel = label.trim();
        if (trimmedSlug && trimmedLabel && !seen.has(trimmedSlug)) {
          normalized.push({ slug: trimmedSlug, label: trimmedLabel });
          seen.add(trimmedSlug);
        }
      }
    });
    return normalized;
  }

  let categories = normalizeCategories(window.APP_CATEGORIES);
  let lastLookup = '';
  let pendingDeletePersonnummer = '';
  const LAST_PERSONNUMMER_KEY = 'admin_last_personnummer';

  function setLookupMessage(text, isError) {
    setMessageElement(pdfLookupMessage, text, isError);
  }

  function setToolsMessage(text, isError) {
    setMessageElement(adminToolsMessage, text, isError);
  }

  function storeLastPersonnummer(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) {
      lastLookup = '';
      try {
        window.sessionStorage.removeItem(LAST_PERSONNUMMER_KEY);
      } catch (err) {}
      return;
    }
    lastLookup = trimmed;
    try {
      window.sessionStorage.setItem(LAST_PERSONNUMMER_KEY, trimmed);
    } catch (err) {}
  }

  function loadLastPersonnummer() {
    if (lastLookup) return lastLookup;
    try {
      const stored = window.sessionStorage.getItem(LAST_PERSONNUMMER_KEY) || '';
      if (stored) {
        lastLookup = stored;
        return stored;
      }
    } catch (err) {}
    return '';
  }

  function renderCategoryOptions(selected) {
    const normalizedSelected = new Set(selected || []);

    if (!categories.length) {
      const span = document.createElement('span');
      span.className = 'category-empty';
      span.textContent = 'Inga kategorier tillgängliga.';
      return { control: span, disabled: true };
    }

    const select = document.createElement('select');
    select.multiple = true;
    select.className = 'category-select';
    select.size = Math.min(6, Math.max(3, categories.length));

    categories.forEach(({ slug, label }) => {
      const option = document.createElement('option');
      option.value = slug;
      option.textContent = label;
      option.selected = normalizedSelected.has(slug);
      select.appendChild(option);
    });

    return { control: select, disabled: false };
  }

  function renderPdfRow(pdf) {
    const tr = document.createElement('tr');
    const idCell = document.createElement('td');
    idCell.textContent = String(pdf.id);
    tr.appendChild(idCell);

    const fileCell = document.createElement('td');
    fileCell.textContent = pdf.filename;
    tr.appendChild(fileCell);

    const categoryCell = document.createElement('td');
    const { control, disabled } = renderCategoryOptions(pdf.categories);
    categoryCell.appendChild(control);
    tr.appendChild(categoryCell);

    const uploadedCell = document.createElement('td');
    uploadedCell.textContent = pdf.uploaded_at ? new Date(pdf.uploaded_at).toLocaleString('sv-SE') : '';
    tr.appendChild(uploadedCell);

    const actionsCell = document.createElement('td');
    const saveBtn = document.createElement('button');
    saveBtn.type = 'button';
    saveBtn.textContent = 'Spara kategorier';
    saveBtn.disabled = disabled;
    saveBtn.title = disabled ? 'Inga kategorier har konfigurerats.' : '';
    saveBtn.addEventListener('click', async () => {
      if (disabled) return;
      const selectedValues = Array.from(control.selectedOptions).map((o) => o.value);
      await updatePdf(pdf.id, selectedValues);
    });
    const deleteBtn = document.createElement('button');
    deleteBtn.type = 'button';
    deleteBtn.className = 'danger';
    deleteBtn.textContent = 'Ta bort PDF';
    deleteBtn.addEventListener('click', async () => {
      if (!window.confirm('Är du säker på att du vill ta bort PDF:en?')) {
        return;
      }
      await deletePdf(pdf.id);
    });

    actionsCell.appendChild(saveBtn);
    actionsCell.appendChild(deleteBtn);
    tr.appendChild(actionsCell);
    return tr;
  }

  async function fetchOverview(personnummer) {
    setLookupMessage('Hämtar uppgifter…', false);
    try {
      const res = await fetch('/admin/api/oversikt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ personnummer })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Kunde inte hämta uppgifter.');
      }
      pdfResultBody.innerHTML = '';
      if (!data.data || !Array.isArray(data.data.pdfs) || data.data.pdfs.length === 0) {
        setLookupMessage('Inga PDF:er hittades för angivet personnummer.', false);
        pdfResults.hidden = true;
        return;
      }
      categories = normalizeCategories(data.data.categories);
      data.data.pdfs.forEach((pdf) => {
        pdfResultBody.appendChild(renderPdfRow(pdf));
      });
      pdfResults.hidden = false;
      setLookupMessage('PDF:er hämtade.', false);
    } catch (err) {
      pdfResults.hidden = true;
      setLookupMessage(err.message, true);
    }
  }

  async function updatePdf(pdfId, newCategories) {
    setLookupMessage('Sparar kategorier…', false);
    try {
      const res = await fetch('/admin/api/uppdatera-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ personnummer: lastLookup, pdf_id: pdfId, categories: newCategories })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Kunde inte uppdatera PDF.');
      }
      setLookupMessage('Kategorier uppdaterade.', false);
      await fetchOverview(lastLookup);
    } catch (err) {
      setLookupMessage(err.message, true);
    }
  }

  async function deletePdf(pdfId) {
    setLookupMessage('Tar bort PDF…', false);
    try {
      const res = await fetch('/admin/api/radera-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ personnummer: lastLookup, pdf_id: pdfId })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Kunde inte ta bort PDF.');
      }
      setLookupMessage('PDF borttagen.', false);
      await fetchOverview(lastLookup);
    } catch (err) {
      setLookupMessage(err.message, true);
    }
  }

  if (pdfLookupForm) {
    pdfLookupForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const input = document.getElementById('lookupPersonnummer');
      if (!input) return;
      const value = input.value.trim();
      if (!value) {
        setLookupMessage('Ange ett personnummer.', true);
        return;
      }
      storeLastPersonnummer(value);
      fetchOverview(value);
    });
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

  if (deleteAccountForm) {
    deleteAccountForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const input = document.getElementById('deletePersonnummer');
      const personnummer = input ? input.value.trim() : '';
      if (!personnummer) {
        setMessageElement(deleteAccountMessage, 'Ange ett personnummer.', true);
        return;
      }
      storeLastPersonnummer(personnummer);
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

  function getLastPersonnummer() {
    const stored = loadLastPersonnummer();
    if (!stored) {
      setToolsMessage(
        'Sök först upp ett personnummer via PDF-översikten eller något av formulären.',
        true,
      );
      return '';
    }
    return stored;
  }

  if (fillLastPersonnummerBtn) {
    fillLastPersonnummerBtn.addEventListener('click', () => {
      const personnummer = getLastPersonnummer();
      if (!personnummer) return;
      const targets = document.querySelectorAll('[data-personnummer-target="true"]');
      targets.forEach((input) => {
        input.value = personnummer;
      });
      setToolsMessage('Personnummer ifyllda.', false);
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
        setToolsMessage('Personnummer kopierat.', false);
      } catch (err) {
        setToolsMessage('Kunde inte kopiera personnummer.', true);
      }
    });
  }

  if (clearAdminFormsBtn) {
    clearAdminFormsBtn.addEventListener('click', () => {
      document.querySelectorAll('form').forEach((form) => form.reset());
      [
        pdfLookupMessage,
        resetMessage,
        createSupervisorMessage,
        linkSupervisorMessage,
        supervisorOverviewMessage,
        verifyCertificateMessage,
        deleteAccountMessage,
      ].forEach((element) => {
        if (element) {
          setMessageElement(element, '', false);
        }
      });
      if (pdfResults) {
        pdfResults.hidden = true;
      }
      if (supervisorOverviewCard) {
        supervisorOverviewCard.hidden = true;
      }
      setToolsMessage('Formulär rensade.', false);
    });
  }

  document.querySelectorAll('[data-personnummer-target="true"]').forEach((input) => {
    input.addEventListener('blur', (event) => {
      storeLastPersonnummer(event.target.value);
    });
  });

  if (createSupervisorForm) {
    setMessageElement(createSupervisorMessage, '', false);
    createSupervisorForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!createSupervisorMessage) return;
      const formData = new FormData(createSupervisorForm);
      const payload = {
        name: formData.get('name')?.toString().trim(),
        email: formData.get('email')?.toString().trim(),
      };
      setMessageElement(createSupervisorMessage, 'Skapar företagskonto…', false);
      try {
        const res = await fetch('/admin/api/foretagskonto/skapa', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte skapa företagskonto.');
        }
        setMessageElement(
          createSupervisorMessage,
          data.message || 'Företagskonto skapat.',
          false,
        );
        createSupervisorForm.reset();
      } catch (err) {
        setMessageElement(createSupervisorMessage, err.message, true);
      }
    });
  }

  if (linkSupervisorForm) {
    setMessageElement(linkSupervisorMessage, '', false);
    linkSupervisorForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!linkSupervisorMessage) return;
      const formData = new FormData(linkSupervisorForm);
      const payload = {
        orgnr: formData.get('orgnr')?.toString().trim(),
        personnummer: formData.get('personnummer')?.toString().trim(),
      };
      setMessageElement(linkSupervisorMessage, 'Skapar koppling…', false);
      try {
        const res = await fetch('/admin/api/foretagskonto/koppla', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte skapa koppling.');
        }
        setMessageElement(
          linkSupervisorMessage,
          data.message || 'Kopplingen har sparats.',
          false,
        );
        linkSupervisorForm.reset();
      } catch (err) {
        setMessageElement(linkSupervisorMessage, err.message, true);
      }
    });
  }

  function renderSupervisorOverview(data) {
    if (!supervisorOverviewCard || !supervisorOverviewBody || !supervisorOverviewTitle) {
      return;
    }
    supervisorOverviewBody.innerHTML = '';
    const connections = Array.isArray(data.connections) ? data.connections : [];
    supervisorOverviewTitle.textContent = `Kopplade användarkonton för ${data.name || 'företagskonto'}`;

    if (!connections.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 2;
      cell.textContent = 'Inga kopplingar hittades.';
      row.appendChild(cell);
      supervisorOverviewBody.appendChild(row);
    } else {
      connections.forEach((entry) => {
        const row = document.createElement('tr');
        const nameCell = document.createElement('td');
        nameCell.textContent = entry.username || 'Användarkonto';
        const infoCell = document.createElement('td');
        const hash = entry.personnummer_hash || '';
        const label = document.createElement('span');
        label.textContent = 'Hash: ';
        infoCell.appendChild(label);
        const code = document.createElement('code');
        code.textContent = hash ? `${hash.slice(0, 12)}…` : 'saknas';
        infoCell.appendChild(code);
        row.appendChild(nameCell);
        row.appendChild(infoCell);
        supervisorOverviewBody.appendChild(row);
      });
    }

    supervisorOverviewCard.hidden = false;
  }

  if (supervisorOverviewForm) {
    setMessageElement(supervisorOverviewMessage, '', false);
    supervisorOverviewCard.hidden = true;
    supervisorOverviewForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!supervisorOverviewMessage) return;
      const orgnrInput = document.getElementById('overviewSupervisorOrgnr');
      const orgnr = orgnrInput ? orgnrInput.value.trim() : '';
      setMessageElement(supervisorOverviewMessage, 'Hämtar kopplingar…', false);
      supervisorOverviewCard.hidden = true;
      try {
        const res = await fetch('/admin/api/foretagskonto/oversikt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ orgnr }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte hämta kopplingar.');
        }
        renderSupervisorOverview(data.data || {});
        setMessageElement(supervisorOverviewMessage, 'Kopplingar hämtade.', false);
      } catch (err) {
        supervisorOverviewCard.hidden = true;
        setMessageElement(supervisorOverviewMessage, err.message, true);
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
})();
