(function () {
  const pdfLookupForm = document.getElementById('pdfLookupForm');
  const pdfLookupMessage = document.getElementById('pdfLookupMessage');
  const pdfResults = document.getElementById('pdfResults');
  const pdfResultBody = document.getElementById('pdfResultBody');
  const resetForm = document.getElementById('resetForm');
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

  function setMessageElement(element, text, isError) {
    if (!element) return;
    element.textContent = text || '';
    element.classList.toggle('error', Boolean(isError));
    element.style.display = text ? '' : 'none';
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

  function setLookupMessage(text, isError) {
    setMessageElement(pdfLookupMessage, text, isError);
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
      lastLookup = value;
      fetchOverview(value);
    });
  }

  if (resetForm) {
    resetForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!resetMessage) return;
      setMessageElement(resetMessage, 'Skickar återställningslänk…', false);
      const personnummer = document.getElementById('resetPersonnummer').value.trim();
      const email = document.getElementById('resetEmail').value.trim();
      try {
        const res = await fetch('/admin/api/skicka-aterstallning', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ personnummer, email })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte skicka återställning.');
        }
        setMessageElement(resetMessage, 'Återställningsmejl skickat.', false);
      } catch (err) {
        setMessageElement(resetMessage, err.message, true);
      }
    });
  }

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
        email: formData.get('email')?.toString().trim(),
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
    supervisorOverviewTitle.textContent = `Kopplade standardkonton för ${data.name || 'företagskonto'}`;

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
        nameCell.textContent = entry.username || 'Standardkonto';
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
      const emailInput = document.getElementById('overviewSupervisorEmail');
      const email = emailInput ? emailInput.value.trim() : '';
      setMessageElement(supervisorOverviewMessage, 'Hämtar kopplingar…', false);
      supervisorOverviewCard.hidden = true;
      try {
        const res = await fetch('/admin/api/foretagskonto/oversikt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
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
})();
