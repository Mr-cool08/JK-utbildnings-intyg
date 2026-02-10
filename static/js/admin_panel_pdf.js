// # Copyright (c) Liam Suorsa
(() => {
  const pdfLookupForm = document.getElementById('pdfLookupForm');
  const pdfLookupMessage = document.getElementById('pdfLookupMessage');
  const pdfResults = document.getElementById('pdfResults');
  const pdfResultBody = document.getElementById('pdfResultBody');
  const storage = window.AdminPanelStorage;
  const apiClient = window.AdminApiClient;

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
      const data = await apiClient.apiPost(
        '/admin/api/oversikt',
        { personnummer },
        {
          context: 'Hämtade PDF-översikt',
          errorMessage: 'Kunde inte hämta uppgifter.',
        },
      );
      pdfResultBody.replaceChildren();
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
      await apiClient.apiPost(
        '/admin/api/uppdatera-pdf',
        { personnummer: lastLookup, pdf_id: pdfId, categories: newCategories },
        {
          context: 'Uppdaterade PDF-kategorier',
          errorMessage: 'Kunde inte uppdatera PDF.',
        },
      );
      setLookupMessage('Kategorier uppdaterade.', false);
      await fetchOverview(lastLookup);
    } catch (err) {
      setLookupMessage(err.message, true);
    }
  }

  async function deletePdf(pdfId) {
    setLookupMessage('Tar bort PDF…', false);
    try {
      await apiClient.apiPost(
        '/admin/api/radera-pdf',
        { personnummer: lastLookup, pdf_id: pdfId },
        {
          context: 'Raderade PDF',
          errorMessage: 'Kunde inte ta bort PDF.',
        },
      );
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
      if (storage) {
        storage.storeLastPersonnummer(value);
      }
      fetchOverview(value);
    });
  }
})();
// # Copyright (c) Liam Suorsa
