(function () {
  const pdfLookupForm = document.getElementById('pdfLookupForm');
  const pdfLookupMessage = document.getElementById('pdfLookupMessage');
  const pdfResults = document.getElementById('pdfResults');
  const pdfResultBody = document.getElementById('pdfResultBody');
  const resetForm = document.getElementById('resetForm');
  const resetMessage = document.getElementById('resetMessage');
  const categories = Array.isArray(window.APP_CATEGORIES) ? window.APP_CATEGORIES : [];
  let lastLookup = '';

  function setLookupMessage(text, isError) {
    if (!pdfLookupMessage) return;
    pdfLookupMessage.textContent = text || '';
    pdfLookupMessage.classList.toggle('error', Boolean(isError));
  }

  function renderCategoryOptions(selected) {
    const select = document.createElement('select');
    select.multiple = true;
    select.className = 'category-select';
    const selectedSet = new Set(selected || []);
    categories.forEach(([slug, label]) => {
      const option = document.createElement('option');
      option.value = slug;
      option.textContent = label;
      option.selected = selectedSet.has(slug);
      select.appendChild(option);
    });
    return select;
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
    const select = renderCategoryOptions(pdf.categories);
    categoryCell.appendChild(select);
    tr.appendChild(categoryCell);

    const uploadedCell = document.createElement('td');
    uploadedCell.textContent = pdf.uploaded_at ? new Date(pdf.uploaded_at).toLocaleString('sv-SE') : '';
    tr.appendChild(uploadedCell);

    const actionsCell = document.createElement('td');
    const saveBtn = document.createElement('button');
    saveBtn.type = 'button';
    saveBtn.textContent = 'Spara kategorier';
    saveBtn.addEventListener('click', async () => {
      await updatePdf(pdf.id, Array.from(select.selectedOptions).map((o) => o.value));
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
      resetMessage.textContent = 'Skickar återställningslänk…';
      resetMessage.classList.remove('error');
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
        resetMessage.textContent = 'Återställningsmejl skickat.';
      } catch (err) {
        resetMessage.textContent = err.message;
        resetMessage.classList.add('error');
      }
    });
  }
})();
