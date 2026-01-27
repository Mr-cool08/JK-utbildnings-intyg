// # Copyright (c) Liam Suorsa
(function () {
  const tableForm = document.getElementById('tableForm');
  const tableSelect = document.getElementById('tableSelect');
  const searchInput = document.getElementById('searchInput');
  const tableStatus = document.getElementById('tableStatus');
  const tableContainer = document.getElementById('tableContainer');
  const tableHead = document.getElementById('tableHead');
  const tableBody = document.getElementById('tableBody');
  const rowIdInput = document.getElementById('rowIdInput');
  const payloadInput = document.getElementById('payloadInput');
  const createBtn = document.getElementById('createBtn');
  const updateBtn = document.getElementById('updateBtn');
  const deleteBtn = document.getElementById('deleteBtn');
  const editorMessage = document.getElementById('editorMessage');
  let currentSchema = [];
  const allowedTables = new Set(
    Array.from(tableSelect?.options || [])
      .map((option) => option.value)
      .filter(Boolean)
  );

  async function sendClientLog(payload) {
    if (!payload) return;
    if (payload.url && payload.url.includes('/admin/api/klientlogg')) return;
    try {
      await fetch('/admin/api/klientlogg', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch {
      return;
    }
  }

  async function parseJsonResponse(response, context) {
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      sendClientLog({
        message: 'Svarade inte med JSON.',
        context,
        url: response.url,
        status: response.status,
        details: { contentType }
      });
      return null;
    }
    try {
      return await response.json();
    } catch {
      sendClientLog({
        message: 'Kunde inte tolka JSON.',
        context,
        url: response.url,
        status: response.status,
        details: { contentType }
      });
      return null;
    }
  }

  function buildUnexpectedFormatError() {
    return new Error('Servern svarade med ett oväntat format. Logga in igen och försök på nytt.');
  }

  function getSelectedTable() {
    const tableName = tableSelect.value;
    if (!allowedTables.has(tableName)) {
      throw new Error('Ogiltigt tabellval.');
    }
    return tableName;
  }

  function setTableStatus(message, isError) {
    if (!tableStatus) return;
    tableStatus.textContent = message || '';
    tableStatus.classList.toggle('error', Boolean(isError));
  }

  function setEditorMessage(message, isError) {
    if (!editorMessage) return;
    editorMessage.textContent = message || '';
    editorMessage.classList.toggle('error', Boolean(isError));
  }

  function renderTable(rows) {
    if (!Array.isArray(rows) || rows.length === 0) {
      tableContainer.hidden = true;
      setTableStatus('Inga poster att visa.', false);
      return;
    }
    if (currentSchema.length === 0) {
      currentSchema = Object.keys(rows[0]).map((name) => ({ name }));
    }
    tableHead.innerHTML = '';
    tableBody.innerHTML = '';

    const headRow = document.createElement('tr');
    currentSchema.forEach((column) => {
      const th = document.createElement('th');
      th.textContent = column.name;
      headRow.appendChild(th);
    });
    tableHead.appendChild(headRow);

    rows.forEach((row) => {
      const tr = document.createElement('tr');
      currentSchema.forEach((column) => {
        const td = document.createElement('td');
        const value = row[column.name];
        if (typeof value === 'string' && value.length > 120) {
          td.textContent = value.slice(0, 120) + '…';
        } else if (value === null || value === undefined) {
          td.textContent = '';
        } else {
          td.textContent = String(value);
        }
        tr.appendChild(td);
      });
      tableBody.appendChild(tr);
    });

    tableContainer.hidden = false;
    setTableStatus(`${rows.length} poster visade.`, false);
  }

  async function loadSchema(tableName) {
    const res = await fetch(`/admin/advanced/api/schema/${encodeURIComponent(tableName)}`);
    const data = await parseJsonResponse(res, 'Läste tabellschema');
    if (!data) {
      throw buildUnexpectedFormatError();
    }
    if (!res.ok) {
      throw new Error(data.message || 'Kunde inte läsa tabellens schema.');
    }
    currentSchema = data.schema || [];
    return currentSchema;
  }

  async function loadRows(tableName, searchTerm) {
    const params = new URLSearchParams();
    if (searchTerm) {
      params.set('sok', searchTerm);
    }
    const res = await fetch(`/admin/advanced/api/rows/${encodeURIComponent(tableName)}?${params.toString()}`);
    const data = await parseJsonResponse(res, 'Läste tabellrader');
    if (!data) {
      throw buildUnexpectedFormatError();
    }
    if (!res.ok) {
      throw new Error(data.message || 'Kunde inte läsa poster.');
    }
    renderTable(data.rows || []);
  }

  function parsePayload() {
    const raw = payloadInput.value.trim();
    if (!raw) {
      return {};
    }
    try {
      return JSON.parse(raw);
    } catch (err) {
      throw new Error('Ogiltigt JSON-format.');
    }
  }

  async function refresh() {
    let tableName;
    try {
      tableName = getSelectedTable();
    } catch (err) {
      setTableStatus(err.message, true);
      return;
    }
    setTableStatus('Laddar…', false);
    try {
      await loadSchema(tableName);
      await loadRows(tableName, searchInput.value.trim());
    } catch (err) {
      setTableStatus(err.message, true);
    }
  }

  if (tableForm) {
    tableForm.addEventListener('submit', (event) => {
      event.preventDefault();
      refresh();
    });
  }

  if (createBtn) {
    createBtn.addEventListener('click', async () => {
      setEditorMessage('Skapar rad…', false);
      try {
        const payload = parsePayload();
        const tableName = getSelectedTable();
        const res = await fetch(`/admin/advanced/api/rows/${encodeURIComponent(tableName)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await parseJsonResponse(res, 'Skapade tabellrad');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte skapa rad.');
        }
        setEditorMessage('Rad skapad.', false);
        payloadInput.value = '';
        await refresh();
      } catch (err) {
        setEditorMessage(err.message, true);
      }
    });
  }

  if (updateBtn) {
    updateBtn.addEventListener('click', async () => {
      setEditorMessage('Uppdaterar rad…', false);
      try {
        const payload = parsePayload();
        const id = Number(rowIdInput.value);
        if (!id) {
          throw new Error('Ange ett giltigt rad-ID.');
        }
        const tableName = getSelectedTable();
        const res = await fetch(`/admin/advanced/api/rows/${encodeURIComponent(tableName)}/${id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await parseJsonResponse(res, 'Uppdaterade tabellrad');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte uppdatera rad.');
        }
        setEditorMessage('Rad uppdaterad.', false);
        await refresh();
      } catch (err) {
        setEditorMessage(err.message, true);
      }
    });
  }

  if (deleteBtn) {
    deleteBtn.addEventListener('click', async () => {
      setEditorMessage('Tar bort rad…', false);
      try {
        const id = Number(rowIdInput.value);
        if (!id) {
          throw new Error('Ange ett giltigt rad-ID.');
        }
        const tableName = getSelectedTable();
        const res = await fetch(`/admin/advanced/api/rows/${encodeURIComponent(tableName)}/${id}`, {
          method: 'DELETE'
        });
        const data = await parseJsonResponse(res, 'Tog bort tabellrad');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte ta bort rad.');
        }
        setEditorMessage('Rad borttagen.', false);
        await refresh();
      } catch (err) {
        setEditorMessage(err.message, true);
      }
    });
  }

  if (tableSelect) {
    tableSelect.addEventListener('change', () => {
      payloadInput.value = '';
      rowIdInput.value = '';
      setEditorMessage('', false);
      refresh();
    });
  }

  if (tableSelect && tableSelect.value) {
    refresh();
  }
})();
