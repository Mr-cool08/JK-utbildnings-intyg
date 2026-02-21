// # Copyright (c) Liam Suorsa and Mika Suorsa
(() => {
  const createSupervisorForm = document.getElementById('createSupervisorForm');
  const createSupervisorMessage = document.getElementById('createSupervisorMessage');
  const linkSupervisorForm = document.getElementById('linkSupervisorForm');
  const linkSupervisorMessage = document.getElementById('linkSupervisorMessage');
  const removeSupervisorForm = document.getElementById('removeSupervisorForm');
  const removeSupervisorMessage = document.getElementById('removeSupervisorMessage');
  const changeSupervisorForm = document.getElementById('changeSupervisorForm');
  const changeSupervisorMessage = document.getElementById('changeSupervisorMessage');
  const deleteSupervisorForm = document.getElementById('deleteSupervisorForm');
  const deleteSupervisorMessage = document.getElementById('deleteSupervisorMessage');
  const supervisorOverviewForm = document.getElementById('supervisorOverviewForm');
  const supervisorOverviewMessage = document.getElementById('supervisorOverviewMessage');
  const supervisorOverviewCard = document.getElementById('supervisorOverviewCard');
  const supervisorOverviewBody = document.getElementById('supervisorOverviewBody');
  const supervisorOverviewTitle = document.getElementById('supervisorOverviewTitle');
  const csrfToken = document.querySelector('[data-csrf-token]')?.dataset.csrfToken || '';
  let currentOverviewOrgnr = '';

  function setMessageElement(element, text, isError) {
    if (!element) return;
    element.textContent = text || '';
    element.classList.toggle('error', Boolean(isError));
    element.style.display = text ? '' : 'none';
  }

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
        const data = await parseJsonResponse(res, 'Skapade företagskonto');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
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
        const data = await parseJsonResponse(res, 'Skapade koppling');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
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

  if (removeSupervisorForm) {
    setMessageElement(removeSupervisorMessage, '', false);
    removeSupervisorForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!removeSupervisorMessage) return;
      const formData = new FormData(removeSupervisorForm);
      const payload = {
        orgnr: formData.get('orgnr')?.toString().trim(),
        personnummer: formData.get('personnummer')?.toString().trim(),
      };
      setMessageElement(removeSupervisorMessage, 'Tar bort koppling…', false);
      try {
        const res = await fetch('/admin/api/foretagskonto/ta-bort', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
          },
          body: JSON.stringify({
            ...payload,
            ...(csrfToken ? { csrf_token: csrfToken } : {}),
          }),
        });
        const data = await parseJsonResponse(res, 'Tog bort koppling');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte ta bort kopplingen.');
        }
        setMessageElement(
          removeSupervisorMessage,
          data.message || 'Kopplingen har tagits bort.',
          false,
        );
        removeSupervisorForm.reset();
      } catch (err) {
        setMessageElement(removeSupervisorMessage, err.message, true);
      }
    });
  }

  if (changeSupervisorForm) {
    setMessageElement(changeSupervisorMessage, '', false);
    changeSupervisorForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!changeSupervisorMessage) return;
      const formData = new FormData(changeSupervisorForm);
      const payload = {
        from_orgnr: formData.get('from_orgnr')?.toString().trim(),
        to_orgnr: formData.get('to_orgnr')?.toString().trim(),
        personnummer: formData.get('personnummer')?.toString().trim(),
      };
      setMessageElement(changeSupervisorMessage, 'Uppdaterar koppling…', false);
      try {
        const res = await fetch('/admin/api/foretagskonto/uppdatera-koppling', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
          },
          body: JSON.stringify({
            ...payload,
            ...(csrfToken ? { csrf_token: csrfToken } : {}),
          }),
        });
        const data = await parseJsonResponse(res, 'Uppdaterade koppling');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte uppdatera kopplingen.');
        }
        setMessageElement(
          changeSupervisorMessage,
          data.message || 'Kopplingen har uppdaterats.',
          false,
        );
        changeSupervisorForm.reset();
      } catch (err) {
        setMessageElement(changeSupervisorMessage, err.message, true);
      }
    });
  }

  function updateOverviewEmptyState() {
    if (!supervisorOverviewBody) return;
    if (supervisorOverviewBody.children.length > 0) return;
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 3;
    cell.textContent = 'Inga kopplingar hittades.';
    row.appendChild(cell);
    supervisorOverviewBody.appendChild(row);
  }

  async function removeOverviewConnection(personnummerHash, username) {
    if (!currentOverviewOrgnr) {
      setMessageElement(
        supervisorOverviewMessage,
        'Välj först ett företagskonto att visa.',
        true,
      );
      return;
    }
    const label = username || 'det valda kontot';
    const confirmed = window.confirm(`Vill du ta bort kopplingen för ${label}?`);
    if (!confirmed) return;
    setMessageElement(supervisorOverviewMessage, 'Tar bort koppling…', false);
    try {
      const res = await fetch('/admin/api/foretagskonto/ta-bort', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
        },
        body: JSON.stringify({
          orgnr: currentOverviewOrgnr,
          personnummer_hash: personnummerHash,
          ...(csrfToken ? { csrf_token: csrfToken } : {}),
        }),
      });
      const data = await parseJsonResponse(res, 'Tog bort koppling i översikt');
      if (!data) {
        throw buildUnexpectedFormatError();
      }
      if (!res.ok) {
        throw new Error(data.message || 'Kunde inte ta bort kopplingen.');
      }
      const row = supervisorOverviewBody?.querySelector(
        `tr[data-personnummer-hash="${personnummerHash}"]`,
      );
      row?.remove();
      updateOverviewEmptyState();
      setMessageElement(
        supervisorOverviewMessage,
        data.message || 'Kopplingen har tagits bort.',
        false,
      );
    } catch (err) {
      setMessageElement(supervisorOverviewMessage, err.message, true);
    }
  }

  function renderSupervisorOverview(data) {
    if (!supervisorOverviewCard || !supervisorOverviewBody || !supervisorOverviewTitle) {
      return;
    }
    supervisorOverviewBody.replaceChildren();
    const connections = Array.isArray(data.connections) ? data.connections : [];
    supervisorOverviewTitle.textContent = `Kopplade användarkonton för ${data.name || 'företagskonto'}`;

    if (!connections.length) {
      updateOverviewEmptyState();
    } else {
      connections.forEach((entry) => {
        const row = document.createElement('tr');
        row.dataset.personnummerHash = entry.personnummer_hash || '';
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
        const actionCell = document.createElement('td');
        const removeButton = document.createElement('button');
        removeButton.type = 'button';
        removeButton.className = 'btn btn-danger btn-small';
        removeButton.textContent = 'Ta bort koppling';
        removeButton.disabled = !hash;
        removeButton.addEventListener('click', () => {
          if (!hash) {
            setMessageElement(
              supervisorOverviewMessage,
              'Kunde inte ta bort kopplingen eftersom hash saknas.',
              true,
            );
            return;
          }
          removeOverviewConnection(hash, entry.username);
        });
        actionCell.appendChild(removeButton);
        row.appendChild(nameCell);
        row.appendChild(infoCell);
        row.appendChild(actionCell);
        supervisorOverviewBody.appendChild(row);
      });
    }

    supervisorOverviewCard.hidden = false;
  }

  if (supervisorOverviewForm) {
    setMessageElement(supervisorOverviewMessage, '', false);
    if (!supervisorOverviewCard) {
      setMessageElement(
        supervisorOverviewMessage,
        'Översiktskortet saknas. Ladda om sidan och försök igen.',
        true,
      );
      return;
    }
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
        const data = await parseJsonResponse(res, 'Hämtade kopplingar');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte hämta kopplingar.');
        }
        currentOverviewOrgnr = orgnr;
        renderSupervisorOverview(data.data || {});
        setMessageElement(supervisorOverviewMessage, 'Kopplingar hämtade.', false);
      } catch (err) {
        supervisorOverviewCard.hidden = true;
        setMessageElement(supervisorOverviewMessage, err.message, true);
      }
    });
  }

  if (deleteSupervisorForm) {
    setMessageElement(deleteSupervisorMessage, '', false);
    deleteSupervisorForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!deleteSupervisorMessage) return;
      const formData = new FormData(deleteSupervisorForm);
      const payload = {
        orgnr: formData.get('orgnr')?.toString().trim(),
      };
      if (!payload.orgnr) {
        setMessageElement(
          deleteSupervisorMessage,
          'Ange organisationsnummer.',
          true,
        );
        return;
      }
      const confirmed = window.confirm(
        'Vill du radera företagskontot och alla kopplingar?',
      );
      if (!confirmed) return;
      setMessageElement(deleteSupervisorMessage, 'Raderar företagskonto…', false);
      try {
        const res = await fetch('/admin/api/foretagskonto/radera', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
          },
          body: JSON.stringify({
            ...payload,
            ...(csrfToken ? { csrf_token: csrfToken } : {}),
          }),
        });
        const data = await parseJsonResponse(res, 'Raderade företagskonto');
        if (!data) {
          throw buildUnexpectedFormatError();
        }
        if (!res.ok) {
          throw new Error(data.message || 'Kunde inte radera företagskontot.');
        }
        setMessageElement(
          deleteSupervisorMessage,
          data.message || 'Företagskontot har raderats.',
          false,
        );
        deleteSupervisorForm.reset();
      } catch (err) {
        setMessageElement(deleteSupervisorMessage, err.message, true);
      }
    });
  }
})();
// # Copyright (c) Liam Suorsa and Mika Suorsa
