(function () {
  const container = document.querySelector('.admin-applications');
  if (!container) {
    return;
  }

  const csrfToken = container.getAttribute('data-csrf-token') || '';
  const statusFilter = document.getElementById('statusFilter');
  const refreshBtn = document.getElementById('refreshApplications');
  const tableBody = document.querySelector('#applicationsTable tbody');
  const messageBox = document.getElementById('applicationsMessage');
  const detailSection = document.getElementById('applicationDetail');
  const detailMessage = document.getElementById('detailMessage');
  const rejectForm = document.getElementById('rejectForm');
  const rejectReason = document.getElementById('rejectReason');
  const cancelRejectBtn = document.getElementById('cancelReject');
  const showRejectBtn = document.getElementById('showRejectForm');
  const approveBtn = document.getElementById('approveApplication');
  const actionsWrapper = document.getElementById('applicationActions');
  const detailFields = {
    name: document.getElementById('detailName'),
    email: document.getElementById('detailEmail'),
    company: document.getElementById('detailCompany'),
    orgnr: document.getElementById('detailOrgnr'),
    invoiceAddress: document.getElementById('detailInvoiceAddress'),
    invoiceContact: document.getElementById('detailInvoiceContact'),
    invoiceReference: document.getElementById('detailInvoiceReference'),
    type: document.getElementById('detailType'),
    comment: document.getElementById('detailComment'),
    status: document.getElementById('detailStatus'),
    created: document.getElementById('detailCreated'),
    updated: document.getElementById('detailUpdated'),
    reviewer: document.getElementById('detailReviewer'),
    reason: document.getElementById('detailReason'),
  };
  const reviewerBlock = document.getElementById('detailReviewers');
  const decisionBlock = document.getElementById('detailDecision');
  const invoiceWrappers = {
    address: document.getElementById('detailInvoiceAddressWrapper'),
    contact: document.getElementById('detailInvoiceContactWrapper'),
    reference: document.getElementById('detailInvoiceReferenceWrapper'),
  };

  let applications = [];
  let selectedId = null;

  function setMessage(element, text, type = 'info') {
    if (!element) return;
    if (text) {
      element.textContent = text;
      element.classList.toggle('error', type === 'error');
      element.classList.toggle('success', type === 'success');
      element.hidden = false;
    } else {
      element.hidden = true;
      element.textContent = '';
      element.classList.remove('error', 'success');
    }
  }

  function formatAccountType(value) {
    if (value === 'foretagskonto') return 'Företagskonto';
    return 'Standardkonto';
  }

  function formatStatus(value) {
    switch (value) {
      case 'approved':
        return 'Godkänd';
      case 'rejected':
        return 'Avslagen';
      default:
        return 'Väntar';
    }
  }

  function formatDate(value) {
    if (!value) return '–';
    try {
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {
        return '–';
      }
      return date.toLocaleString('sv-SE');
    } catch (err) {
      return '–';
    }
  }

  function clearSelection() {
    selectedId = null;
    detailSection.hidden = true;
    actionsWrapper.hidden = true;
    rejectForm.hidden = true;
    setMessage(detailMessage, '');
    tableBody.querySelectorAll('tr').forEach((row) => row.classList.remove('is-selected'));
  }

  function renderTable(items) {
    tableBody.innerHTML = '';
    if (!items.length) {
      const emptyRow = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 5;
      cell.textContent = 'Ingen ansökan hittades.';
      emptyRow.appendChild(cell);
      tableBody.appendChild(emptyRow);
      clearSelection();
      return;
    }

    items.forEach((item) => {
      const tr = document.createElement('tr');
      tr.dataset.id = String(item.id);
      if (selectedId === item.id) {
        tr.classList.add('is-selected');
      }

      const cells = [
        item.name,
        item.company_name,
        formatAccountType(item.account_type),
        formatStatus(item.status),
        formatDate(item.created_at),
      ];

      cells.forEach((value) => {
        const td = document.createElement('td');
        td.textContent = value || '–';
        tr.appendChild(td);
      });

      tr.addEventListener('click', () => {
        selectedId = item.id;
        tableBody.querySelectorAll('tr').forEach((row) => row.classList.remove('is-selected'));
        tr.classList.add('is-selected');
        showDetail(item.id);
      });

      tableBody.appendChild(tr);
    });

    if (!selectedId) {
      detailSection.hidden = true;
    }
  }

  function showDetail(id) {
    const item = applications.find((entry) => entry.id === id);
    if (!item) {
      detailSection.hidden = true;
      return;
    }

    detailFields.name.textContent = item.name || '–';
    detailFields.email.textContent = item.email || '–';
    detailFields.company.textContent = item.company_name || '–';
    detailFields.orgnr.textContent = item.orgnr_normalized || '–';
    if (item.account_type === 'foretagskonto') {
      if (invoiceWrappers.address && detailFields.invoiceAddress) {
        const hasAddress = Boolean(item.invoice_address);
        invoiceWrappers.address.hidden = !hasAddress;
        detailFields.invoiceAddress.textContent = hasAddress ? item.invoice_address : '';
      }
      if (invoiceWrappers.contact && detailFields.invoiceContact) {
        const hasContact = Boolean(item.invoice_contact);
        invoiceWrappers.contact.hidden = !hasContact;
        detailFields.invoiceContact.textContent = hasContact ? item.invoice_contact : '';
      }
      if (invoiceWrappers.reference && detailFields.invoiceReference) {
        const hasReference = Boolean(item.invoice_reference);
        invoiceWrappers.reference.hidden = !hasReference;
        detailFields.invoiceReference.textContent = hasReference ? item.invoice_reference : '';
      }
    } else {
      if (invoiceWrappers.address && detailFields.invoiceAddress) {
        invoiceWrappers.address.hidden = true;
        detailFields.invoiceAddress.textContent = '';
      }
      if (invoiceWrappers.contact && detailFields.invoiceContact) {
        invoiceWrappers.contact.hidden = true;
        detailFields.invoiceContact.textContent = '';
      }
      if (invoiceWrappers.reference && detailFields.invoiceReference) {
        invoiceWrappers.reference.hidden = true;
        detailFields.invoiceReference.textContent = '';
      }
    }
    detailFields.type.textContent = formatAccountType(item.account_type);
    detailFields.comment.textContent = item.comment || '–';
    detailFields.status.textContent = formatStatus(item.status);
    detailFields.created.textContent = formatDate(item.created_at);
    detailFields.updated.textContent = formatDate(item.updated_at);

    if (item.reviewed_by) {
      reviewerBlock.hidden = false;
      detailFields.reviewer.textContent = `${item.reviewed_by} (${formatDate(item.reviewed_at)})`;
    } else {
      reviewerBlock.hidden = true;
      detailFields.reviewer.textContent = '';
    }

    if (item.decision_reason) {
      decisionBlock.hidden = false;
      detailFields.reason.textContent = item.decision_reason;
    } else {
      decisionBlock.hidden = true;
      detailFields.reason.textContent = '';
    }

    const pending = item.status === 'pending';
    actionsWrapper.hidden = !pending;
    rejectForm.hidden = true;
    if (pending && rejectReason) {
      rejectReason.value = '';
    }
    setMessage(detailMessage, '');
    detailSection.hidden = false;
  }

  async function fetchApplications() {
    const filterValue = statusFilter?.value || 'pending';
    const params = new URLSearchParams();
    if (filterValue && filterValue !== 'alla') {
      params.set('status', filterValue);
    }

    setMessage(messageBox, 'Hämtar ansökningar…', 'info');

    try {
      const res = await fetch(`/admin/api/ansokningar${params.toString() ? `?${params}` : ''}`);
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.message || 'Kunde inte hämta ansökningar.');
      }
      applications = Array.isArray(payload.data) ? payload.data : [];
      renderTable(applications);
      setMessage(messageBox, applications.length ? '' : 'Ingen ansökan hittades.');
    } catch (err) {
      applications = [];
      renderTable(applications);
      setMessage(messageBox, err.message, 'error');
    }
  }

  async function approveSelected() {
    if (!selectedId) {
      return;
    }
    setMessage(detailMessage, 'Godkänner ansökan…');
    try {
      const res = await fetch(`/admin/api/ansokningar/${selectedId}/godkann`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ csrf_token: csrfToken }),
      });
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.message || 'Det gick inte att godkänna ansökan.');
      }
      setMessage(
        detailMessage,
        payload.email_warning || 'Ansökan godkänd. Kontot skapas och e-post skickas.',
        payload.email_warning ? 'error' : 'success'
      );
      await fetchApplications();
      showDetail(selectedId);
    } catch (err) {
      setMessage(detailMessage, err.message, 'error');
    }
  }

  async function rejectSelected(event) {
    event.preventDefault();
    if (!selectedId) {
      return;
    }
    const reason = (rejectReason.value || '').trim();
    if (!reason) {
      setMessage(detailMessage, 'Ange en motivering till avslaget.', 'error');
      return;
    }

    setMessage(detailMessage, 'Skickar avslag…');
    try {
      const res = await fetch(`/admin/api/ansokningar/${selectedId}/avslag`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ reason, csrf_token: csrfToken }),
      });
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.message || 'Det gick inte att avslå ansökan.');
      }
      setMessage(
        detailMessage,
        payload.email_warning || 'Ansökan avslogs och svar skickades.',
        payload.email_warning ? 'error' : 'success'
      );
      rejectForm.hidden = true;
      await fetchApplications();
      showDetail(selectedId);
    } catch (err) {
      setMessage(detailMessage, err.message, 'error');
    }
  }

  function toggleRejectForm(show) {
    if (!rejectForm) return;
    rejectForm.hidden = !show;
    if (show) {
      rejectReason.value = '';
      rejectReason.focus();
    } else {
      rejectReason.value = '';
    }
  }

  refreshBtn?.addEventListener('click', fetchApplications);
  statusFilter?.addEventListener('change', () => {
    selectedId = null;
    fetchApplications();
  });

  approveBtn?.addEventListener('click', approveSelected);
  showRejectBtn?.addEventListener('click', () => toggleRejectForm(true));
  cancelRejectBtn?.addEventListener('click', () => toggleRejectForm(false));
  rejectForm?.addEventListener('submit', rejectSelected);

  fetchApplications();
})();
