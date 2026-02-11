// # Copyright (c) Liam Suorsa
(() => {
    const csrfToken = document.querySelector('.admin-applications')?.dataset.csrfToken || '';
    const list = document.getElementById('applicationsList');
    const message = document.getElementById('applicationsMessage');
    const statusFilter = document.getElementById('statusFilter');
    const refreshButton = document.getElementById('refreshApplications');

    const statusLabels = {
        pending: 'Väntar på granskning',
        approved: 'Godkänd',
        rejected: 'Avslagen',
    };

    async function sendClientLog(payload) {
        if (!payload) return;
        if (payload.url && payload.url.includes('/admin/api/klientlogg')) return;
        try {
            await fetch('/admin/api/klientlogg', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (error) {
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
        } catch (error) {
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

    function formatDate(value) {
        if (!value) return '—';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return value;
        return date.toLocaleString('sv-SE', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    function setMessage(text, variant = 'info', extraNode = null) {
        message.textContent = text;
        if (extraNode) {
            message.appendChild(document.createTextNode(' '));
            message.appendChild(extraNode);
        }
        message.className = `message ${variant}`;
        message.hidden = false;
    }

    function clearMessage() {
        message.hidden = true;
        message.textContent = '';
    }

    function toggleLoading(isLoading) {
        refreshButton.disabled = isLoading;
        statusFilter.disabled = isLoading;
        list.classList.toggle('is-loading', isLoading);
    }


    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function allowedStatus(value) {
        if (value === 'pending' || value === 'approved' || value === 'rejected') {
            return value;
        }
        return 'pending';
    }

    function updateStatusBadge(card, status) {
        const badge = card.querySelector('.status-badge');
        card.dataset.status = status;
        badge.textContent = statusLabels[status] || status;
        badge.className = `status-badge badge-${status}`;
    }

    function buildDetailList(application) {
        return `
            <dl class="application-detail">
                <div>
                    <dt>Organisationsnummer</dt>
                    <dd>${escapeHtml(application.orgnr_normalized || '—')}</dd>
                </div>
                <div>
                    <dt>Företagsnamn</dt>
                    <dd>${escapeHtml(application.company_name || '—')}</dd>
                </div>
                <div>
                    <dt>Fakturaadress</dt>
                    <dd>${escapeHtml(application.invoice_address || '—')}</dd>
                </div>
                <div>
                    <dt>Kontaktperson</dt>
                    <dd>${escapeHtml(application.invoice_contact || '—')}</dd>
                </div>
                <div>
                    <dt>Kommentar</dt>
                    <dd>${escapeHtml(application.comment || '—')}</dd>
                </div>
                <div>
                    <dt>Inskickad</dt>
                    <dd>${escapeHtml(formatDate(application.created_at))}</dd>
                </div>
            </dl>
        `;
    }

    function buildCard(application) {
        const card = document.createElement('article');
        const status = allowedStatus(application.status);
        const appId = Number.isInteger(Number(application.id)) ? Number(application.id) : 0;
        const accountTypeLabel = application.account_type === 'foretagskonto' ? 'Företagskonto' : 'Standardkonto';
        const accountTypeChip = application.account_type === 'foretagskonto' ? 'Företag' : 'Standard';
        card.className = 'application-item';
        card.dataset.status = status;
        card.dataset.appId = String(appId);

        card.innerHTML = `
            <div class="application-card">
                <div class="application-summary">
                    <div class="application-info">
                        <span class="application-name">${escapeHtml(application.name || '—')}</span>
                        <span class="application-email">${escapeHtml(application.email || '—')}</span>
                        <span class="application-type">${escapeHtml(accountTypeLabel)}</span>
                    </div>
                    <span class="status-badge badge-${status}">${escapeHtml(statusLabels[status] || status)}</span>
                </div>
                <div class="application-meta">
                    <span class="meta-chip">${escapeHtml(accountTypeChip)}</span>
                    <span class="meta-chip">${escapeHtml(formatDate(application.created_at))}</span>
                </div>
                <details class="application-detail-toggle">
                    <summary>Visa detaljer</summary>
                    ${buildDetailList(application)}
                </details>
                <div class="application-actions">
                    <button type="button" class="btn btn-small btn-approve" data-action="approve">Godkänn direkt</button>
                    <button type="button" class="btn btn-small btn-deny" data-action="reject">Avslå</button>
                </div>
                <div class="reject-panel" hidden>
                    <label for="reject-reason-${appId}">Motivering (valfritt)</label>
                    <textarea id="reject-reason-${appId}" rows="2" placeholder="Kort motivering till avslaget"></textarea>
                    <div class="reject-actions">
                        <button type="button" class="btn btn-small btn-deny" data-action="confirm-reject">Skicka avslag</button>
                        <button type="button" class="btn btn-small btn-secondary" data-action="cancel-reject">Avbryt</button>
                    </div>
                </div>
            </div>
        `;

        hookCardActions(card, appId);
        return card;
    }

    function setButtonsDisabled(card, disabled) {
        card.querySelectorAll('button').forEach((btn) => {
            btn.disabled = disabled;
        });
    }

    async function approveApplication(card, applicationId) {
        setButtonsDisabled(card, true);
        setMessage('Godkänner ansökan …');
        try {
            const response = await fetch(`/admin/api/ansokningar/${applicationId}/godkann`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify({ csrf_token: csrfToken }),
            });

            const data = await parseJsonResponse(response, 'Godkände ansökan');
            if (!data) {
                throw buildUnexpectedFormatError();
            }
            if (!response.ok || data.status !== 'success') {
                throw new Error(data.message || 'Kunde inte godkänna ansökan.');
            }

            updateStatusBadge(card, 'approved');
            const creationText = data.creation_link
                ? document.createTextNode(`Aktiveringslänk: ${data.creation_link}`)
                : null;
            setMessage('Ansökan godkänd.', 'success', creationText);
        } catch (error) {
            console.error(error);
            setMessage(error.message || 'Ett fel uppstod vid godkännande.', 'error');
        } finally {
            setButtonsDisabled(card, false);
        }
    }

    async function rejectApplication(card, applicationId, reason) {
        setButtonsDisabled(card, true);
        setMessage('Avslår ansökan …');
        try {
            const response = await fetch(`/admin/api/ansokningar/${applicationId}/avslag`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify({ csrf_token: csrfToken, reason }),
            });

            const data = await parseJsonResponse(response, 'Avslog ansökan');
            if (!data) {
                throw buildUnexpectedFormatError();
            }
            if (!response.ok || data.status !== 'success') {
                throw new Error(data.message || 'Kunde inte avslå ansökan.');
            }

            updateStatusBadge(card, 'rejected');
            setMessage('Ansökan avslogs.', 'success');
            card.querySelector('.reject-panel').hidden = true;
        } catch (error) {
            console.error(error);
            setMessage(error.message || 'Ett fel uppstod vid avslag.', 'error');
        } finally {
            setButtonsDisabled(card, false);
        }
    }

    function hookCardActions(card, applicationId) {
        const approveButton = card.querySelector('[data-action="approve"]');
        const rejectButton = card.querySelector('[data-action="reject"]');
        const rejectPanel = card.querySelector('.reject-panel');
        const confirmReject = card.querySelector('[data-action="confirm-reject"]');
        const cancelReject = card.querySelector('[data-action="cancel-reject"]');
        const reasonField = card.querySelector('textarea');

        approveButton?.addEventListener('click', () => approveApplication(card, applicationId));
        rejectButton?.addEventListener('click', () => {
            rejectPanel.hidden = false;
            reasonField.focus();
        });
        cancelReject?.addEventListener('click', () => {
            rejectPanel.hidden = true;
            reasonField.value = '';
        });
        confirmReject?.addEventListener('click', () => {
            rejectApplication(card, applicationId, reasonField.value.trim());
        });
    }

    function renderApplications(applications) {
        list.innerHTML = '';
        if (!applications.length) {
            list.innerHTML = '<p class="empty-state">Inga ansökningar hittades för det här filtret.</p>';
            return;
        }

        applications.forEach((application) => {
            list.appendChild(buildCard(application));
        });
    }

    async function fetchApplications() {
        toggleLoading(true);
        clearMessage();
        const status = statusFilter.value;
        const query = status === 'alla' ? '' : `?status=${encodeURIComponent(status)}`;
        try {
            const response = await fetch(`/admin/api/ansokningar${query}`);
            const data = await parseJsonResponse(response, 'Läste ansökningar');
            if (!data) {
                throw buildUnexpectedFormatError();
            }
            if (!response.ok || data.status !== 'success') {
                throw new Error(data.message || 'Kunde inte läsa ansökningarna.');
            }
            renderApplications(data.data || []);
        } catch (error) {
            console.error(error);
            setMessage(error.message || 'Ett fel uppstod när ansökningarna skulle hämtas.', 'error');
        } finally {
            toggleLoading(false);
        }
    }

    statusFilter.addEventListener('change', fetchApplications);
    refreshButton.addEventListener('click', fetchApplications);

    fetchApplications();
})();
// # Copyright (c) Liam Suorsa
