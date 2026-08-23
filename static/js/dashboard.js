// # Copyright (c) Liam Suorsa and Mika Suorsa
// static/js/dashboard.js

(() => {
  function normalizeSearchValue(value) {
    const normalized = (value || '').toLowerCase().replace(/\s+/g, ' ').trim();

    if (typeof normalized.normalize !== 'function') {
      return normalized;
    }

    return normalized.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  }

  function buildPdfSearchText(filename, note, groupLabel) {
    return `${filename || ''} ${note || ''} ${groupLabel || ''}`.trim().toLowerCase();
  }

  function updateExpiryStatus(pdfItem) {
    const statusElement = pdfItem.querySelector('[data-expiry-status]');
    const expiryValue = pdfItem.dataset.pdfExpiresOn || '';

    if (!statusElement) {
      return;
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(expiryValue)) {
      statusElement.textContent = '';
      statusElement.hidden = true;
      statusElement.removeAttribute('aria-label');
      statusElement.setAttribute('aria-hidden', 'true');
      return;
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const expiryDate = new Date(`${expiryValue}T00:00:00`);
    const daysUntilExpiry = Math.ceil(
      (expiryDate.getTime() - today.getTime()) / 86400000
    );
    let emoji;
    let label;

    if (daysUntilExpiry < 0) {
      emoji = '🔴';
      label = 'Intyget har gått ut';
    } else if (daysUntilExpiry <= 30) {
      emoji = '🟡';
      label = 'Intyget går ut inom 30 dagar';
    } else {
      emoji = '🟢';
      label = 'Intyget går ut om mer än 30 dagar';
    }

    statusElement.textContent = emoji;
    statusElement.setAttribute('aria-label', label);
    statusElement.setAttribute('title', label);
    statusElement.setAttribute('aria-hidden', 'false');
    statusElement.hidden = false;
  }

  function setupExpiryStatuses() {
    document.querySelectorAll('[data-pdf-item]').forEach(updateExpiryStatus);
  }

  function refreshDashboardSearch() {
    const searchInput = document.querySelector('[data-dashboard-search]');
    if (!searchInput) {
      return;
    }
    searchInput.dispatchEvent(new Event('input', { bubbles: true }));
  }

  function setupDashboardSearch() {
    const searchInput = document.querySelector('[data-dashboard-search]');
    const pdfItems = Array.from(document.querySelectorAll('[data-pdf-item]'));
    const groups = Array.from(document.querySelectorAll('[data-pdf-group]'));
    const emptyState = document.getElementById('dashboardSearchEmpty');

    if (!searchInput || !pdfItems.length) {
      return;
    }

    function filterItems() {
      const query = normalizeSearchValue(searchInput.value);
      let visibleCount = 0;

      pdfItems.forEach((item) => {
        const haystack = normalizeSearchValue(item.dataset.searchText || '');
        const matches = !query || haystack.includes(query);
        item.hidden = !matches;
        if (matches) {
          visibleCount += 1;
        }
      });

      groups.forEach((group) => {
        const visibleItems = Array.from(
          group.querySelectorAll('[data-pdf-item]')
        ).some((item) => !item.hidden);
        group.hidden = !visibleItems;
      });

      if (emptyState) {
        emptyState.hidden = visibleCount !== 0;
      }
    }

    searchInput.addEventListener('input', filterItems);
    filterItems();
  }

  function setupSupervisorDashboard() {
    const searchInput = document.querySelector('[data-user-search]');
    const userCards = Array.from(document.querySelectorAll('[data-user-card]'));
    const searchStatus = document.querySelector('[data-user-search-status]');
    const emptyMessage = document.getElementById('supervisor-user-search-empty');
    const toggleButtons = Array.from(document.querySelectorAll('[data-user-toggle]'));
    const removeForms = Array.from(
      document.querySelectorAll('[data-supervisor-remove]')
    );

    function updateToggleState(button, shouldExpand) {
      const detailsId = button.getAttribute('aria-controls');
      const details = detailsId ? document.getElementById(detailsId) : null;
      const openLabel = button.dataset.openLabel || 'Visa detaljer';
      const closeLabel = button.dataset.closeLabel || 'Dölj detaljer';
      const visibleLabel = button.querySelector('[data-user-toggle-label]');

      button.setAttribute('aria-expanded', shouldExpand ? 'true' : 'false');
      if (visibleLabel) {
        visibleLabel.textContent = shouldExpand ? closeLabel : openLabel;
      } else {
        button.textContent = shouldExpand ? closeLabel : openLabel;
      }

      if (details) {
        details.hidden = !shouldExpand;
      }
    }

    toggleButtons.forEach((button) => {
      updateToggleState(button, button.getAttribute('aria-expanded') === 'true');
      button.addEventListener('click', () => {
        const isExpanded = button.getAttribute('aria-expanded') === 'true';
        updateToggleState(button, !isExpanded);
      });
    });

    removeForms.forEach((form) => {
      form.addEventListener('submit', (event) => {
        if (!window.confirm('Vill du ta bort kopplingen till användaren?')) {
          event.preventDefault();
        }
      });
    });

    if (!searchInput || !userCards.length) {
      return;
    }

    const totalUsers = userCards.length;

    function updateSearchStatus(visibleCount, hasQuery) {
      if (!searchStatus) {
        return;
      }

      if (!hasQuery) {
        searchStatus.textContent = `Visar alla ${totalUsers} användare.`;
        return;
      }

      if (visibleCount === 0) {
        searchStatus.textContent = 'Ingen användare matchar sökningen.';
        return;
      }

      searchStatus.textContent = `Visar ${visibleCount} av ${totalUsers} användare.`;
    }

    function filterUsers() {
      const query = normalizeSearchValue(searchInput.value);
      let visibleCount = 0;

      userCards.forEach((card) => {
        const haystack = normalizeSearchValue(
          card.dataset.userSearchText || card.dataset.userName || ''
        );
        const matches = !query || haystack.includes(query);
        const toggle = card.querySelector('[data-user-toggle]');
        card.hidden = !matches;

        if (toggle && query) {
          if (typeof card.dataset.searchWasExpanded === 'undefined') {
            card.dataset.searchWasExpanded = toggle.getAttribute('aria-expanded');
          }
          if (matches) {
            updateToggleState(toggle, true);
          }
        } else if (toggle && typeof card.dataset.searchWasExpanded !== 'undefined') {
          updateToggleState(toggle, card.dataset.searchWasExpanded === 'true');
          delete card.dataset.searchWasExpanded;
        }

        if (matches) {
          visibleCount += 1;
        }
      });

      if (emptyMessage) {
        emptyMessage.hidden = visibleCount !== 0;
      }

      updateSearchStatus(visibleCount, query.length > 0);
    }

    searchInput.addEventListener('input', filterUsers);
    filterUsers();
  }

  function setupSupervisorShareModal() {
    const shareWorkspace = document.querySelector('[data-supervisor-share-workspace]');
    const shareModal = document.getElementById('supervisorShareModal');
    const shareForm = document.getElementById('supervisorShareForm');
    const shareEmailInput = document.getElementById('supervisorShareRecipientEmail');
    const csrfInput = document.getElementById('supervisorShareCsrfToken');
    const shareFeedback = document.getElementById('supervisorShareFeedback');
    const shareDocumentSummary = document.getElementById(
      'supervisorShareDocumentSummary'
    );
    const shareOwnerSummary = document.getElementById('supervisorShareOwnerSummary');
    const shareDocumentList = document.getElementById('supervisorShareDocumentList');
    const submitButton = shareForm
      ? shareForm.querySelector('[data-supervisor-share-submit]')
      : null;
    const globalSelection = document.querySelector(
      '[data-supervisor-global-selection]'
    );
    const globalStatus = document.querySelector('[data-supervisor-global-status]');
    const globalShareButton = document.querySelector('[data-supervisor-global-share]');
    const clearSelectionButton = document.querySelector(
      '[data-supervisor-clear-selection]'
    );
    const sharePanels = Array.from(
      document.querySelectorAll('[data-supervisor-person-hash]')
    );
    const batchShareUrl = shareWorkspace
      ? shareWorkspace.dataset.supervisorBatchShareUrl || ''
      : '';
    const supportsNativeDialog =
      !!shareModal &&
      typeof shareModal.showModal === 'function' &&
      typeof shareModal.close === 'function';

    if (
      !shareModal ||
      !shareForm ||
      !shareEmailInput ||
      !csrfInput ||
      !submitButton ||
      !shareWorkspace ||
      !batchShareUrl ||
      !globalSelection ||
      !globalStatus ||
      !globalShareButton ||
      !clearSelectionButton ||
      !sharePanels.length
    ) {
      return;
    }

    const closeButtons = Array.from(
      shareModal.querySelectorAll('[data-supervisor-share-close]')
    );

    if (!supportsNativeDialog) {
      shareModal.setAttribute('data-polyfill', 'true');
      shareModal.setAttribute('aria-hidden', 'true');
    }

    let activePdfs = [];
    let clearSelectionOnSuccess = false;
    let isSubmitting = false;
    let returnFocusTarget = null;

    function setFeedback(message = '', state = '') {
      if (!shareFeedback) {
        return;
      }

      if (!message) {
        shareFeedback.textContent = '';
        shareFeedback.dataset.state = '';
        shareFeedback.hidden = true;
        shareFeedback.setAttribute('role', 'status');
        return;
      }

      shareFeedback.textContent = message;
      shareFeedback.dataset.state = state;
      shareFeedback.hidden = false;
      shareFeedback.setAttribute('role', state === 'error' ? 'alert' : 'status');
    }

    function pdfFromCheckbox(checkbox, panel = null) {
      const id = Number.parseInt(checkbox.value || '', 10);
      const personHash =
        checkbox.dataset.personHash || panel?.dataset.supervisorPersonHash || '';
      if (!Number.isInteger(id) || id < 1 || !personHash) {
        return null;
      }

      return {
        id,
        personHash,
        name: checkbox.dataset.pdfName || 'intyget',
        ownerName:
          checkbox.dataset.ownerName ||
          panel?.dataset.supervisorOwnerName ||
          'användaren',
      };
    }

    function selectedPdfsForPanel(panel) {
      return Array.from(
        panel.querySelectorAll('[data-supervisor-share-select]:checked')
      )
        .map((checkbox) => pdfFromCheckbox(checkbox, panel))
        .filter(Boolean);
    }

    function selectedPdfsAcrossWorkspace() {
      return Array.from(
        shareWorkspace.querySelectorAll('[data-supervisor-share-select]:checked')
      )
        .map((checkbox) => pdfFromCheckbox(checkbox, checkbox.closest('[data-supervisor-person-hash]')))
        .filter(Boolean);
    }

    function updatePanelSelection(panel) {
      const checkboxes = Array.from(
        panel.querySelectorAll('[data-supervisor-share-select]')
      );
      const selected = selectedPdfsForPanel(panel);
      const selectAll = panel.querySelector('[data-supervisor-select-all]');
      const selectionBar = panel.querySelector('[data-supervisor-selection-bar]');
      const status = panel.querySelector('[data-supervisor-selection-status]');

      if (selectAll) {
        selectAll.checked = checkboxes.length > 0 && selected.length === checkboxes.length;
        selectAll.indeterminate = selected.length > 0 && selected.length < checkboxes.length;
      }

      if (selectionBar) {
        selectionBar.classList.toggle('has-selection', selected.length > 0);
      }

      if (status) {
        if (selected.length === 0) {
          status.textContent = 'Inga intyg markerade';
        } else if (selected.length === 1) {
          status.textContent = '1 intyg markerat';
        } else {
          status.textContent = `${selected.length} intyg markerade`;
        }
      }

    }

    function updateGlobalSelection() {
      const selected = selectedPdfsAcrossWorkspace();
      const ownerCount = new Set(selected.map((pdf) => pdf.personHash)).size;
      globalSelection.classList.toggle('has-selection', selected.length > 0);

      if (selected.length === 0) {
        globalStatus.textContent = 'Inga intyg markerade';
      } else {
        const certificateText =
          selected.length === 1
            ? '1 intyg markerat'
            : `${selected.length} intyg markerade`;
        const ownerText = ownerCount === 1 ? '1 person' : `${ownerCount} personer`;
        globalStatus.textContent = `${certificateText} från ${ownerText}`;
      }

      globalShareButton.disabled = selected.length === 0;
      globalShareButton.textContent =
        selected.length > 0 ? `Dela ${selected.length} intyg` : 'Dela markerade';
      clearSelectionButton.disabled = selected.length === 0;
    }

    function updateAllSelectionStates() {
      sharePanels.forEach(updatePanelSelection);
      updateGlobalSelection();
    }

    function renderSelection(pdfs) {
      if (!shareDocumentList) {
        return;
      }

      shareDocumentList.innerHTML = '';
      const fragment = document.createDocumentFragment();
      const ownerCount = new Set(pdfs.map((pdf) => pdf.personHash)).size;
      pdfs.forEach((pdf) => {
        const item = document.createElement('li');
        item.textContent =
          ownerCount > 1
            ? `${pdf.ownerName}: ${pdf.name || 'Intyg'}`
            : pdf.name || 'Intyg';
        fragment.appendChild(item);
      });
      shareDocumentList.appendChild(fragment);
    }

    function setSubmitting(submitting) {
      isSubmitting = submitting;
      submitButton.disabled = submitting;
      shareEmailInput.readOnly = submitting;
      closeButtons.forEach((button) => {
        button.disabled = submitting;
      });
    }

    function resetModalState() {
      if (isSubmitting) {
        return;
      }

      activePdfs = [];
      clearSelectionOnSuccess = false;
      shareEmailInput.value = '';
      setFeedback();
      if (shareDocumentList) {
        shareDocumentList.innerHTML = '';
      }
      if (shareDocumentSummary) {
        shareDocumentSummary.textContent = 'intyget';
      }
      if (shareOwnerSummary) {
        shareOwnerSummary.textContent = 'användaren';
      }
      submitButton.textContent = 'Skicka intyg';
      setSubmitting(false);
    }

    function closeShareModal() {
      if (isSubmitting) {
        setFeedback('Vänta tills delningen är klar.', 'info');
        return;
      }

      if (supportsNativeDialog) {
        if (shareModal.open) {
          shareModal.close();
        }
      } else {
        shareModal.classList.remove('is-visible');
        shareModal.setAttribute('aria-hidden', 'true');
        resetModalState();
        if (returnFocusTarget) {
          returnFocusTarget.focus();
        }
        returnFocusTarget = null;
      }
    }

    function openShareModal(pdfs, trigger, clearAfterSuccess) {
      if (!pdfs.length || isSubmitting) {
        return;
      }

      activePdfs = pdfs;
      clearSelectionOnSuccess = clearAfterSuccess;
      returnFocusTarget = trigger || null;
      shareEmailInput.value = '';
      setFeedback();
      renderSelection(pdfs);

      if (shareDocumentSummary) {
        shareDocumentSummary.textContent =
          pdfs.length === 1 ? pdfs[0].name || 'intyget' : `${pdfs.length} intyg`;
      }
      if (shareOwnerSummary) {
        const owners = Array.from(
          new Set(pdfs.map((pdf) => pdf.ownerName || 'användaren'))
        );
        shareOwnerSummary.textContent =
          owners.length === 1 ? owners[0] : `${owners.length} personer`;
      }
      submitButton.textContent =
        pdfs.length === 1 ? 'Skicka intyg' : `Skicka ${pdfs.length} intyg`;

      if (supportsNativeDialog) {
        if (!shareModal.open) {
          shareModal.showModal();
        }
      } else {
        shareModal.classList.add('is-visible');
        shareModal.setAttribute('aria-hidden', 'false');
      }

      window.setTimeout(() => shareEmailInput.focus(), 0);
    }

    closeButtons.forEach((button) =>
      button.addEventListener('click', closeShareModal)
    );

    if (supportsNativeDialog) {
      shareModal.addEventListener('cancel', (event) => {
        event.preventDefault();
        closeShareModal();
      });
      shareModal.addEventListener('close', () => {
        resetModalState();
        if (returnFocusTarget) {
          returnFocusTarget.focus();
        }
        returnFocusTarget = null;
      });
    } else {
      shareModal.addEventListener('click', (event) => {
        if (event.target === shareModal) {
          closeShareModal();
        }
      });
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && shareModal.classList.contains('is-visible')) {
          closeShareModal();
        }
      });
    }

    sharePanels.forEach((panel) => {
      const checkboxes = Array.from(
        panel.querySelectorAll('[data-supervisor-share-select]')
      );
      const selectAll = panel.querySelector('[data-supervisor-select-all]');

      checkboxes.forEach((checkbox) => {
        checkbox.addEventListener('change', () => {
          updatePanelSelection(panel);
          updateGlobalSelection();
        });
      });

      if (selectAll) {
        selectAll.addEventListener('change', () => {
          checkboxes.forEach((checkbox) => {
            checkbox.checked = selectAll.checked;
          });
          updatePanelSelection(panel);
          updateGlobalSelection();
        });
      }

      panel.querySelectorAll('[data-supervisor-share-one]').forEach((button) => {
        button.addEventListener('click', () => {
          const row = button.closest('[data-supervisor-pdf-row]');
          const checkbox = row
            ? row.querySelector('[data-supervisor-share-select]')
            : null;
          if (!checkbox) {
            return;
          }
          const selectedPdf = pdfFromCheckbox(checkbox, panel);
          if (!selectedPdf) {
            return;
          }
          openShareModal([selectedPdf], button, false);
        });
      });
    });

    clearSelectionButton.addEventListener('click', () => {
      shareWorkspace
        .querySelectorAll('[data-supervisor-share-select]')
        .forEach((checkbox) => {
          checkbox.checked = false;
        });
      updateAllSelectionStates();
    });

    globalShareButton.addEventListener('click', () => {
      openShareModal(selectedPdfsAcrossWorkspace(), globalShareButton, true);
    });

    updateAllSelectionStates();

    shareForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (isSubmitting || !activePdfs.length) {
        return;
      }

      const recipientEmail = shareEmailInput.value.trim();
      if (!recipientEmail || !shareEmailInput.checkValidity()) {
        setFeedback('Ange en giltig e-postadress.', 'error');
        shareEmailInput.focus();
        return;
      }

      const requestPdfs = activePdfs.map((pdf) => ({ ...pdf }));
      const shouldClearSelection = clearSelectionOnSuccess;
      setSubmitting(true);
      setFeedback(
        requestPdfs.length === 1 ? 'Skickar intyget...' : 'Skickar intygen...',
        'info'
      );

      try {
        const response = await fetch(batchShareUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({
            items: requestPdfs.map((pdf) => ({
              person_hash: pdf.personHash,
              pdf_id: pdf.id,
            })),
            recipient_email: recipientEmail,
            csrf_token: csrfInput.value,
          }),
        });
        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
          setFeedback(
            data.fel || 'Intygen kunde inte skickas. Försök igen.',
            'error'
          );
          return;
        }

        setFeedback(
          data.meddelande ||
            (requestPdfs.length === 1
              ? 'Intyget har skickats via e-post.'
              : 'Intygen har skickats via e-post.'),
          'success'
        );
        shareEmailInput.value = '';

        if (shouldClearSelection) {
          const sharedKeys = new Set(
            requestPdfs.map((pdf) => `${pdf.personHash}:${pdf.id}`)
          );
          shareWorkspace
            .querySelectorAll('[data-supervisor-share-select]')
            .forEach((checkbox) => {
              const pdf = pdfFromCheckbox(
                checkbox,
                checkbox.closest('[data-supervisor-person-hash]')
              );
              if (pdf && sharedKeys.has(`${pdf.personHash}:${pdf.id}`)) {
                checkbox.checked = false;
              }
            });
          updateAllSelectionStates();
          clearSelectionOnSuccess = false;
        }
      } catch (error) {
        setFeedback('Det gick inte att ansluta till servern. Försök igen.', 'error');
      } finally {
        setSubmitting(false);
      }
    });
  }

  function setupEditPdfModal() {
    const editModal = document.getElementById('editPdfModal');
    const editForm = document.getElementById('editPdfForm');
    const nameInput = document.getElementById('editPdfName');
    const noteInput = document.getElementById('editPdfNote');
    const expiryModeSelect = document.getElementById('editPdfExpiryMode');
    const expiryDateInput = document.getElementById('editPdfExpiryDate');
    const expiryYearsInput = document.getElementById('editPdfExpiryYears');
    const expiryMonthsInput = document.getElementById('editPdfExpiryMonths');
    const csrfInput = document.getElementById('editPdfCsrfToken');
    const feedback = document.getElementById('editPdfFeedback');
    const summary = document.getElementById('editPdfSummary');
    const triggerButtons = Array.from(document.querySelectorAll('[data-edit-pdf]'));
    const supportsNativeDialog =
      !!editModal &&
      typeof editModal.showModal === 'function' &&
      typeof editModal.close === 'function';

    if (editModal && !supportsNativeDialog) {
      editModal.setAttribute('data-polyfill', 'true');
      editModal.setAttribute('aria-hidden', 'true');
    }

    if (
      !editModal ||
      !editForm ||
      !nameInput ||
      !noteInput ||
      !expiryModeSelect ||
      !expiryDateInput ||
      !expiryYearsInput ||
      !expiryMonthsInput ||
      !csrfInput ||
      !feedback ||
      !summary ||
      !triggerButtons.length
    ) {
      return;
    }

    const closeElements = Array.from(editModal.querySelectorAll('[data-edit-close]'));
    const submitButton = editForm.querySelector('button[type="submit"]');
    const expiryFields = {
      date: {
        container: editForm.querySelector('[data-edit-expiry-field="date"]'),
        inputs: [expiryDateInput],
      },
      duration: {
        container: editForm.querySelector('[data-edit-expiry-field="duration"]'),
        inputs: [expiryYearsInput, expiryMonthsInput],
      },
    };
    const defaultSummaryName = 'intyget';

    let activePdfItem = null;
    let isSubmitting = false;

    function setFeedback(message, state) {
      if (!message) {
        feedback.textContent = '';
        feedback.dataset.state = '';
        feedback.hidden = true;
        return;
      }

      feedback.textContent = message;
      feedback.dataset.state = state;
      feedback.hidden = false;
    }

    function setExpiryMode(mode) {
      Object.entries(expiryFields).forEach(([fieldMode, fieldState]) => {
        if (!fieldState.container) {
          return;
        }

        const isActive = mode === fieldMode;
        fieldState.container.hidden = !isActive;
        fieldState.inputs.forEach((input) => {
          if (!input) {
            return;
          }
          input.disabled = !isActive;
          if (!isActive) {
            input.value = '';
          }
        });
      });
    }

    function resetEditModalState() {
      activePdfItem = null;
      editForm.reset();
      setFeedback('', '');
      summary.textContent = defaultSummaryName;
      setExpiryMode('none');
    }

    function closeEditModal() {
      if (supportsNativeDialog) {
        if (editModal.open) {
          editModal.close();
        }
      } else {
        editModal.classList.remove('is-visible');
        editModal.setAttribute('aria-hidden', 'true');
        document.removeEventListener('keydown', handleKeyDown);
        resetEditModalState();
      }
    }

    function openEditModal(pdfItem) {
      activePdfItem = pdfItem;
      nameInput.value = pdfItem.dataset.editableName || '';
      noteInput.value = pdfItem.dataset.pdfNote || '';

      const expiresOn = pdfItem.dataset.pdfExpiresOn || '';
      expiryModeSelect.value = expiresOn ? 'date' : 'none';
      expiryDateInput.value = expiresOn;
      expiryYearsInput.value = '';
      expiryMonthsInput.value = '';
      setExpiryMode(expiryModeSelect.value);
      setFeedback('', '');
      summary.textContent = pdfItem.dataset.pdfFilename || defaultSummaryName;

      if (supportsNativeDialog) {
        if (!editModal.open) {
          editModal.showModal();
        }
      } else {
        editModal.classList.add('is-visible');
        editModal.setAttribute('aria-hidden', 'false');
        document.addEventListener('keydown', handleKeyDown);
      }

      const focusNameInput = () => {
        nameInput.focus();
        nameInput.select();
      };
      if (typeof window.requestAnimationFrame === 'function') {
        window.requestAnimationFrame(focusNameInput);
      } else {
        setTimeout(focusNameInput, 0);
      }
    }

    function updatePdfItemView(pdfItem, data) {
      const filename =
        typeof data.filename === 'string' ? data.filename : pdfItem.dataset.pdfFilename || '';
      const note = typeof data.note === 'string' ? data.note : '';
      const expiresOn = typeof data.expires_on === 'string' ? data.expires_on : '';
      const editableName = filename.replace(/\.pdf$/i, '');
      const groupLabel = pdfItem.dataset.groupLabel || '';

      pdfItem.dataset.pdfFilename = filename;
      pdfItem.dataset.editableName = editableName;
      pdfItem.dataset.pdfNote = note;
      pdfItem.dataset.pdfExpiresOn = expiresOn;
      pdfItem.dataset.searchText = buildPdfSearchText(filename, note, groupLabel);
      updateExpiryStatus(pdfItem);

      const shareCheckbox = pdfItem.querySelector('[data-share-select]');
      if (shareCheckbox) {
        shareCheckbox.dataset.pdfName = filename;
        shareCheckbox.setAttribute(
          'aria-label',
          `Markera ${filename} för delning`
        );
      }

      const filenameLink = pdfItem.querySelector('[data-pdf-link]');
      if (filenameLink) {
        filenameLink.textContent = filename;
      }

      const metaContainer = pdfItem.querySelector('[data-pdf-meta]');
      const noteElement = pdfItem.querySelector('[data-pdf-note-text]');
      const expiryElement = pdfItem.querySelector('[data-pdf-expiry-text]');

      if (noteElement) {
        noteElement.textContent = note;
        noteElement.hidden = !note;
      }

      if (expiryElement) {
        expiryElement.textContent = expiresOn ? `Gäller till ${expiresOn}` : '';
        expiryElement.hidden = !expiresOn;
      }

      if (metaContainer) {
        metaContainer.hidden = !note && !expiresOn;
      }

      if (activePdfItem === pdfItem) {
        nameInput.value = editableName;
        noteInput.value = note;
        expiryModeSelect.value = expiresOn ? 'date' : 'none';
        expiryDateInput.value = expiresOn;
        expiryYearsInput.value = '';
        expiryMonthsInput.value = '';
        setExpiryMode(expiryModeSelect.value);
        summary.textContent = filename || defaultSummaryName;
      }
    }

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeEditModal();
      }
    };

    closeElements.forEach((element) => {
      element.addEventListener('click', () => {
        closeEditModal();
      });
    });

    if (supportsNativeDialog) {
      editModal.addEventListener('cancel', (event) => {
        event.preventDefault();
        closeEditModal();
      });
      editModal.addEventListener('close', () => {
        resetEditModalState();
      });
    } else {
      editModal.addEventListener('click', (event) => {
        if (event.target === editModal) {
          closeEditModal();
        }
      });
    }

    expiryModeSelect.addEventListener('change', () => {
      setExpiryMode(expiryModeSelect.value);
      setFeedback('', '');
    });

    triggerButtons.forEach((button) => {
      button.addEventListener('click', () => {
        const pdfItem = button.closest('[data-pdf-item]');
        if (!pdfItem) {
          return;
        }
        openEditModal(pdfItem);
      });
    });

    editForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      if (isSubmitting) {
        return;
      }

      if (!activePdfItem) {
        setFeedback('Det gick inte att identifiera intyget.', 'error');
        return;
      }

      const pdfItemToUpdate = activePdfItem;
      const updateUrl = pdfItemToUpdate.dataset.updateUrl || '';
      if (!updateUrl) {
        setFeedback('Det gick inte att identifiera intyget.', 'error');
        return;
      }

      const rawName = nameInput.value.trim();
      if (!rawName) {
        setFeedback('Intygsnamnet kan inte vara tomt.', 'error');
        nameInput.focus();
        return;
      }

      isSubmitting = true;
      if (submitButton) {
        submitButton.disabled = true;
      }
      setFeedback('Sparar ändringarna...', 'info');

      try {
        const response = await fetch(updateUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({
            csrf_token: csrfInput.value,
            filename: rawName,
            note: noteInput.value,
            expiry_mode: expiryModeSelect.value,
            expiry_date: expiryDateInput.value,
            expiry_years: expiryYearsInput.value,
            expiry_months: expiryMonthsInput.value,
          }),
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
          setFeedback(
            data.fel || 'Det gick inte att uppdatera intyget.',
            'error'
          );
          return;
        }

        updatePdfItemView(pdfItemToUpdate, data.data || {});
        refreshDashboardSearch();
        closeEditModal();
      } catch (error) {
        setFeedback('Det gick inte att ansluta till servern.', 'error');
      } finally {
        isSubmitting = false;
        if (submitButton) {
          submitButton.disabled = false;
        }
      }
    });
  }

  function setupShareModal() {
    const shareModal = document.getElementById('shareModal');
    const shareForm = document.getElementById('shareForm');
    const shareEmailInput = document.getElementById('shareRecipientEmail');
    const shareFeedback = document.getElementById('shareFeedback');
    const shareDocumentSummary = document.getElementById('shareDocumentSummary');
    const shareDocumentSelection = document.getElementById('shareDocumentSelection');
    const shareDocumentList = document.getElementById('shareDocumentList');
    const supportsNativeDialog =
      !!shareModal &&
      typeof shareModal.showModal === 'function' &&
      typeof shareModal.close === 'function';

    if (shareModal && !supportsNativeDialog) {
      shareModal.setAttribute('data-polyfill', 'true');
      shareModal.setAttribute('aria-hidden', 'true');
    }

    const closeElements = shareModal
      ? Array.from(shareModal.querySelectorAll('[data-share-close]'))
      : [];
    const submitButton = shareForm
      ? shareForm.querySelector('button[type="submit"]')
      : null;
    const shareSelectedButton = document.getElementById('shareSelectedButton');
    const selectionCheckboxes = Array.from(
      document.querySelectorAll('[data-share-select]')
    );

    if (!shareModal || !shareForm || !shareEmailInput || !submitButton) {
      return;
    }

    let activePdfIds = [];
    let clearSelectionOnSuccess = false;
    let isSubmitting = false;

    function setFeedback(message, state) {
      if (!shareFeedback) {
        return;
      }

      if (!message) {
        shareFeedback.textContent = '';
        shareFeedback.dataset.state = '';
        shareFeedback.hidden = true;
        return;
      }

      shareFeedback.textContent = message;
      shareFeedback.dataset.state = state;
      shareFeedback.hidden = false;
    }

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeShareModal();
      }
    };

    function renderSelectionList(items) {
      if (!shareDocumentSelection || !shareDocumentList) {
        return;
      }

      shareDocumentList.innerHTML = '';

      if (!items.length) {
        shareDocumentSelection.hidden = true;
        return;
      }

      const fragment = document.createDocumentFragment();
      items.forEach((item) => {
        const listItem = document.createElement('li');
        listItem.textContent = item.name || 'intyget';
        fragment.appendChild(listItem);
      });

      shareDocumentList.appendChild(fragment);
      shareDocumentSelection.hidden = false;
    }

    function openShareModal(pdfs, { clearSelection = false } = {}) {
      activePdfIds = pdfs.map((pdf) => pdf.id);
      clearSelectionOnSuccess = clearSelection;
      if (supportsNativeDialog) {
        if (!shareModal.open) {
          shareModal.showModal();
        }
      } else {
        shareModal.classList.add('is-visible');
        shareModal.setAttribute('aria-hidden', 'false');
        document.addEventListener('keydown', handleKeyDown);
      }
      setFeedback('', '');
      shareEmailInput.value = '';
      const focusEmailInput = () => {
        shareEmailInput.focus();
      };
      if (typeof window.requestAnimationFrame === 'function') {
        window.requestAnimationFrame(focusEmailInput);
      } else {
        setTimeout(focusEmailInput, 0);
      }
      if (shareDocumentSummary) {
        if (pdfs.length === 1) {
          shareDocumentSummary.textContent = pdfs[0].name || 'intyget';
        } else if (pdfs.length > 1) {
          shareDocumentSummary.textContent = `${pdfs.length} intyg`;
        } else {
          shareDocumentSummary.textContent = 'intyget';
        }
      }
      renderSelectionList(pdfs);
    }

    function resetShareModalState() {
      activePdfIds = [];
      clearSelectionOnSuccess = false;
      setFeedback('', '');
      if (shareDocumentSummary) {
        shareDocumentSummary.textContent = 'intyget';
      }
      renderSelectionList([]);
    }

    function closeShareModal() {
      if (supportsNativeDialog) {
        if (shareModal.open) {
          shareModal.close();
        }
      } else {
        shareModal.classList.remove('is-visible');
        shareModal.setAttribute('aria-hidden', 'true');
        document.removeEventListener('keydown', handleKeyDown);
        resetShareModalState();
      }
    }

    closeElements.forEach((element) => {
      element.addEventListener('click', () => {
        closeShareModal();
      });
    });

    if (supportsNativeDialog) {
      shareModal.addEventListener('cancel', (event) => {
        event.preventDefault();
        closeShareModal();
      });
      shareModal.addEventListener('close', () => {
        resetShareModalState();
      });
    } else {
      shareModal.addEventListener('click', (event) => {
        if (event.target === shareModal) {
          closeShareModal();
        }
      });
    }

    shareForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      if (isSubmitting) {
        return;
      }

      const email = shareEmailInput.value.trim();
      if (!email) {
        setFeedback('Ange en e-postadress.', 'error');
        shareEmailInput.focus();
        return;
      }

      if (!activePdfIds.length) {
        setFeedback('Det gick inte att identifiera intyget.', 'error');
        return;
      }

      isSubmitting = true;
      submitButton.disabled = true;
      const sendingMessage =
        activePdfIds.length === 1
          ? 'Skickar intyget...'
          : 'Skickar intygen...';
      setFeedback(sendingMessage, 'info');

      try {
        const response = await fetch('/share_pdf', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({
            pdf_ids: activePdfIds,
            recipient_email: email,
          }),
        });

        const data = await response.json().catch(() => ({}));

        if (response.ok) {
          const defaultSuccess =
            activePdfIds.length === 1
              ? 'Intyget har skickats.'
              : 'Intygen har skickats.';
          setFeedback(data.meddelande || defaultSuccess, 'success');
          shareEmailInput.value = '';
          if (clearSelectionOnSuccess) {
            selectionCheckboxes.forEach((checkbox) => {
              checkbox.checked = false;
            });
            updateShareSelectionState();
          }
        } else {
          setFeedback(
            data.fel || 'Det gick inte att skicka intyget.',
            'error'
          );
        }
      } catch (error) {
        setFeedback('Det gick inte att ansluta till servern.', 'error');
      } finally {
        isSubmitting = false;
        submitButton.disabled = false;
      }
    });

    function getSelectedPdfs() {
      return selectionCheckboxes
        .filter((checkbox) => checkbox.checked)
        .map((checkbox) => ({
          id: Number.parseInt(checkbox.value || '', 10),
          name: checkbox.dataset.pdfName || 'intyget',
        }))
        .filter((pdf) => Number.isInteger(pdf.id));
    }

    function updateShareSelectionState() {
      if (!shareSelectedButton) {
        return;
      }

      const selected = getSelectedPdfs();
      shareSelectedButton.disabled = selected.length === 0;
    }

    selectionCheckboxes.forEach((checkbox) => {
      checkbox.addEventListener('change', updateShareSelectionState);
    });

    updateShareSelectionState();

    if (shareSelectedButton) {
      shareSelectedButton.addEventListener('click', () => {
        const selected = getSelectedPdfs();
        if (!selected.length) {
          return;
        }

        openShareModal(selected, { clearSelection: true });
      });
    }

  }

  setupDashboardSearch();
  setupExpiryStatuses();
  setupSupervisorDashboard();
  setupSupervisorShareModal();
  setupEditPdfModal();
  setupShareModal();
})();
