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

      button.setAttribute('aria-expanded', shouldExpand ? 'true' : 'false');
      button.textContent = shouldExpand ? closeLabel : openLabel;

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
        card.hidden = !matches;

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

      const updateUrl = activePdfItem.dataset.updateUrl || '';
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

        updatePdfItemView(activePdfItem, data.data || {});
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
  setupSupervisorDashboard();
  setupEditPdfModal();
  setupShareModal();
})();
