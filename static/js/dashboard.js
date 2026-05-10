// # Copyright (c) Liam Suorsa and Mika Suorsa
// static/js/dashboard.js

(() => {
  function setupDashboardSearch() {
    const searchInput = document.querySelector('[data-dashboard-search]');
    const pdfItems = Array.from(document.querySelectorAll('[data-pdf-item]'));
    const groups = Array.from(document.querySelectorAll('[data-pdf-group]'));
    const emptyState = document.getElementById('dashboardSearchEmpty');

    if (!searchInput || !pdfItems.length) {
      return;
    }

    function filterItems() {
      const query = searchInput.value.toLowerCase().trim();
      let visibleCount = 0;

      pdfItems.forEach((item) => {
        const haystack = item.dataset.searchText || '';
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
  setupShareModal();
})();
