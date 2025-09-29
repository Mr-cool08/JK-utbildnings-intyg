// static/js/dashboard.js

(() => {
  const checkboxes = Array.from(
    document.querySelectorAll('[data-category-filter]')
  );
  const pdfItems = Array.from(
    document.querySelectorAll('[data-pdf-categories]')
  );
  const noResults = document.getElementById('noFilteredResults');

  function setupFiltering() {
    if (!checkboxes.length || !pdfItems.length) {
      if (noResults) {
        noResults.style.display = 'none';
      }
      return;
    }

    function updateVisibility() {
      const active = checkboxes
        .filter((checkbox) => checkbox.checked)
        .map((checkbox) => checkbox.value);

      let visibleCount = 0;

      pdfItems.forEach((item) => {
        const categories = (item.dataset.pdfCategories || '')
          .split(',')
          .map((value) => value.trim())
          .filter((value) => value);
        const matches =
          active.length === 0 ||
          categories.some((category) => active.includes(category));

        item.style.display = matches ? '' : 'none';
        if (matches) {
          visibleCount += 1;
        }
      });

      if (noResults) {
        noResults.style.display = visibleCount === 0 ? 'block' : 'none';
      }
    }

    checkboxes.forEach((checkbox) => {
      checkbox.addEventListener('change', updateVisibility);
    });

    updateVisibility();
  }

  function setupShareModal() {
    const shareModal = document.getElementById('shareModal');
    const shareForm = document.getElementById('shareForm');
    const shareEmailInput = document.getElementById('shareRecipientEmail');
    const shareFeedback = document.getElementById('shareFeedback');
    const shareDocumentSummary = document.getElementById('shareDocumentSummary');
    const shareDocumentSelection = document.getElementById('shareDocumentSelection');
    const shareDocumentList = document.getElementById('shareDocumentList');
    const closeElements = shareModal
      ? Array.from(shareModal.querySelectorAll('[data-share-close]'))
      : [];
    const submitButton = shareForm
      ? shareForm.querySelector('button[type="submit"]')
      : null;
    const shareSelectedButton = document.getElementById('shareSelectedButton');
    const shareSelectionPopup = document.getElementById('shareSelectionPopup');
    const shareSelectionClose = shareSelectionPopup
      ? shareSelectionPopup.querySelector('[data-share-selection-close]')
      : null;
    const selectionCheckboxes = Array.from(
      document.querySelectorAll('[data-share-select]')
    );

    if (!shareModal || !shareForm || !shareEmailInput || !submitButton) {
      return;
    }

    let activePdfIds = [];
    let clearSelectionOnSuccess = false;
    let isSubmitting = false;
    let shareSelectionDismissed = false;
    let shareSelectionHideTimeout;

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

    function showShareSelectionPopup() {
      if (!shareSelectionPopup) {
        return;
      }

      if (shareSelectionHideTimeout) {
        window.clearTimeout(shareSelectionHideTimeout);
        shareSelectionHideTimeout = undefined;
      }

      shareSelectionPopup.hidden = false;
      shareSelectionPopup.setAttribute('aria-hidden', 'false');
      requestAnimationFrame(() => {
        shareSelectionPopup.classList.add('is-visible');
      });
    }

    function hideShareSelectionPopup({ dismiss = false, resetDismissal = false } = {}) {
      if (!shareSelectionPopup) {
        return;
      }

      if (shareSelectionHideTimeout) {
        window.clearTimeout(shareSelectionHideTimeout);
        shareSelectionHideTimeout = undefined;
      }

      if (dismiss) {
        shareSelectionDismissed = true;
      }

      if (resetDismissal) {
        shareSelectionDismissed = false;
      }

      shareSelectionPopup.classList.remove('is-visible');
      shareSelectionPopup.setAttribute('aria-hidden', 'true');
      shareSelectionHideTimeout = window.setTimeout(() => {
        shareSelectionPopup.hidden = true;
        shareSelectionHideTimeout = undefined;
      }, 200);
    }

    function openShareModal(pdfs, { clearSelection = false } = {}) {
      activePdfIds = pdfs.map((pdf) => pdf.id);
      clearSelectionOnSuccess = clearSelection;
      shareModal.classList.add('is-visible');
      shareModal.setAttribute('aria-hidden', 'false');
      setFeedback('', '');
      shareEmailInput.value = '';
      shareEmailInput.focus();
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
      document.addEventListener('keydown', handleKeyDown);
      hideShareSelectionPopup();
    }

    function closeShareModal() {
      activePdfIds = [];
      clearSelectionOnSuccess = false;
      shareModal.classList.remove('is-visible');
      shareModal.setAttribute('aria-hidden', 'true');
      setFeedback('', '');
      if (shareDocumentSummary) {
        shareDocumentSummary.textContent = 'intyget';
      }
      renderSelectionList([]);
      document.removeEventListener('keydown', handleKeyDown);
      if (
        shareSelectionPopup &&
        getSelectedPdfs().length > 0 &&
        !shareSelectionDismissed
      ) {
        showShareSelectionPopup();
      }
    }

    closeElements.forEach((element) => {
      element.addEventListener('click', () => {
        closeShareModal();
      });
    });

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

      if (selected.length === 1) {
        shareSelectedButton.textContent = 'Dela markerat intyg';
      } else if (selected.length > 1) {
        shareSelectedButton.textContent = `Dela ${selected.length} markerade intyg`;
      } else {
        shareSelectedButton.textContent = 'Dela markerade intyg';
      }

      if (!shareSelectionPopup) {
        return;
      }

      if (selected.length === 0) {
        hideShareSelectionPopup({ resetDismissal: true });
      } else if (!shareSelectionDismissed) {
        showShareSelectionPopup();
      }
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

    if (shareSelectionClose) {
      shareSelectionClose.addEventListener('click', () => {
        hideShareSelectionPopup({ dismiss: true });
      });
    }

    const shareButtons = Array.from(
      document.querySelectorAll('[data-share-button]')
    );

    shareButtons.forEach((button) => {
      button.addEventListener('click', () => {
        const pdfId = Number.parseInt(button.dataset.pdfId || '', 10);
        const pdfName = button.dataset.pdfName || 'intyget';

        if (!Number.isInteger(pdfId)) {
          setFeedback('Det gick inte att identifiera intyget.', 'error');
          return;
        }

        openShareModal([{ id: pdfId, name: pdfName }]);
      });
    });
  }

  setupFiltering();
  setupShareModal();
})();
