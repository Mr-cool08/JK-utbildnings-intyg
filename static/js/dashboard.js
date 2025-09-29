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
    const shareDocumentName = document.getElementById('shareDocumentName');
    const closeElements = shareModal
      ? Array.from(shareModal.querySelectorAll('[data-share-close]'))
      : [];
    const submitButton = shareForm
      ? shareForm.querySelector('button[type="submit"]')
      : null;

    if (!shareModal || !shareForm || !shareEmailInput || !submitButton) {
      return;
    }

    let activePdfId = null;
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

    function openShareModal(pdfId, pdfName) {
      activePdfId = pdfId;
      shareModal.classList.add('is-visible');
      shareModal.setAttribute('aria-hidden', 'false');
      setFeedback('', '');
      shareEmailInput.value = '';
      shareEmailInput.focus();
      if (shareDocumentName) {
        shareDocumentName.textContent = pdfName || 'intyget';
      }
      document.addEventListener('keydown', handleKeyDown);
    }

    function closeShareModal() {
      activePdfId = null;
      shareModal.classList.remove('is-visible');
      shareModal.setAttribute('aria-hidden', 'true');
      setFeedback('', '');
      document.removeEventListener('keydown', handleKeyDown);
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

      if (!activePdfId) {
        setFeedback('Det gick inte att identifiera intyget.', 'error');
        return;
      }

      isSubmitting = true;
      submitButton.disabled = true;
      setFeedback('Skickar intyget...', 'info');

      try {
        const response = await fetch('/share_pdf', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({
            pdf_id: activePdfId,
            recipient_email: email,
          }),
        });

        const data = await response.json().catch(() => ({}));

        if (response.ok) {
          setFeedback(
            data.meddelande || 'Intyget har skickats.',
            'success'
          );
          shareEmailInput.value = '';
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

        openShareModal(pdfId, pdfName);
      });
    });
  }

  setupFiltering();
  setupShareModal();
})();
