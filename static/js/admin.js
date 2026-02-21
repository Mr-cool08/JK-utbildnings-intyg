// # Copyright (c) Liam Suorsa and Mika Suorsa
(() => {
  const form = document.getElementById('adminForm');
  const result = document.getElementById('result');
  const submitBtn = document.getElementById('submitBtn');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');

  const emailInput = document.getElementById('email');
  const usernameInput = document.getElementById('username');
  const pnrInput = document.getElementById('personnummer');
  const pdfInput = document.getElementById('pdf');
  const fileCategoryGroup = document.getElementById('fileCategoryGroup');
  const fileCategoryList = document.getElementById('fileCategoryList');
  const fileCategoryTemplate = document.getElementById('fileCategoryTemplate');

  const MAX_MB = 100;
  const MAX_BYTES = MAX_MB * 1024 * 1024;
  const ALLOWED_MIME = 'application/pdf';

  function showMessage(type, text, isHtml = false) {
    result.style.display = 'block';
    result.className = `message ${type}`;
    if (isHtml) result.innerText = text;
    else result.textContent = text;
  }
  function hideMessage() {
    result.style.display = 'none';
    result.textContent = '';
    result.className = 'message';
  }

  let progressInterval;
  function startProgress() {
    progressContainer.style.display = 'block';
    let width = 0;
    progressBar.style.width = '0%';
    progressInterval = setInterval(() => {
      width = (width + 10) % 100;
      progressBar.style.width = `${width}%`;
    }, 500);
  }
  function stopProgress() {
    progressContainer.style.display = 'none';
    clearInterval(progressInterval);
  }

  function isValidEmail(v) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  }
  function isValidPersonnummer(v) {
    return /^(?:\d{6}|\d{8})-?\d{4}$/.test(v);
  }
  function validatePdf(file) {
    if (!file) return 'PDF-fil saknas.';
    if (file.size > MAX_BYTES) return `Filen är för stor (max ${MAX_MB} MB).`;
    if (file.type && file.type !== ALLOWED_MIME) return 'Endast PDF-filer tillåts.';
    if (!/\.pdf$/i.test(file.name)) return 'Filen måste ha ändelsen .pdf.';
    return null;
  }

  function renderCategorySelectors(files) {
    fileCategoryList.innerHTML = '';
    if (!files.length) {
      fileCategoryGroup.hidden = true;
      return;
    }

    const fragment = document.createDocumentFragment();
    files.forEach((file, index) => {
      const clone = fileCategoryTemplate.content.cloneNode(true);
      const item = clone.querySelector('.file-category-item');
      item.dataset.index = String(index);
      const nameEl = clone.querySelector('.file-name');
      nameEl.textContent = file.name;
      fragment.appendChild(clone);
    });

    fileCategoryList.appendChild(fragment);
    fileCategoryGroup.hidden = false;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideMessage();

    const email = emailInput.value.trim();
    const username = usernameInput.value.trim();
    const pnr = pnrInput.value.trim();
    const files = Array.from(pdfInput.files);
    const categorySelects = Array.from(
      fileCategoryList.querySelectorAll('.file-category-select')
    );

    if (!isValidEmail(email)) { showMessage('error', 'Ogiltig e-postadress.'); emailInput.focus(); return; }
    if (!username) { showMessage('error', 'Ange användarnamn.'); usernameInput.focus(); return; }
    if (!isValidPersonnummer(pnr)) { showMessage('error', 'Ogiltigt personnummer.'); pnrInput.focus(); return; }
    if (!files.length) { showMessage('error', 'PDF-fil saknas.'); pdfInput.focus(); return; }
    if (categorySelects.length !== files.length) {
      showMessage('error', 'Välj kategori för varje PDF.');
      return;
    }

    for (const file of files) {
      const pdfError = validatePdf(file);
      if (pdfError) { showMessage('error', pdfError); pdfInput.focus(); return; }
    }

    const categories = [];
    for (let i = 0; i < categorySelects.length; i += 1) {
      const select = categorySelects[i];
      const value = select.value.trim();
      if (!value) {
        showMessage('error', 'Välj kategori för varje PDF.');
        select.focus();
        return;
      }
      categories.push(value);
    }

    const fd = new FormData();
    fd.append('email', email);
    fd.append('username', username);
    fd.append('personnummer', pnr);
    files.forEach((file, index) => {
      fd.append('pdf', file);
      fd.append('categories', categories[index]);
    });

    submitBtn.disabled = true;
    submitBtn.textContent = 'Skapar...';
    startProgress();

    try {
      const res = await fetch('/admin', { method: 'POST', body: fd });
      const data = await res.json().catch(() => null);

      if (res.ok && data?.status === 'success') {
        const msg = data.link ? `Användarkonto skapat. Länk: <a href="${data.link}">${data.link}</a>` : 'Användarkonto skapat.';
        showMessage('success', msg, !!data.link);
        form.reset();
        renderCategorySelectors([]);
      } else {
        const msg = data?.message || `Kunde inte skapa användarkonto (HTTP ${res.status}).`;
        showMessage('error', msg);
      }
    } catch {
      showMessage('error', 'Nätverks- eller serverfel. Försök igen.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Skapa användarkonto';
      stopProgress();
    }
  });

  [emailInput, usernameInput, pnrInput, pdfInput].forEach(el => {
    el.addEventListener('input', hideMessage);
    el.addEventListener('change', hideMessage);
  });

  pdfInput.addEventListener('change', () => {
    const files = Array.from(pdfInput.files);
    renderCategorySelectors(files);
  });
})();
