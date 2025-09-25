// static/js/admin.js

(() => {
  // --- Hämta DOM-element ---
  const form = document.getElementById('adminForm');
  const result = document.getElementById('result');
  const submitBtn = document.getElementById('submitBtn');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');

  // Fält
  const emailInput = document.getElementById('email');
  const usernameInput = document.getElementById('username');
  const pnrInput = document.getElementById('personnummer');
  const pdfInput = document.getElementById('pdf');


  // --- Konstanter (synka gärna med servern) ---
  const MAX_MB = 100; // matchar app.config['MAX_CONTENT_LENGTH']
  const MAX_BYTES = MAX_MB * 1024 * 1024;
  const ALLOWED_MIME = 'application/pdf';

  // --- Hjälpmeddelanden ---
  function showMessage(type, text, isHtml = false) {
    result.style.display = 'block';
    result.className = `message ${type}`;
    if (isHtml) {
      result.innerHTML = text;
    } else {
      result.textContent = text;
    }
  }
  function hideMessage() {
    result.style.display = 'none';
    result.textContent = '';
    result.className = 'message';
  }

  // --- Progress bar handling ---
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

  // --- Enkel validering ---
  function isValidEmail(v) {
    // Enkel men robust e-post-koll
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  }

  function isValidPersonnummer(v) {
    // Tillåt sex eller åtta siffror, valfritt bindestreck och fyra siffror (ÅÅMMDDXXXX eller ÅÅÅÅMMDDXXXX)
    return /^(?:\d{6}|\d{8})-?\d{4}$/.test(v);
  }

  function validatePdf(file) {
    if (!file) return 'PDF-fil saknas.';
    if (file.size > MAX_BYTES) return `Filen är för stor (max ${MAX_MB} MB).`;
    // MIME kan variera mellan browsers – vi dubbelkollar ändå
    if (file.type && file.type !== ALLOWED_MIME) return 'Endast PDF-filer tillåts.';
    // Grundkoll på filändelse (fallback om type saknas)
    if (!/\.pdf$/i.test(file.name)) return 'Filen måste ha ändelsen .pdf.';
    return null;
  }

  // --- Submit-hantering ---
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideMessage();

    // Klientvalidering
    const email = emailInput.value.trim();
    const username = usernameInput.value.trim();
    const pnr = pnrInput.value.trim();
    const files = Array.from(pdfInput.files);

    if (!isValidEmail(email)) {
      showMessage('error', 'Ogiltig e-postadress.');
      emailInput.focus();
      return;
    }
    if (!username) {
      showMessage('error', 'Ange användarnamn.');
      usernameInput.focus();
      return;
    }
    if (!isValidPersonnummer(pnr)) {
      showMessage(
        'error',
        'Ogiltigt personnummer. Ange ÅÅMMDDXXXX eller ÅÅÅÅMMDDXXXX, t.ex. 900101-1234 eller 19900101-1234.'
      );
      pnrInput.focus();
      return;
    }
    if (!files.length) {
      showMessage('error', 'PDF-fil saknas.');
      pdfInput.focus();
      return;
    }
    const totalSize = files.reduce((sum, f) => sum + f.size, 0);
    if (totalSize > MAX_BYTES) {
      showMessage('error', `Filerna är för stora (max ${MAX_MB} MB totalt).`);
      pdfInput.focus();
      return;
    }
    for (const file of files) {
      const pdfError = validatePdf(file);
      if (pdfError) {
        showMessage('error', pdfError);
        pdfInput.focus();
        return;
      }
    }

    // Bygg FormData (måste matcha serverns förväntningar: email, username, personnummer, pdf)
    const fd = new FormData();
    fd.append('email', email);
    fd.append('username', username);
    fd.append('personnummer', pnr);
    for (const file of files) {
      fd.append('pdf', file);
    }

    // Skicka
    submitBtn.disabled = true;
    submitBtn.textContent = 'Skapar...';
    startProgress();

    try {
      const res = await fetch('/admin', {
        method: 'POST',
        body: fd,
        // Viktigt: INTE sätta Content-Type – browsern sätter rätt boundary automatiskt
      });

      // Försök tolka svaret som JSON; om det misslyckas, gör ett snällt fallback-meddelande
      let data = null;
      try {
        data = await res.json();
      } catch {
        // Ignorera – hanteras nedan
      }

      if (res.ok && data && data.status === 'success') {
        const msg = data.link
          ? `Användare skapad. Länk: <a href="${data.link}">${data.link}</a>`
          : 'Användare skapad.';
        showMessage('success', msg, !!data.link);
        form.reset();
      } else {
        const msg =
          (data && (data.message || data.error)) ||
          `Kunde inte skapa användare (HTTP ${res.status}).`;
        showMessage('error', msg);
      }
    } catch (err) {
      showMessage('error', 'Nätverks- eller serverfel. Försök igen om en stund.');
      // Du kan logga err till konsolen för felsökning
      // console.error(err);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Skapa användare';
      stopProgress();
    }
  });

  // --- UX: rensa status när användaren ändrar något ---
  [emailInput, usernameInput, pnrInput, pdfInput, ...categoryInputs].forEach((el) => {
    el.addEventListener('input', () => hideMessage());
    el.addEventListener('change', () => hideMessage());
  });
})();
