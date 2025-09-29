(function () {
    const categoryDataElement = document.getElementById('categoryData');
    const categories = categoryDataElement ? JSON.parse(categoryDataElement.textContent) : [];

    const searchForm = document.getElementById('searchForm');
    const searchInput = document.getElementById('searchPersonnummer');
    const resultsSection = document.getElementById('pdfResults');
    const tableBody = document.querySelector('#pdfTable tbody');
    const messageBox = document.getElementById('adminMessage');
    const currentUserLabel = document.getElementById('currentUser');
    const resetForm = document.getElementById('resetForm');
    let currentPersonnummer = '';

    function showMessage(text, isError = false) {
        if (!messageBox) {
            return;
        }
        if (!text) {
            messageBox.style.display = 'none';
            return;
        }
        messageBox.style.display = 'block';
        messageBox.textContent = text;
        messageBox.classList.toggle('error', Boolean(isError));
        messageBox.classList.toggle('success', !isError);
    }

    function formatDate(value) {
        if (!value) {
            return '–';
        }
        try {
            const date = new Date(value);
            if (Number.isNaN(date.getTime())) {
                return value;
            }
            return date.toLocaleString('sv-SE');
        } catch (err) {
            return value;
        }
    }

    function createCategorySelect(selected) {
        const wrapper = document.createElement('div');
        wrapper.className = 'category-select-wrapper';
        const select = document.createElement('select');
        select.multiple = true;
        select.className = 'category-select';

        categories.forEach(([slug, label]) => {
            const option = document.createElement('option');
            option.value = slug;
            option.textContent = label;
            if (selected.includes(slug)) {
                option.selected = true;
            }
            select.appendChild(option);
        });

        wrapper.appendChild(select);
        return { wrapper, select };
    }

    function renderTable(pdfs) {
        tableBody.innerHTML = '';
        if (!pdfs.length) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 5;
            cell.textContent = 'Inga PDF:er hittades för detta personnummer.';
            row.appendChild(cell);
            tableBody.appendChild(row);
            return;
        }

        pdfs.forEach((pdf) => {
            const row = document.createElement('tr');

            const idCell = document.createElement('td');
            idCell.textContent = String(pdf.id);
            row.appendChild(idCell);

            const nameCell = document.createElement('td');
            nameCell.textContent = pdf.filename;
            row.appendChild(nameCell);

            const categoriesCell = document.createElement('td');
            const { wrapper, select } = createCategorySelect(pdf.categories || []);
            categoriesCell.appendChild(wrapper);
            row.appendChild(categoriesCell);

            const uploadedCell = document.createElement('td');
            uploadedCell.textContent = formatDate(pdf.uploaded_at);
            row.appendChild(uploadedCell);

            const actionsCell = document.createElement('td');
            actionsCell.className = 'actions-cell';

            const saveButton = document.createElement('button');
            saveButton.type = 'button';
            saveButton.textContent = 'Spara kategorier';
            saveButton.addEventListener('click', async () => {
                const selectedValues = Array.from(select.selectedOptions).map((option) => option.value);
                if (!selectedValues.length) {
                    showMessage('Välj minst en kategori.', true);
                    return;
                }
                await updateCategories(pdf.id, selectedValues, select);
            });

            const deleteButton = document.createElement('button');
            deleteButton.type = 'button';
            deleteButton.className = 'danger';
            deleteButton.textContent = 'Ta bort';
            deleteButton.addEventListener('click', async () => {
                if (!window.confirm('Är du säker på att du vill ta bort PDF:en?')) {
                    return;
                }
                await deletePdf(pdf.id);
            });

            actionsCell.appendChild(saveButton);
            actionsCell.appendChild(deleteButton);
            row.appendChild(actionsCell);

            tableBody.appendChild(row);
        });
    }

    async function fetchJson(url, body) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await response.json();
        if (!response.ok || data.status !== 'success') {
            const errorMessage = data && data.message ? data.message : 'Ett okänt fel inträffade.';
            throw new Error(errorMessage);
        }
        return data;
    }

    async function loadPdfs(personnummer) {
        showMessage('Hämtar PDF:er …');
        try {
            const data = await fetchJson('/admin/hantera/pdfer', { personnummer });
            currentPersonnummer = personnummer;
            currentUserLabel.textContent = `Personnummer: ${personnummer}`;
            renderTable(data.pdfs || []);
            resultsSection.hidden = false;
            showMessage('PDF:er hämtade.', false);
        } catch (error) {
            resultsSection.hidden = true;
            showMessage(error.message, true);
        }
    }

    async function deletePdf(pdfId) {
        try {
            const data = await fetchJson('/admin/hantera/radera_pdf', {
                personnummer: currentPersonnummer,
                pdf_id: pdfId,
            });
            showMessage(data.message || 'PDF borttagen.');
            await loadPdfs(currentPersonnummer);
        } catch (error) {
            showMessage(error.message, true);
        }
    }

    async function updateCategories(pdfId, categoriesList, selectElement) {
        try {
            const data = await fetchJson('/admin/hantera/uppdatera_kategorier', {
                personnummer: currentPersonnummer,
                pdf_id: pdfId,
                categories: categoriesList,
            });
            showMessage(data.message || 'Kategorier uppdaterade.');
            if (data.categories && Array.isArray(data.categories)) {
                const options = Array.from(selectElement.options);
                options.forEach((option) => {
                    option.selected = data.categories.includes(option.value);
                });
            }
        } catch (error) {
            showMessage(error.message, true);
        }
    }

    if (searchForm) {
        searchForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const value = searchInput.value.trim();
            if (!value) {
                showMessage('Ange ett personnummer.', true);
                return;
            }
            await loadPdfs(value);
        });
    }

    if (resetForm) {
        resetForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const emailInput = document.getElementById('resetEmail');
            const email = emailInput ? emailInput.value.trim() : '';
            if (!email) {
                showMessage('Ange en e-postadress.', true);
                return;
            }
            showMessage('Skickar återställningslänk …');
            try {
                const data = await fetchJson('/admin/hantera/skicka_aterstallning', { email });
                showMessage(data.message || 'Återställningslänk skickad.');
                resetForm.reset();
            } catch (error) {
                showMessage(error.message, true);
            }
        });
    }
})();
