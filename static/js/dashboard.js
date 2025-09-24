// static/js/dashboard.js

(() => {
  const checkboxes = Array.from(
    document.querySelectorAll('[data-category-filter]')
  );
  const pdfItems = Array.from(
    document.querySelectorAll('[data-pdf-categories]')
  );
  const noResults = document.getElementById('noFilteredResults');

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
})();
