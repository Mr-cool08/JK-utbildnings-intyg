(function () {
  const form = document.querySelector('.apply-form');
  if (!form) {
    return;
  }

  const accountRadios = form.querySelectorAll('input[name="account_type"]');
  const invoiceSection = document.getElementById('invoiceSection');
  const invoiceAddress = document.getElementById('invoice_address');
  const invoiceContact = document.getElementById('invoice_contact');
  const invoiceReference = document.getElementById('invoice_reference');

  if (!accountRadios || accountRadios.length === 0) {
    if (invoiceSection) {
      invoiceSection.hidden = false;
    }
    return;
  }

  function toggleInvoiceFields() {
    const selected = form.querySelector('input[name="account_type"]:checked');
    const isHandledare = selected && selected.value === 'handledare';

    if (invoiceSection) {
      invoiceSection.hidden = !isHandledare;
    }
    if (invoiceAddress) {
      invoiceAddress.required = Boolean(isHandledare);
    }
    if (invoiceContact) {
      invoiceContact.required = Boolean(isHandledare);
    }
    if (invoiceReference) {
      invoiceReference.required = Boolean(isHandledare);
    }
  }

  accountRadios.forEach((radio) => {
    radio.addEventListener('change', toggleInvoiceFields);
  });

  document.addEventListener('DOMContentLoaded', toggleInvoiceFields);
  toggleInvoiceFields();
})();
