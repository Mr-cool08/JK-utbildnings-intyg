// # Copyright (c) Liam Suorsa and Mika Suorsa
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
    const isForetagskonto = selected && selected.value === 'foretagskonto';

    if (invoiceSection) {
      invoiceSection.hidden = !isForetagskonto;
    }
    if (invoiceAddress) {
      invoiceAddress.required = Boolean(isForetagskonto);
    }
    if (invoiceContact) {
      invoiceContact.required = Boolean(isForetagskonto);
    }
    if (invoiceReference) {
      invoiceReference.required = Boolean(isForetagskonto);
    }
  }

  accountRadios.forEach((radio) => {
    radio.addEventListener('change', toggleInvoiceFields);
  });

  document.addEventListener('DOMContentLoaded', toggleInvoiceFields);
  toggleInvoiceFields();
})();
