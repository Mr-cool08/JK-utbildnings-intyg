(() => {
  const DEFAULT_UNEXPECTED_ERROR =
    'Servern svarade med ett oväntat format. Logga in igen och försök på nytt.';

  function getCsrfToken() {
    const tokenFromDataAttribute = document.querySelector('[data-csrf-token]')?.dataset.csrfToken;
    if (tokenFromDataAttribute) return tokenFromDataAttribute;

    const tokenFromMeta = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    if (tokenFromMeta) return tokenFromMeta;

    const tokenFromCookie = document.cookie
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith('csrf_token='))
      ?.split('=')[1];
    if (tokenFromCookie) {
      try {
        return decodeURIComponent(tokenFromCookie);
      } catch {
        return tokenFromCookie;
      }
    }

    return '';
  }

  function isMutatingMethod(method) {
    const normalizedMethod = (method || 'GET').toUpperCase();
    return !['GET', 'HEAD', 'OPTIONS'].includes(normalizedMethod);
  }

  async function sendClientLog(payload) {
    if (!payload) return;
    if (payload.url && payload.url.includes('/admin/api/klientlogg')) return;
    try {
      const csrfToken = getCsrfToken();
      await fetch('/admin/api/klientlogg', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
        },
        body: JSON.stringify(payload),
      });
    } catch {
      return;
    }
  }

  async function parseJsonResponse(response, context) {
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      await sendClientLog({
        message: 'Svarade inte med JSON.',
        context,
        url: response.url,
        status: response.status,
        details: { contentType },
      });
      return null;
    }

    try {
      return await response.json();
    } catch {
      await sendClientLog({
        message: 'Kunde inte tolka JSON.',
        context,
        url: response.url,
        status: response.status,
        details: { contentType },
      });
      return null;
    }
  }

  function buildUnexpectedFormatError() {
    return new Error(DEFAULT_UNEXPECTED_ERROR);
  }

  async function apiRequest(url, options = {}) {
    const {
      method = 'GET',
      body,
      context,
      errorMessage = 'Något gick fel vid kommunikation med servern.',
      headers = {},
    } = options;
    const normalizedMethod = method.toUpperCase();
    const requestHeaders = { ...headers };
    const requestInit = {
      method: normalizedMethod,
      headers: requestHeaders,
    };

    let requestBody = body;
    if (body !== undefined) {
      requestHeaders['Content-Type'] = requestHeaders['Content-Type'] || 'application/json';
      if (requestHeaders['Content-Type'].includes('application/json')) {
        const payload = body && typeof body === 'object' && !Array.isArray(body) ? { ...body } : body;
        if (
          isMutatingMethod(normalizedMethod) &&
          payload &&
          typeof payload === 'object' &&
          !Array.isArray(payload)
        ) {
          const csrfToken = getCsrfToken();
          if (csrfToken && !payload.csrf_token) {
            payload.csrf_token = csrfToken;
          }
        }
        requestBody = JSON.stringify(payload);
      }
      requestInit.body = requestBody;
    }

    if (isMutatingMethod(normalizedMethod)) {
      const csrfToken = getCsrfToken();
      if (csrfToken) {
        requestHeaders['X-CSRF-Token'] = csrfToken;
      }
    }

    let response;
    try {
      response = await fetch(url, requestInit);
    } catch {
      throw new Error('Kunde inte nå servern. Försök igen.');
    }

    const data = await parseJsonResponse(response, context);
    if (data === null) {
      throw buildUnexpectedFormatError();
    }
    if (!response.ok) {
      throw new Error(data.message || errorMessage);
    }

    return data;
  }

  async function apiGet(url, options = {}) {
    return apiRequest(url, { ...options, method: 'GET' });
  }

  async function apiPost(url, body, options = {}) {
    return apiRequest(url, { ...options, method: 'POST', body });
  }

  async function apiDelete(url, body, options = {}) {
    return apiRequest(url, { ...options, method: 'DELETE', body });
  }

  window.AdminApiClient = {
    apiRequest,
    apiGet,
    apiPost,
    apiDelete,
    sendClientLog,
    buildUnexpectedFormatError,
  };
})();
/* # Copyright (c) Liam Suorsa */
