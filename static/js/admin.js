const form = document.getElementById('adminForm');
        const resultBox = document.getElementById('result');
        const submitBtn = document.getElementById('submitBtn');

        function showMessage(text, ok=true) {
            resultBox.style.display = 'block';
            resultBox.className = 'message ' + (ok ? 'success' : 'error');
            resultBox.textContent = text;
        }

        form.addEventListener('submit', async (ev) => {
            ev.preventDefault();
            // Basic validity check
            if (!form.checkValidity()) {
                form.reportValidity();
                return;
            }

            submitBtn.disabled = true;
            showMessage('Sending...', true);

            const data = new FormData(form);

            try {
                const resp = await fetch('/admin', {
                    method: 'POST',
                    body: data
                });

                // server responds with JSON per your main.py
                const json = await resp.json();

                if (resp.ok && json.status === 'success') {
                    showMessage(json.message || 'User created successfully', true);
                    form.reset();
                } else {
                    showMessage(json.message || 'Server returned an error', false);
                }
            } catch (err) {
                showMessage('Network or client error: ' + err.message, false);
            } finally {
                submitBtn.disabled = false;
            }
        });