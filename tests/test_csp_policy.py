from pathlib import Path


def test_nginx_conf_includes_csp_header_with_required_directives():
    conf = Path('deploy/nginx/conf.d/app.conf').read_text(encoding='utf-8')

    assert 'add_header Content-Security-Policy' in conf
    assert "default-src 'self'" in conf
    assert "img-src 'self' data:" in conf
    assert "style-src 'self' 'unsafe-inline'" in conf
    assert "script-src 'self'" in conf
    assert "connect-src 'self'" in conf
    assert 'google-analytics.com' in conf
    assert 'analytics.google.com' in conf
    assert 'cdn.consentmanager.net' in conf
    assert "frame-ancestors 'none'" in conf
    assert "base-uri 'self'" in conf
    assert "object-src 'none'" in conf


def test_admin_and_dashboard_templates_do_not_use_inline_script_tags():
    templates = [
        Path('templates/admin_accounts.html'),
        Path('templates/admin_applications.html'),
        Path('templates/dashboard.html'),
        Path('templates/supervisor_dashboard.html'),
        Path('templates/apply_standardkonto.html'),
        Path('templates/base.html'),
    ]

    for template_path in templates:
        content = template_path.read_text(encoding='utf-8')
        assert '<script>' not in content


def test_toast_stylesheet_is_loaded_in_head_not_body():
    content = Path('templates/base.html').read_text(encoding='utf-8')

    head_start = content.find('<head>')
    head_end = content.find('</head>')
    body_start = content.find('<body>')
    link = "<link rel=\"stylesheet\" href=\"{{ url_for('static', filename='css/toasts.css') }}\">"

    assert head_start != -1 and head_end != -1 and body_start != -1
    assert content.find(link, head_start, head_end) != -1
    assert content.find(link, body_start) == -1


# Copyright (c) Liam Suorsa
