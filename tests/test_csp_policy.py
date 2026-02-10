from pathlib import Path


def test_nginx_conf_includes_csp_header_with_required_directives():
    conf = Path('deploy/nginx/conf.d/app.conf').read_text(encoding='utf-8')

    assert 'add_header Content-Security-Policy' in conf
    assert "default-src 'self'" in conf
    assert "img-src 'self' data:" in conf
    assert "style-src 'self' 'unsafe-inline'" in conf
    assert "script-src 'self'" in conf
    assert "frame-ancestors 'none'" in conf
    assert "base-uri 'self'" in conf


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


# Copyright (c) Liam Suorsa
