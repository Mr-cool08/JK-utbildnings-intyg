<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Tester

Det här dokumentet sammanfattar den testsvit som projektet samlar med `pytest`.

Inventeringen nedan bygger på `python -m pytest --collect-only -q tests` den **27 maj 2026**.

## Snabbkörning

- Kör hela testsviten parallellt: `pytest -n auto`
- Fallback utan xdist: `pytest`
- Samla testlista: `python -m pytest --collect-only -q tests`

## Nuvarande omfattning

- Totalt antal tester: **785**
- Antal testfiler: **60**
- Testerna täcker publika flöden, adminpanel, användardashboard, företagskonton, PDF-hantering, loggning, säkerhet, Docker, statussida, prestanda och övervakning.

## Praktiska noter

- `pytest.ini` placerar temporära pytest-filer under `.pytest_tmp/run`.
- Vissa Docker-relaterade tester hoppar över automatiskt om Docker inte finns tillgängligt i miljön.
- Flera tester är stora regressionspaket för admin- och dashboardflöden. Räkna med att hela sviten kan ta tid att köra.

## Testfiler och antal tester

- `tests/test_additional.py` - 50 tester
- `tests/test_admin_applications_api.py` - 7 tester
- `tests/test_admin_client_log.py` - 2 tester
- `tests/test_admin_panel_features.py` - 91 tester
- `tests/test_admin_upload.py` - 7 tester
- `tests/test_antivirus_alert_config.py` - 4 tester
- `tests/test_app_additional.py` - 14 tester
- `tests/test_app_coverage_boost.py` - 8 tester
- `tests/test_application_flow.py` - 15 tester
- `tests/test_certificate_verification.py` - 1 test
- `tests/test_config_loader_additional.py` - 6 tester
- `tests/test_course_categories_bulk.py` - 50 tester
- `tests/test_create_user_route.py` - 1 test
- `tests/test_critical_events.py` - 19 tester
- `tests/test_custom_404.py` - 1 test
- `tests/test_dashboard.py` - 6 tester
- `tests/test_database_logic.py` - 21 tester
- `tests/test_docker_files.py` - 18 tester
- `tests/test_e2e_flows.py` - 2 tester
- `tests/test_email_env.py` - 5 tester
- `tests/test_email_templates.py` - 5 tester
- `tests/test_error_notifications.py` - 1 test
- `tests/test_functions_additional.py` - 11 tester
- `tests/test_functions_extra.py` - 14 tester
- `tests/test_functions_more.py` - 7 tester
- `tests/test_functions_text_utils.py` - 2 tester
- `tests/test_hash_value_deterministic.py` - 200 tester
- `tests/test_health.py` - 1 test
- `tests/test_load_stress.py` - 2 tester
- `tests/test_logging_masking.py` - 3 tester
- `tests/test_logging_utils_additional.py` - 12 tester
- `tests/test_login.py` - 6 tester
- `tests/test_logout.py` - 2 tester
- `tests/test_manage_compose.py` - 20 tester
- `tests/test_normalize_personnummer.py` - 2 tester
- `tests/test_orgnr_validator.py` - 4 tester
- `tests/test_pdf_scanner.py` - 9 tester
- `tests/test_pdf_storage.py` - 7 tester
- `tests/test_performance.py` - 3 tester
- `tests/test_pricing_page.py` - 3 tester
- `tests/test_proxy_fix.py` - 1 test
- `tests/test_public_apply_routes.py` - 8 tester
- `tests/test_request_utils.py` - 6 tester
- `tests/test_save_pdf.py` - 4 tester
- `tests/test_save_pdf_for_user.py` - 4 tester
- `tests/test_server_monitor_config.py` - 9 tester
- `tests/test_server_monitor_smoke.py` - 11 tester
- `tests/test_share_pdf.py` - 5 tester
- `tests/test_sitemap.py` - 2 tester
- `tests/test_sql_injection_protection.py` - 1 test
- `tests/test_supervisor_features.py` - 23 tester
- `tests/test_tls_support.py` - 5 tester
- `tests/test_ui_rendering.py` - 21 tester
- `tests/test_update_app.py` - 5 tester
- `tests/test_user_create.py` - 1 test
- `tests/test_user_management.py` - 2 tester
- `tests/test_user_queries.py` - 2 tester
- `tests/test_user_upload_pdf.py` - 6 tester

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
