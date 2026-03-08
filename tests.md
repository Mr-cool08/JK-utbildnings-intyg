# Tests.md

Detta dokument beskriver alla testtyper och samtliga tester som samlas av `pytest` i projektet.

## Snabb körning

- Kör hela testsviten: `pytest`
- Kör i parallell om xdist finns: `pytest -n auto`
- Samla testlista: `pytest --collect-only -q`

- Totalt antal tester i denna inventering: **694**

## Testtyper

### Smoke-tester (övervakning)

- Antal testfiler: **1**
- Antal tester: **4**
- Filer:
  - `tests/test_server_monitor_smoke.py` (4 tester)

### E2E-tester

- Antal testfiler: **1**
- Antal tester: **2**
- Filer:
  - `tests/test_e2e_flows.py` (2 tester)

### UI-tester

- Antal testfiler: **1**
- Antal tester: **5**
- Filer:
  - `tests/test_ui_rendering.py` (5 tester)

### Prestandatester

- Antal testfiler: **1**
- Antal tester: **3**
- Filer:
  - `tests/test_performance.py` (3 tester)

### Belastnings- och stresstester

- Antal testfiler: **1**
- Antal tester: **2**
- Filer:
  - `tests/test_load_stress.py` (2 tester)

### Säkerhetstester

- Antal testfiler: **5**
- Antal tester: **18**
- Filer:
  - `tests/test_certificate_verification.py` (1 tester)
  - `tests/test_logging_masking.py` (3 tester)
  - `tests/test_pdf_scanner.py` (8 tester)
  - `tests/test_sql_injection_protection.py` (1 tester)
  - `tests/test_tls_support.py` (5 tester)

### Infrastruktur- och driftstester

- Antal testfiler: **5**
- Antal tester: **68**
- Filer:
  - `tests/test_docker_files.py` (12 tester)
  - `tests/test_manage_compose.py` (20 tester)
  - `tests/test_server_monitor_config.py` (9 tester)
  - `tests/test_status_service.py` (22 tester)
  - `tests/test_update_app.py` (5 tester)

### Integrationstester

- Antal testfiler: **21**
- Antal tester: **173**
- Filer:
  - `tests/test_admin_applications_api.py` (7 tester)
  - `tests/test_admin_client_log.py` (2 tester)
  - `tests/test_admin_panel_features.py` (82 tester)
  - `tests/test_admin_upload.py` (5 tester)
  - `tests/test_app_additional.py` (14 tester)
  - `tests/test_app_coverage_boost.py` (8 tester)
  - `tests/test_application_flow.py` (12 tester)
  - `tests/test_create_user_route.py` (1 tester)
  - `tests/test_custom_404.py` (1 tester)
  - `tests/test_dashboard.py` (2 tester)
  - `tests/test_demo_mode.py` (4 tester)
  - `tests/test_health.py` (1 tester)
  - `tests/test_login.py` (5 tester)
  - `tests/test_logout.py` (2 tester)
  - `tests/test_pricing_page.py` (2 tester)
  - `tests/test_proxy_fix.py` (1 tester)
  - `tests/test_public_apply_routes.py` (4 tester)
  - `tests/test_share_pdf.py` (5 tester)
  - `tests/test_sitemap.py` (2 tester)
  - `tests/test_supervisor_features.py` (11 tester)
  - `tests/test_user_upload_pdf.py` (2 tester)

### Enhetstester

- Antal testfiler: **24**
- Antal tester: **419**
- Filer:
  - `tests/test_additional.py` (50 tester)
  - `tests/test_antivirus_alert_config.py` (4 tester)
  - `tests/test_config_loader_additional.py` (6 tester)
  - `tests/test_course_categories_bulk.py` (50 tester)
  - `tests/test_critical_events.py` (19 tester)
  - `tests/test_database_logic.py` (11 tester)
  - `tests/test_email_env.py` (4 tester)
  - `tests/test_email_templates.py` (3 tester)
  - `tests/test_error_notifications.py` (1 tester)
  - `tests/test_functions_additional.py` (11 tester)
  - `tests/test_functions_extra.py` (13 tester)
  - `tests/test_functions_more.py` (7 tester)
  - `tests/test_functions_text_utils.py` (2 tester)
  - `tests/test_hash_value_deterministic.py` (200 tester)
  - `tests/test_logging_utils_additional.py` (9 tester)
  - `tests/test_normalize_personnummer.py` (2 tester)
  - `tests/test_orgnr_validator.py` (4 tester)
  - `tests/test_pdf_storage.py` (5 tester)
  - `tests/test_request_utils.py` (6 tester)
  - `tests/test_save_pdf.py` (4 tester)
  - `tests/test_save_pdf_for_user.py` (3 tester)
  - `tests/test_user_create.py` (1 tester)
  - `tests/test_user_management.py` (2 tester)
  - `tests/test_user_queries.py` (2 tester)

## Fullständig testlista

Nedan listas alla tester per fil (samma namn som i `pytest --collect-only -q`).

### `tests/test_additional.py`

- Typ: **Enhetstester**
- Antal tester i filen: **50**
- Tester:
  - `tests/test_additional.py::test_hash_value_deterministic[input0]`
  - `tests/test_additional.py::test_hash_value_deterministic[input1]`
  - `tests/test_additional.py::test_hash_value_deterministic[input2]`
  - `tests/test_additional.py::test_hash_value_deterministic[input3]`
  - `tests/test_additional.py::test_hash_value_deterministic[input4]`
  - `tests/test_additional.py::test_hash_value_deterministic[input5]`
  - `tests/test_additional.py::test_hash_value_deterministic[input6]`
  - `tests/test_additional.py::test_hash_value_deterministic[input7]`
  - `tests/test_additional.py::test_hash_value_deterministic[input8]`
  - `tests/test_additional.py::test_hash_value_deterministic[input9]`
  - `tests/test_additional.py::test_hash_password_verify[pass0]`
  - `tests/test_additional.py::test_hash_password_verify[pass1]`
  - `tests/test_additional.py::test_hash_password_verify[pass2]`
  - `tests/test_additional.py::test_hash_password_verify[pass3]`
  - `tests/test_additional.py::test_hash_password_verify[pass4]`
  - `tests/test_additional.py::test_hash_password_verify[pass5]`
  - `tests/test_additional.py::test_hash_password_verify[pass6]`
  - `tests/test_additional.py::test_hash_password_verify[pass7]`
  - `tests/test_additional.py::test_hash_password_verify[pass8]`
  - `tests/test_additional.py::test_hash_password_verify[pass9]`
  - `tests/test_additional.py::test_verify_password_fails[pass0]`
  - `tests/test_additional.py::test_verify_password_fails[pass1]`
  - `tests/test_additional.py::test_verify_password_fails[pass2]`
  - `tests/test_additional.py::test_verify_password_fails[pass3]`
  - `tests/test_additional.py::test_verify_password_fails[pass4]`
  - `tests/test_additional.py::test_verify_password_fails[pass5]`
  - `tests/test_additional.py::test_verify_password_fails[pass6]`
  - `tests/test_additional.py::test_verify_password_fails[pass7]`
  - `tests/test_additional.py::test_verify_password_fails[pass8]`
  - `tests/test_additional.py::test_verify_password_fails[pass9]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900101-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900102-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900103-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900104-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900105-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900106-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900107-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900108-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900109-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_valid[19900110-0000]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[19900101]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[abc]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[19900101-000]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[1990010100000]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[990101-000]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[1990010]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[19900101000]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[19900101-0000a1]`
  - `tests/test_additional.py::test_normalize_personnummer_invalid[19900101000000]`

### `tests/test_admin_applications_api.py`

- Typ: **Integrationstester**
- Antal tester i filen: **7**
- Tester:
  - `tests/test_admin_applications_api.py::test_admin_list_applications`
  - `tests/test_admin_applications_api.py::test_admin_get_application_by_id`
  - `tests/test_admin_applications_api.py::test_admin_approve_application_api`
  - `tests/test_admin_applications_api.py::test_admin_approve_standard_application_creates_activation_link`
  - `tests/test_admin_applications_api.py::test_admin_approve_application_validation_error_returns_400`
  - `tests/test_admin_applications_api.py::test_admin_reject_application_system_error_returns_500`
  - `tests/test_admin_applications_api.py::test_admin_reject_application_api`

### `tests/test_admin_client_log.py`

- Typ: **Integrationstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_admin_client_log.py::test_admin_client_log_records_warning`
  - `tests/test_admin_client_log.py::test_admin_client_log_rejects_invalid_payload`

### `tests/test_admin_panel_features.py`

- Typ: **Integrationstester**
- Antal tester i filen: **82**
- Tester:
  - `tests/test_admin_panel_features.py::test_admin_delete_pdf_removes_record`
  - `tests/test_admin_panel_features.py::test_admin_update_pdf_categories`
  - `tests/test_admin_panel_features.py::test_admin_delete_account_removes_records`
  - `tests/test_admin_panel_features.py::test_admin_delete_account_without_email`
  - `tests/test_admin_panel_features.py::test_admin_guide_renders_markdown`
  - `tests/test_admin_panel_features.py::test_password_reset_flow`
  - `tests/test_admin_panel_features.py::test_password_reset_for_pending_user`
  - `tests/test_admin_panel_features.py::test_supervisor_password_reset_flow`
  - `tests/test_admin_panel_features.py::test_admin_list_accounts_returns_active_and_pending`
  - `tests/test_admin_panel_features.py::test_admin_update_account_returns_error_when_summary_missing`
  - `tests/test_admin_panel_features.py::test_admin_update_account_updates_record`
  - `tests/test_admin_panel_features.py::test_admin_remove_supervisor_connection`
  - `tests/test_admin_panel_features.py::test_admin_change_supervisor_connection`
  - `tests/test_admin_panel_features.py::test_admin_remove_supervisor_connection_by_hash`
  - `tests/test_admin_panel_features.py::test_admin_delete_supervisor_account`
  - `tests/test_admin_panel_features.py::test_password_reset_token_lifecycle`
  - `tests/test_admin_panel_features.py::test_password_reset_token_expires`
  - `tests/test_admin_panel_features.py::test_password_reset_token_requires_matching_user`
  - `tests/test_admin_panel_features.py::test_admin_advanced_crud`
  - `tests/test_admin_panel_features.py::test_admin_protected_endpoints_count`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/guide-302]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/konton-302]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/intyg-302]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/foretagskonto-302]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/ansokningar-302]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/ansokningar-302]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/fakturering-302]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/api/ansokningar-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/api/ansokningar/1-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/api/ansokningar/2-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/ansokningar/1/godkann-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/ansokningar/2/godkann-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/ansokningar/1/avslag-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/ansokningar/2/avslag-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/oversikt-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/klientlogg-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/radera-pdf-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/radera-konto-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/api/konton/lista-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/konton/uppdatera-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/konton/losenord-status-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/konton/skapa-losenordslank-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/uppdatera-pdf-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/skicka-aterstallning-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/foretagskonto/skapa-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/foretagskonto/koppla-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/foretagskonto/oversikt-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/foretagskonto/ta-bort-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/foretagskonto/uppdatera-koppling-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/foretagskonto/radera-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/avancerat-302]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/advanced/api/schema/pending_users-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/advanced/api/schema/users-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/advanced/api/rows/pending_users-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/advanced/api/rows/users-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/advanced/api/rows/pending_users-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/advanced/api/rows/users-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[put-/admin/advanced/api/rows/pending_users/1-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[put-/admin/advanced/api/rows/users/1-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[delete-/admin/advanced/api/rows/pending_users/1-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[delete-/admin/advanced/api/rows/users/1-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/api/ansokningar/99-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/ansokningar/99/godkann-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/ansokningar/99/avslag-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[put-/admin/advanced/api/rows/pending_users/99-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[delete-/admin/advanced/api/rows/pending_users/99-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[put-/admin/advanced/api/rows/users/99-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[delete-/admin/advanced/api/rows/users/99-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/api/ansokningar/12345-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/ansokningar/12345/godkann-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[post-/admin/api/ansokningar/12345/avslag-403]`
  - `tests/test_admin_panel_features.py::test_admin_routes_require_login[get-/admin/advanced/api/schema/company_users-403]`
  - `tests/test_admin_panel_features.py::test_admin_password_status_pending_account`
  - `tests/test_admin_panel_features.py::test_admin_send_create_password_link`
  - `tests/test_admin_panel_features.py::test_admin_password_status_without_email`
  - `tests/test_admin_panel_features.py::test_admin_send_create_password_link_with_override_email`
  - `tests/test_admin_panel_features.py::test_admin_send_create_password_link_rejects_invalid_email`
  - `tests/test_admin_panel_features.py::test_admin_send_create_password_link_without_email`
  - `tests/test_admin_panel_features.py::test_admin_password_status_active_account`
  - `tests/test_admin_panel_features.py::test_admin_send_create_password_link_rejects_active_account`
  - `tests/test_admin_panel_features.py::test_admin_password_status_requires_csrf`
  - `tests/test_admin_panel_features.py::test_admin_send_create_password_link_requires_csrf`

### `tests/test_admin_upload.py`

- Typ: **Integrationstester**
- Antal tester i filen: **5**
- Tester:
  - `tests/test_admin_upload.py::test_admin_upload_existing_user_only_saves_pdf`
  - `tests/test_admin_upload.py::test_admin_upload_existing_email`
  - `tests/test_admin_upload.py::test_admin_upload_pending_user`
  - `tests/test_admin_upload.py::test_admin_upload_multiple_pdfs_with_individual_categories`
  - `tests/test_admin_upload.py::test_admin_upload_requires_category`

### `tests/test_antivirus_alert_config.py`

- Typ: **Enhetstester**
- Antal tester i filen: **4**
- Tester:
  - `tests/test_antivirus_alert_config.py::test_antivirus_alert_env_is_configured`
  - `tests/test_antivirus_alert_config.py::test_antivirus_send_alert_email_command_present`
  - `tests/test_antivirus_alert_config.py::test_antivirus_does_not_copy_or_move_infected_files`
  - `tests/test_antivirus_alert_config.py::test_antivirus_extra_excludes_are_configurable`

### `tests/test_app_additional.py`

- Typ: **Integrationstester**
- Antal tester i filen: **14**
- Tester:
  - `tests/test_app_additional.py::test_trusted_proxy_hops_handles_defaults_and_invalid`
  - `tests/test_app_additional.py::test_configure_proxy_fix_applies_when_positive`
  - `tests/test_app_additional.py::test_configure_proxy_fix_disabled_when_zero`
  - `tests/test_app_additional.py::test_resolve_secret_key_generates_in_pytest`
  - `tests/test_app_additional.py::test_enable_debug_mode_sets_handlers_and_creates_user`
  - `tests/test_app_additional.py::test_create_app_enables_demo_mode`
  - `tests/test_app_additional.py::test_create_app_dev_mode_seeds_demo_accounts_without_demo_mode`
  - `tests/test_app_additional.py::test_create_app_enables_debug_mode_via_dev_mode`
  - `tests/test_app_additional.py::test_create_app_defaults_without_debug`
  - `tests/test_app_additional.py::test_create_app_forces_info_level_when_dev_mode_is_off`
  - `tests/test_app_additional.py::test_debug_clear_session_requires_debug`
  - `tests/test_app_additional.py::test_debug_clear_session_clears_session_in_debug`
  - `tests/test_app_additional.py::test_configure_timezone_uses_stockholm_default`
  - `tests/test_app_additional.py::test_configure_timezone_uses_env_override`

### `tests/test_app_coverage_boost.py`

- Typ: **Integrationstester**
- Antal tester i filen: **8**
- Tester:
  - `tests/test_app_coverage_boost.py::test_start_demo_reset_scheduler`
  - `tests/test_app_coverage_boost.py::test_create_user_routes`
  - `tests/test_app_coverage_boost.py::test_supervisor_create_branches`
  - `tests/test_app_coverage_boost.py::test_supervisor_login_paths`
  - `tests/test_app_coverage_boost.py::test_supervisor_login_requires_csrf`
  - `tests/test_app_coverage_boost.py::test_user_upload_and_dashboard_actions`
  - `tests/test_app_coverage_boost.py::test_user_upload_error_paths`
  - `tests/test_app_coverage_boost.py::test_dashboard_actions_csrf_failures`

### `tests/test_application_flow.py`

- Typ: **Integrationstester**
- Antal tester i filen: **12**
- Tester:
  - `tests/test_application_flow.py::test_application_approval_creates_company_and_user`
  - `tests/test_application_flow.py::test_application_rejection_stores_reason`
  - `tests/test_application_flow.py::test_approval_reuses_existing_company`
  - `tests/test_application_flow.py::test_foretagskonto_and_standard_can_share_email`
  - `tests/test_application_flow.py::test_foretagskonto_application_rejects_duplicate_orgnr`
  - `tests/test_application_flow.py::test_missing_invoice_fields_for_foretagskonto_raises`
  - `tests/test_application_flow.py::test_standard_application_requires_personnummer`
  - `tests/test_application_flow.py::test_standard_application_rejects_duplicate_personnummer`
  - `tests/test_application_flow.py::test_list_companies_for_invoicing`
  - `tests/test_application_flow.py::test_list_companies_for_invoicing_counts_connected_users`
  - `tests/test_application_flow.py::test_standard_application_without_orgnr_can_be_godkannas`
  - `tests/test_application_flow.py::test_standard_application_rejects_orgnr`

### `tests/test_certificate_verification.py`

- Typ: **Säkerhetstester**
- Antal tester i filen: **1**
- Tester:
  - `tests/test_certificate_verification.py::test_verify_certificate_caching_and_message`

### `tests/test_config_loader_additional.py`

- Typ: **Enhetstester**
- Antal tester i filen: **6**
- Tester:
  - `tests/test_config_loader_additional.py::test_resolve_unique_paths_skips_empty_entries`
  - `tests/test_config_loader_additional.py::test_resolve_unique_paths_expands_user_home`
  - `tests/test_config_loader_additional.py::test_resolve_unique_paths_ignores_duplicates`
  - `tests/test_config_loader_additional.py::test_load_environment_loads_existing_candidates`
  - `tests/test_config_loader_additional.py::test_load_environment_uses_fallback_when_missing`
  - `tests/test_config_loader_additional.py::test_load_environment_does_not_override_demo_mode`

### `tests/test_course_categories_bulk.py`

- Typ: **Enhetstester**
- Antal tester i filen: **50**
- Tester:
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values0-expected0]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values1-expected1]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values2-expected2]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values3-expected3]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values4-expected4]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values5-expected5]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values6-expected6]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values7-expected7]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values8-expected8]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values9-expected9]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values10-expected10]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values11-expected11]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values12-expected12]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values13-expected13]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values14-expected14]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values15-expected15]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values16-expected16]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values17-expected17]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values18-expected18]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values19-expected19]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values20-expected20]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values21-expected21]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values22-expected22]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values23-expected23]`
  - `tests/test_course_categories_bulk.py::test_normalize_category_slugs[input_values24-expected24]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs0-expected_labels0]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs1-expected_labels1]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs2-expected_labels2]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs3-expected_labels3]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs4-expected_labels4]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs5-expected_labels5]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs6-expected_labels6]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs7-expected_labels7]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs8-expected_labels8]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs9-expected_labels9]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs10-expected_labels10]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs11-expected_labels11]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs12-expected_labels12]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs13-expected_labels13]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs14-expected_labels14]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs15-expected_labels15]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs16-expected_labels16]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs17-expected_labels17]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs18-expected_labels18]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs19-expected_labels19]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs20-expected_labels20]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs21-expected_labels21]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs22-expected_labels22]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs23-expected_labels23]`
  - `tests/test_course_categories_bulk.py::test_labels_for_slugs[slugs24-expected_labels24]`

### `tests/test_create_user_route.py`

- Typ: **Integrationstester**
- Antal tester i filen: **1**
- Tester:
  - `tests/test_create_user_route.py::test_create_user_route_moves_pending_user`

### `tests/test_critical_events.py`

- Typ: **Enhetstester**
- Antal tester i filen: **19**
- Tester:
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_get_admin_email`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_get_admin_emails_multiple`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_get_admin_emails_with_whitespace`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_get_admin_email_missing`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_get_admin_email_empty`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_get_app_name`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_get_app_name_default`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_send_startup_notification`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_send_startup_notification_multiple_recipients`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_send_crash_notification`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_send_critical_error_notification`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_send_critical_event_email_with_error_message`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_html_escaping_in_error_message`
  - `tests/test_critical_events.py::TestCriticalEventsNotifications::test_send_unhandled_exception_notification`
  - `tests/test_critical_events.py::TestCriticalEventIntegration::test_health_endpoint_works`
  - `tests/test_critical_events.py::test_email_error_handler_logs_failure_without_recursive_notification`
  - `tests/test_critical_events.py::test_send_email_async_logs_email_failure_via_failure_logger`
  - `tests/test_critical_events.py::test_error_email_is_rate_limited`
  - `tests/test_critical_events.py::test_error_email_rate_limit_expires`

### `tests/test_custom_404.py`

- Typ: **Integrationstester**
- Antal tester i filen: **1**
- Tester:
  - `tests/test_custom_404.py::test_custom_404_page`

### `tests/test_dashboard.py`

- Typ: **Integrationstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_dashboard.py::test_dashboard_shows_only_user_pdfs`
  - `tests/test_dashboard.py::test_dashboard_capitalizes_first_letter_of_forename_and_surname`

### `tests/test_database_logic.py`

- Typ: **Enhetstester**
- Antal tester i filen: **11**
- Tester:
  - `tests/test_database_logic.py::test_run_migrations_creates_schema_migrations_table`
  - `tests/test_database_logic.py::test_run_migrations_skips_applied_versions`
  - `tests/test_database_logic.py::test_migration_0004_raises_for_unsupported_dialect`
  - `tests/test_database_logic.py::test_create_database_backfills_columns_and_aux_tables`
  - `tests/test_database_logic.py::test_switch_postgres_host_returns_false_without_fallback_hosts`
  - `tests/test_database_logic.py::test_switch_postgres_host_returns_false_for_non_dns_error`
  - `tests/test_database_logic.py::test_switch_postgres_host_returns_false_when_only_current_host_is_listed`
  - `tests/test_database_logic.py::test_company_users_unique_constraint_blocks_duplicate_email_role`
  - `tests/test_database_logic.py::test_company_users_allows_same_email_for_different_roles`
  - `tests/test_database_logic.py::test_build_engine_requires_postgres_user_when_host_is_set`
  - `tests/test_database_logic.py::test_build_engine_requires_postgres_db_when_host_is_set`

### `tests/test_demo_mode.py`

- Typ: **Integrationstester**
- Antal tester i filen: **4**
- Tester:
  - `tests/test_demo_mode.py::test_ensure_demo_data_creates_accounts`
  - `tests/test_demo_mode.py::test_ensure_demo_data_is_idempotent`
  - `tests/test_demo_mode.py::test_demo_menu_link_points_to_main_domain`
  - `tests/test_demo_mode.py::test_reset_demo_database_recreates_defaults`

### `tests/test_docker_files.py`

- Typ: **Infrastruktur- och driftstester**
- Antal tester i filen: **12**
- Tester:
  - `tests/test_docker_files.py::test_dockerfile_uses_python_base_image`
  - `tests/test_docker_files.py::test_dockerfile_uses_stable_python_tag`
  - `tests/test_docker_files.py::test_dockerfile_exposes_port_and_runs_entrypoint`
  - `tests/test_docker_files.py::test_compose_avoids_host_volumes`
  - `tests/test_docker_files.py::test_compose_uses_direct_host_port_bindings_for_main_services`
  - `tests/test_docker_files.py::test_entrypoint_runs_gunicorn_only`
  - `tests/test_docker_files.py::test_dockerfile_installs_openssl`
  - `tests/test_docker_files.py::test_builds_production_app_image_with_pytest_docker`
  - `tests/test_docker_files.py::test_builds_dev_status_image_with_pytest_docker`
  - `tests/test_docker_files.py::test_status_service_dockerfile_copies_functions_package`
  - `tests/test_docker_files.py::test_status_service_dockerfile_copies_config_loader_module`
  - `tests/test_docker_files.py::test_status_service_dockerfile_has_healthcheck_for_root_endpoint`

### `tests/test_e2e_flows.py`

- Typ: **E2E-tester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_e2e_flows.py::test_e2e_standardkonto_flow_application_to_upload_and_share`
  - `tests/test_e2e_flows.py::test_e2e_foretagskonto_flow_application_to_link_request_and_acceptance`

### `tests/test_email_env.py`

- Typ: **Enhetstester**
- Antal tester i filen: **4**
- Tester:
  - `tests/test_email_env.py::test_send_creation_email_uses_env_credentials`
  - `tests/test_email_env.py::test_send_creation_email_uses_ssl_on_port_465`
  - `tests/test_email_env.py::test_send_creation_email_uses_configured_from_address`
  - `tests/test_email_env.py::test_send_creation_email_raises_on_refused_recipient`

### `tests/test_email_templates.py`

- Typ: **Enhetstester**
- Antal tester i filen: **3**
- Tester:
  - `tests/test_email_templates.py::test_send_application_rejection_email_uses_branded_support_email`
  - `tests/test_email_templates.py::test_send_email_skips_when_disable_emails_enabled`
  - `tests/test_email_templates.py::test_should_disable_email_sending_is_false_without_flag`

### `tests/test_error_notifications.py`

- Typ: **Enhetstester**
- Antal tester i filen: **1**
- Tester:
  - `tests/test_error_notifications.py::test_email_error_handler_sends_emails_with_attachments`

### `tests/test_functions_additional.py`

- Typ: **Enhetstester**
- Antal tester i filen: **11**
- Tester:
  - `tests/test_functions_additional.py::test_normalize_personnummer`
  - `tests/test_functions_additional.py::test_admin_and_user_create_flow`
  - `tests/test_functions_additional.py::test_dev_mode_creates_sqlite`
  - `tests/test_functions_additional.py::test_demo_mode_creates_sqlite_without_dev_mode`
  - `tests/test_functions_additional.py::test_demo_mode_overrides_database_url`
  - `tests/test_functions_additional.py::test_build_engine_enables_postgres_pool_safety`
  - `tests/test_functions_additional.py::test_build_engine_skips_psycopg_when_import_fails`
  - `tests/test_functions_additional.py::test_create_database_retries_on_operational_error`
  - `tests/test_functions_additional.py::test_switch_postgres_host_after_dns_error`
  - `tests/test_functions_additional.py::test_migration_0008_postgres_is_idempotent[True-False]`
  - `tests/test_functions_additional.py::test_migration_0008_postgres_is_idempotent[False-True]`

### `tests/test_functions_extra.py`

- Typ: **Enhetstester**
- Antal tester i filen: **13**
- Tester:
  - `tests/test_functions_extra.py::test_normalize_email_trims_and_lowercases`
  - `tests/test_functions_extra.py::test_normalize_email_rejects_newlines`
  - `tests/test_functions_extra.py::test_hash_value_deterministic`
  - `tests/test_functions_extra.py::test_hash_password_verify`
  - `tests/test_functions_extra.py::test_check_pending_user_and_hash`
  - `tests/test_functions_extra.py::test_admin_create_user_duplicate`
  - `tests/test_functions_extra.py::test_check_personnummer_password`
  - `tests/test_functions_extra.py::test_get_user_info`
  - `tests/test_functions_extra.py::test_user_create_user_fails_if_exists`
  - `tests/test_functions_extra.py::test_hash_value_uniqueness_stress`
  - `tests/test_functions_extra.py::test_check_password_user_and_get_username`
  - `tests/test_functions_extra.py::test_get_username_by_personnummer_hash`
  - `tests/test_functions_extra.py::test_invalid_hash_inputs_return_safe_defaults`

### `tests/test_functions_more.py`

- Typ: **Enhetstester**
- Antal tester i filen: **7**
- Tester:
  - `tests/test_functions_more.py::test_check_pending_user_hash_missing`
  - `tests/test_functions_more.py::test_admin_create_user_single_pdf`
  - `tests/test_functions_more.py::test_check_password_user_nonexistent`
  - `tests/test_functions_more.py::test_get_username_nonexistent`
  - `tests/test_functions_more.py::test_create_database_creates_tables`
  - `tests/test_functions_more.py::test_verify_certificate_not_found`
  - `tests/test_functions_more.py::test_user_create_user_no_pending`

### `tests/test_functions_text_utils.py`

- Typ: **Enhetstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_functions_text_utils.py::test_is_truthy_various_inputs`
  - `tests/test_functions_text_utils.py::test_clean_optional_text_trims_and_limits_length`

### `tests/test_hash_value_deterministic.py`

- Typ: **Enhetstester**
- Antal tester i filen: **200**
- Tester:
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value0]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value1]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value2]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value3]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value4]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value5]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value6]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value7]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value8]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value9]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value10]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value11]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value12]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value13]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value14]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value15]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value16]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value17]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value18]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value19]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value20]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value21]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value22]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value23]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value24]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value25]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value26]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value27]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value28]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value29]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value30]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value31]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value32]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value33]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value34]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value35]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value36]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value37]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value38]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value39]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value40]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value41]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value42]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value43]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value44]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value45]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value46]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value47]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value48]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value49]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value50]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value51]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value52]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value53]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value54]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value55]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value56]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value57]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value58]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value59]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value60]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value61]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value62]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value63]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value64]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value65]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value66]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value67]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value68]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value69]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value70]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value71]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value72]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value73]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value74]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value75]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value76]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value77]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value78]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value79]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value80]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value81]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value82]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value83]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value84]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value85]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value86]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value87]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value88]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value89]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value90]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value91]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value92]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value93]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value94]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value95]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value96]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value97]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value98]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value99]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value100]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value101]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value102]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value103]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value104]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value105]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value106]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value107]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value108]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value109]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value110]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value111]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value112]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value113]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value114]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value115]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value116]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value117]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value118]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value119]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value120]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value121]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value122]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value123]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value124]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value125]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value126]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value127]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value128]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value129]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value130]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value131]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value132]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value133]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value134]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value135]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value136]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value137]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value138]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value139]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value140]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value141]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value142]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value143]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value144]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value145]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value146]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value147]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value148]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value149]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value150]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value151]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value152]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value153]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value154]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value155]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value156]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value157]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value158]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value159]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value160]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value161]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value162]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value163]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value164]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value165]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value166]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value167]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value168]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value169]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value170]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value171]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value172]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value173]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value174]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value175]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value176]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value177]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value178]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value179]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value180]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value181]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value182]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value183]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value184]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value185]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value186]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value187]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value188]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value189]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value190]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value191]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value192]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value193]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value194]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value195]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value196]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value197]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value198]`
  - `tests/test_hash_value_deterministic.py::test_hash_value_deterministic[value199]`

### `tests/test_health.py`

- Typ: **Integrationstester**
- Antal tester i filen: **1**
- Tester:
  - `tests/test_health.py::test_health_endpoint_returns_ok`

### `tests/test_load_stress.py`

- Typ: **Belastnings- och stresstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_load_stress.py::test_load_public_routes_high_traffic_stays_available`
  - `tests/test_load_stress.py::test_stress_mixed_authenticated_traffic_handles_burst_load`

### `tests/test_logging_masking.py`

- Typ: **Säkerhetstester**
- Antal tester i filen: **3**
- Tester:
  - `tests/test_logging_masking.py::test_save_pdf_logging_masks_personnummer`
  - `tests/test_logging_masking.py::test_login_logging_masks_personnummer`
  - `tests/test_logging_masking.py::test_admin_upload_logging_masks_sensitive_data`

### `tests/test_logging_utils_additional.py`

- Typ: **Enhetstester**
- Antal tester i filen: **9**
- Tester:
  - `tests/test_logging_utils_additional.py::test_configure_module_logger_inits_without_root_handlers`
  - `tests/test_logging_utils_additional.py::test_configure_module_logger_reuses_existing_handlers`
  - `tests/test_logging_utils_additional.py::test_app_timezone_formatter_uses_stockholm_by_default`
  - `tests/test_logging_utils_additional.py::test_app_timezone_formatter_falls_back_to_stockholm_for_invalid_timezone`
  - `tests/test_logging_utils_additional.py::test_configure_root_logging_uses_first_available_env_var`
  - `tests/test_logging_utils_additional.py::test_configure_root_logging_handles_directory_log_file`
  - `tests/test_logging_utils_additional.py::test_bootstrap_logging_returns_configured_module_logger`
  - `tests/test_logging_utils_additional.py::test_log_level_controls_module_loggers_without_module_overrides`
  - `tests/test_logging_utils_additional.py::test_app_uses_module_logger_instead_of_direct_logging_calls`

### `tests/test_login.py`

- Typ: **Integrationstester**
- Antal tester i filen: **5**
- Tester:
  - `tests/test_login.py::test_login_success[9001011234]`
  - `tests/test_login.py::test_login_success[900101-1234]`
  - `tests/test_login.py::test_login_success[199001011234]`
  - `tests/test_login.py::test_login_failure`
  - `tests/test_login.py::test_login_requires_csrf`

### `tests/test_logout.py`

- Typ: **Integrationstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_logout.py::test_logout_clears_user_session`
  - `tests/test_logout.py::test_logout_clears_admin_session`

### `tests/test_manage_compose.py`

- Typ: **Infrastruktur- och driftstester**
- Antal tester i filen: **20**
- Tester:
  - `tests/test_manage_compose.py::test_build_compose_args_includes_expected_flags`
  - `tests/test_manage_compose.py::test_default_compose_file_uses_repo_root`
  - `tests/test_manage_compose.py::test_default_compose_file_falls_back_to_standard_file`
  - `tests/test_manage_compose.py::test_build_venv_command_raises_clear_error`
  - `tests/test_manage_compose.py::test_run_compose_action_cycle_orders_commands`
  - `tests/test_manage_compose.py::test_run_compose_action_build_up_orders_commands`
  - `tests/test_manage_compose.py::test_select_action_returns_none_for_exit`
  - `tests/test_manage_compose.py::test_run_compose_action_git_pull_runs_git`
  - `tests/test_manage_compose.py::test_build_pytest_command_uses_repo_venv`
  - `tests/test_manage_compose.py::test_run_compose_action_pytest_uses_repo_root`
  - `tests/test_manage_compose.py::test_build_pip_command_uses_repo_venv`
  - `tests/test_manage_compose.py::test_find_requirements_files_ignores_virtualenv_paths`
  - `tests/test_manage_compose.py::test_install_requirements_runs_pip_for_all_files`
  - `tests/test_manage_compose.py::test_run_compose_action_prune_volumes_runs_docker_volume_prune`
  - `tests/test_manage_compose.py::test_run_compose_action_system_df_runs_docker_system_df`
  - `tests/test_manage_compose.py::test_run_compose_action_up_ensures_volumes_first`
  - `tests/test_manage_compose.py::test_ensure_compose_volumes_creates_missing_volume`
  - `tests/test_manage_compose.py::test_ensure_compose_volumes_recreates_missing_mountpoint`
  - `tests/test_manage_compose.py::test_ensure_volume_present_handles_in_use_volume`
  - `tests/test_manage_compose.py::test_run_menu_executes_selected_action`

### `tests/test_normalize_personnummer.py`

- Typ: **Enhetstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_normalize_personnummer.py::test_normalize_personnummer_valid`
  - `tests/test_normalize_personnummer.py::test_normalize_personnummer_invalid`

### `tests/test_orgnr_validator.py`

- Typ: **Enhetstester**
- Antal tester i filen: **4**
- Tester:
  - `tests/test_orgnr_validator.py::test_validate_orgnr_accepts_hyphen`
  - `tests/test_orgnr_validator.py::test_validate_orgnr_strips_spaces`
  - `tests/test_orgnr_validator.py::test_validate_orgnr_rejects_invalid_length`
  - `tests/test_orgnr_validator.py::test_validate_orgnr_rejects_bad_checksum`

### `tests/test_pdf_scanner.py`

- Typ: **Säkerhetstester**
- Antal tester i filen: **8**
- Tester:
  - `tests/test_pdf_scanner.py::test_scan_pdf_allows_clean_pdf`
  - `tests/test_pdf_scanner.py::test_scan_pdf_rejects_suspicious_features`
  - `tests/test_pdf_scanner.py::test_scan_pdf_allows_benign_openaction_only`
  - `tests/test_pdf_scanner.py::test_scan_pdf_rejects_openaction_with_javascript`
  - `tests/test_pdf_scanner.py::test_scan_pdf_rejects_embedded_file`
  - `tests/test_pdf_scanner.py::test_scan_pdf_nonzero_unknown_output_raises`
  - `tests/test_pdf_scanner.py::test_scan_pdf_nonzero_exitcode_with_benign_output_allows`
  - `tests/test_pdf_scanner.py::test_scan_pdf_handles_timeout`

### `tests/test_pdf_storage.py`

- Typ: **Enhetstester**
- Antal tester i filen: **5**
- Tester:
  - `tests/test_pdf_storage.py::test_store_pdf_blob_returns_unique_ids`
  - `tests/test_pdf_storage.py::test_get_pdf_metadata_returns_expected_information`
  - `tests/test_pdf_storage.py::test_get_pdf_metadata_handles_missing_entries`
  - `tests/test_pdf_storage.py::test_pdf_content_is_stored_plainly`
  - `tests/test_pdf_storage.py::test_get_user_pdfs_retries_once_after_operational_error`

### `tests/test_performance.py`

- Typ: **Prestandatester**
- Antal tester i filen: **3**
- Tester:
  - `tests/test_performance.py::test_public_pages_render_within_response_budget`
  - `tests/test_performance.py::test_dashboard_with_many_certificates_renders_within_budget`
  - `tests/test_performance.py::test_dashboard_repeated_requests_remain_stable`

### `tests/test_pricing_page.py`

- Typ: **Integrationstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_pricing_page.py::test_pricing_page_loads`
  - `tests/test_pricing_page.py::test_home_page_links_pricing`

### `tests/test_proxy_fix.py`

- Typ: **Integrationstester**
- Antal tester i filen: **1**
- Tester:
  - `tests/test_proxy_fix.py::test_proxy_fix_applied_and_headers_respected`

### `tests/test_public_apply_routes.py`

- Typ: **Integrationstester**
- Antal tester i filen: **4**
- Tester:
  - `tests/test_public_apply_routes.py::test_apply_landing_has_links`
  - `tests/test_public_apply_routes.py::test_user_application_submission`
  - `tests/test_public_apply_routes.py::test_foretagskonto_application_submission`
  - `tests/test_public_apply_routes.py::test_application_requires_terms_confirmation`

### `tests/test_request_utils.py`

- Typ: **Enhetstester**
- Antal tester i filen: **6**
- Tester:
  - `tests/test_request_utils.py::test_register_public_submission_cleans_stale_attempts`
  - `tests/test_request_utils.py::test_register_public_submission_rate_limits`
  - `tests/test_request_utils.py::test_get_request_ip_prefers_forwarded_header`
  - `tests/test_request_utils.py::test_get_request_ip_ignores_forwarded_header_when_untrusted`
  - `tests/test_request_utils.py::test_as_bool_interpretations`
  - `tests/test_request_utils.py::test_rate_limiting_respects_time_window_boundary`

### `tests/test_save_pdf.py`

- Typ: **Enhetstester**
- Antal tester i filen: **4**
- Tester:
  - `tests/test_save_pdf.py::test_save_pdf_stores_in_database`
  - `tests/test_save_pdf.py::test_save_pdf_rejects_invalid_files`
  - `tests/test_save_pdf.py::test_save_pdf_requires_category`
  - `tests/test_save_pdf.py::test_save_pdf_rejects_multiple_categories`

### `tests/test_save_pdf_for_user.py`

- Typ: **Enhetstester**
- Antal tester i filen: **3**
- Tester:
  - `tests/test_save_pdf_for_user.py::test_save_pdf_for_user`
  - `tests/test_save_pdf_for_user.py::test_save_png_converts_to_pdf`
  - `tests/test_save_pdf_for_user.py::test_save_pdf_rejects_blocked_scan`

### `tests/test_server_monitor_config.py`

- Typ: **Infrastruktur- och driftstester**
- Antal tester i filen: **9**
- Tester:
  - `tests/test_server_monitor_config.py::test_server_monitor_service_exists_in_compose_files`
  - `tests/test_server_monitor_config.py::test_prod_compose_routes_mta_sts_via_app_service`
  - `tests/test_server_monitor_config.py::test_mta_sts_policy_file_has_expected_content`
  - `tests/test_server_monitor_config.py::test_monitor_thresholds_are_configured`
  - `tests/test_server_monitor_config.py::test_collect_container_resource_usage_guards_none_stats`
  - `tests/test_server_monitor_config.py::test_send_email_handles_smtp_timeouts_gracefully`
  - `tests/test_server_monitor_config.py::test_prod_compose_exposes_postgres_on_random_host_port`
  - `tests/test_server_monitor_config.py::test_dockerfile_copies_mta_sts_policy_into_image`
  - `tests/test_server_monitor_config.py::test_server_monitor_uses_uppercase_smtp_env_with_legacy_fallback`

### `tests/test_server_monitor_smoke.py`

- Typ: **Smoke-tester (övervakning)**
- Antal tester i filen: **4**
- Tester:
  - `tests/test_server_monitor_smoke.py::test_parse_smoke_targets_supports_named_and_unnamed_entries`
  - `tests/test_server_monitor_smoke.py::test_run_smoke_tests_records_daily_results`
  - `tests/test_server_monitor_smoke.py::test_maybe_run_smoke_tests_respects_interval`
  - `tests/test_server_monitor_smoke.py::test_weekly_smoke_report_is_sent_once_and_contains_daily_rows`

### `tests/test_share_pdf.py`

- Typ: **Integrationstester**
- Antal tester i filen: **5**
- Tester:
  - `tests/test_share_pdf.py::test_share_pdf_requires_login`
  - `tests/test_share_pdf.py::test_share_pdf_sends_email`
  - `tests/test_share_pdf.py::test_share_pdf_rejects_invalid_email`
  - `tests/test_share_pdf.py::test_share_pdf_missing_document`
  - `tests/test_share_pdf.py::test_share_multiple_pdfs`

### `tests/test_sitemap.py`

- Typ: **Integrationstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_sitemap.py::TestSitemapXml::test_mta_sts_policy_is_public`
  - `tests/test_sitemap.py::TestSitemapXml::test_sitemap_xml_is_public`

### `tests/test_sql_injection_protection.py`

- Typ: **Säkerhetstester**
- Antal tester i filen: **1**
- Tester:
  - `tests/test_sql_injection_protection.py::test_wildcard_search_is_escaped`

### `tests/test_status_service.py`

- Typ: **Infrastruktur- och driftstester**
- Antal tester i filen: **22**
- Tester:
  - `tests/test_status_service.py::test_format_uptime_includes_swedish_units`
  - `tests/test_status_service.py::test_build_status_uses_dependency_overrides`
  - `tests/test_status_service.py::test_resolve_proxy_target_prefers_traefik_and_handles_invalid_port`
  - `tests/test_status_service.py::test_get_country_availability_parses_entries`
  - `tests/test_status_service.py::test_get_http_check_targets_is_hardcoded_for_primary_site`
  - `tests/test_status_service.py::test_check_ssl_status_handles_connection_refused`
  - `tests/test_status_service.py::test_check_ssl_status_uses_hardcoded_primary_url`
  - `tests/test_status_service.py::test_check_ssl_status_returns_error_for_http_error`
  - `tests/test_status_service.py::test_check_http_status_handles_connection_refused`
  - `tests/test_status_service.py::test_check_http_status_uses_fallback_url`
  - `tests/test_status_service.py::test_check_ssl_status_uses_internal_fallback_url`
  - `tests/test_status_service.py::test_get_load_average_handles_missing_support`
  - `tests/test_status_service.py::test_summarize_latency_handles_empty_input`
  - `tests/test_status_service.py::test_build_latency_series_skips_invalid_items`
  - `tests/test_status_service.py::test_check_http_status_handles_timeout_error`
  - `tests/test_status_service.py::test_check_http_status_handles_timeout_inside_url_error`
  - `tests/test_status_service.py::test_check_http_status_handles_http_error`
  - `tests/test_status_service.py::test_check_http_status_treats_client_error_as_reachable`
  - `tests/test_status_service.py::test_check_ssl_status_treats_client_error_as_reachable`
  - `tests/test_status_service.py::test_check_tcp_returns_false_on_error`
  - `tests/test_status_service.py::test_get_cpu_and_ram_procent_handle_exceptions`
  - `tests/test_status_service.py::test_get_display_timestamp_uses_stockholm_timezone`

### `tests/test_supervisor_features.py`

- Typ: **Integrationstester**
- Antal tester i filen: **11**
- Tester:
  - `tests/test_supervisor_features.py::test_supervisor_activation_flow`
  - `tests/test_supervisor_features.py::test_get_supervisor_login_details_for_orgnr`
  - `tests/test_supervisor_features.py::test_supervisor_dashboard_lists_users`
  - `tests/test_supervisor_features.py::test_supervisor_dashboard_has_dropdown_and_search`
  - `tests/test_supervisor_features.py::test_supervisor_share_pdf`
  - `tests/test_supervisor_features.py::test_supervisor_remove_connection`
  - `tests/test_supervisor_features.py::test_supervisor_link_request_and_user_accept`
  - `tests/test_supervisor_features.py::test_user_remove_supervisor_connection`
  - `tests/test_supervisor_features.py::test_admin_create_supervisor_api`
  - `tests/test_supervisor_features.py::test_admin_link_supervisor_api`
  - `tests/test_supervisor_features.py::test_admin_supervisor_overview_api`

### `tests/test_tls_support.py`

- Typ: **Säkerhetstester**
- Antal tester i filen: **5**
- Tester:
  - `tests/test_tls_support.py::test_get_ssl_context_none`
  - `tests/test_tls_support.py::test_get_ssl_context_with_env`
  - `tests/test_tls_support.py::test_get_ssl_context_default_paths`
  - `tests/test_tls_support.py::test_get_ssl_context_with_explicit_paths`
  - `tests/test_tls_support.py::test_default_paths_constants`

### `tests/test_ui_rendering.py`

- Typ: **UI-tester**
- Antal tester i filen: **5**
- Tester:
  - `tests/test_ui_rendering.py::test_public_nav_shows_public_links_and_swedish_lang`
  - `tests/test_ui_rendering.py::test_logged_in_user_nav_shows_user_actions_only`
  - `tests/test_ui_rendering.py::test_standardkonto_form_contains_expected_ui_fields`
  - `tests/test_ui_rendering.py::test_foretagskonto_form_contains_invoice_section_and_required_fields`
  - `tests/test_ui_rendering.py::test_dashboard_ui_contains_share_modal_for_logged_in_user`

### `tests/test_update_app.py`

- Typ: **Infrastruktur- och driftstester**
- Antal tester i filen: **5**
- Tester:
  - `tests/test_update_app.py::test_find_requirements_skips_virtualenv`
  - `tests/test_update_app.py::test_build_venv_command_prefers_unix_layout_on_posix`
  - `tests/test_update_app.py::test_main_sequence_uses_production_compose`
  - `tests/test_update_app.py::test_main_sequence_runs_expected_commands`
  - `tests/test_update_app.py::test_main_runs_compose_up_without_scale_flags`

### `tests/test_user_create.py`

- Typ: **Enhetstester**
- Antal tester i filen: **1**
- Tester:
  - `tests/test_user_create.py::test_user_create_hashes_password`

### `tests/test_user_management.py`

- Typ: **Enhetstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_user_management.py::test_check_user_exists`
  - `tests/test_user_management.py::test_user_create_user_success`

### `tests/test_user_queries.py`

- Typ: **Enhetstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_user_queries.py::test_verify_certificate_existing_user`
  - `tests/test_user_queries.py::test_check_user_exists`

### `tests/test_user_upload_pdf.py`

- Typ: **Integrationstester**
- Antal tester i filen: **2**
- Tester:
  - `tests/test_user_upload_pdf.py::test_user_can_upload_pdf_from_dashboard`
  - `tests/test_user_upload_pdf.py::test_user_upload_rejects_too_long_note`

<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
