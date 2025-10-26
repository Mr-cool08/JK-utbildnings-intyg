#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

readonly db_name="${POSTGRES_DB:-}"
readonly owner_user="${POSTGRES_USER:-}"
readonly ro_user="${POSTGRES_RO_USER:-}"
readonly ro_password="${POSTGRES_RO_PASSWORD:-}"
readonly app_network_cidr="172.28.0.0/16"
readonly pg_hba_file="${PGDATA}/pg_hba.conf"

missing_vars=()

if [[ -z "${ro_user}" ]]; then
    missing_vars+=("POSTGRES_RO_USER")
fi

if [[ -z "${ro_password}" ]]; then
    missing_vars+=("POSTGRES_RO_PASSWORD")
fi

if [[ -z "${db_name}" ]]; then
    missing_vars+=("POSTGRES_DB")
fi

if [[ -z "${owner_user}" ]]; then
    missing_vars+=("POSTGRES_USER")
fi

if (( ${#missing_vars[@]} > 0 )); then
    missing_list=$(IFS=', '; echo "${missing_vars[*]}")
    printf 'Required environment variables are not set: %s\n' "${missing_list}" >&2
    exit 1
fi

psql --username "${owner_user}" "dbname=${db_name}" <<EOSQL
DO
$$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${ro_user}') THEN
        EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', '${ro_user}', '${ro_password}');
    ELSE
        EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', '${ro_user}', '${ro_password}');
    END IF;
END;
$$;

GRANT CONNECT ON DATABASE ${db_name} TO ${ro_user};
GRANT USAGE ON SCHEMA public TO ${ro_user};
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${ro_user};
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO ${ro_user};
GRANT SELECT ON ALL MATERIALIZED VIEWS IN SCHEMA public TO ${ro_user};

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO ${ro_user};
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON SEQUENCES TO ${ro_user};
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON MATERIALIZED VIEWS TO ${ro_user};

DO
$$
BEGIN
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO %I',
        '${owner_user}',
        '${ro_user}'
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON SEQUENCES TO %I',
        '${owner_user}',
        '${ro_user}'
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON MATERIALIZED VIEWS TO %I',
        '${owner_user}',
        '${ro_user}'
    );
END;
$$;
EOSQL

if [[ ! -f "${pg_hba_file}" ]]; then
    echo "Expected pg_hba.conf at ${pg_hba_file} was not found" >&2
    exit 1
fi

# Remove the default rule that allows every host to authenticate with any role
sed -i '/^host\s\+all\s\+all\s\+all\s\+scram-sha-256$/d' "${pg_hba_file}"

# Ensure our custom rules are present exactly once
if ! grep -q '# codex-readonly-access' "${pg_hba_file}"; then
    cat >> "${pg_hba_file}" <<EOF
# codex-readonly-access allow app network full privileges
host    all             all             ${app_network_cidr}           scram-sha-256
# codex-readonly-access allow read-only user from any IPv4 host
host    all             ${ro_user}      0.0.0.0/0            scram-sha-256
# codex-readonly-access allow read-only user from any IPv6 host
host    all             ${ro_user}      ::/0                scram-sha-256
# codex-readonly-access reject all other remote access
host    all             all             0.0.0.0/0           reject
host    all             all             ::/0                reject
EOF
fi
