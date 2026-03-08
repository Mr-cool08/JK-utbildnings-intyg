#!/usr/bin/env python3
import datetime as dt
import logging
import os
import shutil
import smtplib
import subprocess
import tempfile
import time
from email.message import EmailMessage
from pathlib import Path
from urllib import error as url_error
from urllib import request as url_request

import docker

try:
    from functions.logging import bootstrap_logging

    logger = bootstrap_logging(__name__)
except Exception:
    logger = logging.getLogger(__name__)

CHECK_INTERVAL_SECONDS = int(os.getenv("MONITOR_CHECK_INTERVAL_SECONDS", "60"))


def env_with_legacy_fallback(primary_key: str, legacy_key: str, default: str) -> str:
    return os.getenv(primary_key, os.getenv(legacy_key, default))


SMTP_SERVER = env_with_legacy_fallback("SMTP_SERVER", "smtp_server", "")
SMTP_PORT = int(env_with_legacy_fallback("SMTP_PORT", "smtp_port", "587"))
SMTP_USER = env_with_legacy_fallback("SMTP_USER", "smtp_user", "")
SMTP_PASSWORD = env_with_legacy_fallback("SMTP_PASSWORD", "smtp_password", "")
SMTP_TIMEOUT = int(env_with_legacy_fallback("SMTP_TIMEOUT", "smtp_timeout", "30"))
CRITICAL_ALERTS_EMAIL = os.getenv("CRITICAL_ALERTS_EMAIL", "")
EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", SMTP_USER)
HOST_ROOT = os.getenv("HOST_ROOT", "/host")
CLAMAV_SCAN_IMAGE = os.getenv("CLAMAV_SCAN_IMAGE", "clamav/clamav:stable")
CLAMAV_SCAN_TIMEOUT_SECONDS = int(os.getenv("CLAMAV_SCAN_TIMEOUT_SECONDS", str(6 * 3600)))


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on", "ja"}


def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_smoke_targets(raw_value: str) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for part in raw_value.split(","):
        item = part.strip()
        if not item:
            continue
        if "=" in item:
            name, url = item.split("=", 1)
            name = name.strip()
            url = url.strip()
        else:
            url = item
            name = item
        if not name or not url:
            continue
        targets.append((name, url))
    return targets


SMOKE_TESTS_ENABLED = _is_truthy(os.getenv("MONITOR_SMOKE_TESTS_ENABLED", "true"))
SMOKE_TESTS_TIMEOUT_SECONDS = _safe_int(os.getenv("MONITOR_SMOKE_TESTS_TIMEOUT_SECONDS", "8"), 8)
SMOKE_TESTS_INTERVAL_SECONDS = _safe_int(os.getenv("MONITOR_SMOKE_TESTS_INTERVAL_SECONDS", "1800"), 1800)
SMOKE_TESTS_HISTORY_DAYS = _safe_int(os.getenv("MONITOR_SMOKE_TESTS_HISTORY_DAYS", "35"), 35)
SMOKE_WEEKLY_REPORT_WEEKDAY = _safe_int(os.getenv("MONITOR_SMOKE_WEEKLY_REPORT_WEEKDAY", "0"), 0)
SMOKE_WEEKLY_REPORT_HOUR = _safe_int(os.getenv("MONITOR_SMOKE_WEEKLY_REPORT_HOUR", "8"), 8)
SMOKE_WEEKLY_REPORT_MINUTE = _safe_int(os.getenv("MONITOR_SMOKE_WEEKLY_REPORT_MINUTE", "0"), 0)
SMOKE_TEST_TARGETS = parse_smoke_targets(
    os.getenv(
        "MONITOR_SMOKE_TEST_TARGETS",
        "Huvudsidan=https://utbildningsintyg.se/health",
    )
)

DISK_THRESHOLDS = [50, 60, 75, 95, 100]
RAM_THRESHOLD = 80
CPU_THRESHOLD = 90

ALERT_STATE = {
    "disk": {threshold: False for threshold in DISK_THRESHOLDS},
    "ram": False,
    "cpu": False,
}
LAST_CLAMAV_RUN_DATE = None
LAST_SMOKE_RUN_AT = None
LAST_SMOKE_WEEKLY_REPORT_ID = None
DAILY_SMOKE_RESULTS: dict[dt.date, list[dict[str, object]]] = {}


def _read_host_file(path: str) -> str:
    full_path = Path(HOST_ROOT) / path.lstrip("/")
    return full_path.read_text(encoding="utf-8")


def get_disk_percent() -> float:
    usage = shutil.disk_usage(HOST_ROOT)
    return (usage.used / usage.total) * 100 if usage.total else 0.0


def get_ram_percent() -> float:
    meminfo = _read_host_file("proc/meminfo").splitlines()
    values = {}
    for line in meminfo:
        key, value = line.split(":", 1)
        values[key.strip()] = int(value.strip().split()[0])
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    if total == 0:
        return 0.0
    used = total - available
    return (used / total) * 100


def read_cpu_stat():
    stat = _read_host_file("proc/stat").splitlines()[0].split()
    nums = [int(part) for part in stat[1:]]
    idle = nums[3] + nums[4]
    total = sum(nums)
    return total, idle


def get_cpu_percent(previous_total, previous_idle):
    current_total, current_idle = read_cpu_stat()
    total_diff = current_total - previous_total
    idle_diff = current_idle - previous_idle
    if total_diff <= 0:
        return 0.0, current_total, current_idle
    usage = (1 - (idle_diff / total_diff)) * 100
    return usage, current_total, current_idle


def run_command(command: list[str]) -> str:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    output = result.stdout.strip()
    if result.stderr.strip():
        output = f"{output}\n\n[stderr]\n{result.stderr.strip()}".strip()
    return output


def collect_container_resource_usage(client: docker.DockerClient) -> str:
    lines = ["Container-resurser (CPU%, RAM, disk I/O, nätverk):"]
    for container in client.containers.list():
        stats = container.stats(stream=False)
        cpu_total = stats["cpu_stats"]["cpu_usage"].get("total_usage", 0)
        precpu_total = stats["precpu_stats"]["cpu_usage"].get("total_usage", 0)
        system_total = stats["cpu_stats"].get("system_cpu_usage", 0)
        presystem_total = stats["precpu_stats"].get("system_cpu_usage", 0)
        online_cpus = stats["cpu_stats"].get("online_cpus") or 1

        cpu_delta = cpu_total - precpu_total
        system_delta = system_total - presystem_total
        cpu_percent = 0.0
        if cpu_delta > 0 and system_delta > 0:
            cpu_percent = (cpu_delta / system_delta) * online_cpus * 100

        mem_usage = stats["memory_stats"].get("usage", 0)
        mem_limit = stats["memory_stats"].get("limit", 1)
        mem_percent = (mem_usage / mem_limit) * 100 if mem_limit else 0.0

        # Docker API varierar, förenkla och hämta direkt från listorna när de finns
        blkio_entries = stats.get("blkio_stats", {}).get("io_service_bytes_recursive") or []
        blk_read = sum(item.get("value", 0) for item in blkio_entries if item.get("op") == "Read")
        blk_write = sum(item.get("value", 0) for item in blkio_entries if item.get("op") == "Write")
        net_stats = stats.get("networks") or {}
        net_rx = sum(item.get("rx_bytes", 0) for item in net_stats.values())
        net_tx = sum(item.get("tx_bytes", 0) for item in net_stats.values())

        lines.append(
            f"- {container.name}: CPU {cpu_percent:.2f}%, RAM {mem_percent:.2f}% "
            f"({mem_usage / 1024 / 1024:.1f} MiB), Disk read/write {blk_read}/{blk_write} bytes, "
            f"Nät RX/TX {net_rx}/{net_tx} bytes"
        )
    if len(lines) == 1:
        lines.append("Inga körande containrar hittades.")
    return "\n".join(lines)


def collect_container_logs(client: docker.DockerClient, output_dir: Path) -> list[Path]:
    attachments = []
    for container in client.containers.list(all=True):
        log_data = container.logs(tail=300, timestamps=True).decode("utf-8", errors="replace")
        file_path = output_dir / f"docker_logs_{container.name}.txt"
        file_path.write_text(log_data or "Inga loggrader tillgängliga.", encoding="utf-8")
        attachments.append(file_path)
    return attachments


def collect_disk_report(output_dir: Path) -> Path:
    disk_report = output_dir / "disk_usage_top.txt"
    command = [
        "bash",
        "-lc",
        f"du -x -h --max-depth=2 {HOST_ROOT} 2>/dev/null | sort -h | tail -n 120",
    ]
    disk_report.write_text(run_command(command), encoding="utf-8")
    return disk_report


def collect_cpu_report(output_dir: Path) -> Path:
    cpu_report = output_dir / "cpu_top_processes.txt"
    command = ["bash", "-lc", "ps aux --sort=-%cpu | head -n 40"]
    cpu_report.write_text(run_command(command), encoding="utf-8")
    return cpu_report


def collect_ram_report(output_dir: Path) -> Path:
    ram_report = output_dir / "ram_top_processes.txt"
    command = ["bash", "-lc", "ps aux --sort=-%mem | head -n 40"]
    ram_report.write_text(run_command(command), encoding="utf-8")
    return ram_report


def send_email(subject: str, body: str, attachments: list[Path]):
    if not CRITICAL_ALERTS_EMAIL or not SMTP_SERVER:
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = EMAIL_FROM
    message["To"] = CRITICAL_ALERTS_EMAIL
    message.set_content(body)

    for attachment in attachments:
        data = attachment.read_bytes()
        message.add_attachment(
            data,
            maintype="text",
            subtype="plain",
            filename=attachment.name,
        )

    try:
        if SMTP_PORT == 465:
            # Implicit TLS (SMTPS)
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(message)
        else:
            # STARTTLS (vanligen 587)
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(message)

    except (smtplib.SMTPException, TimeoutError, OSError) as exc:
        logger.error("Kunde inte skicka e-postvarning: %s", str(exc))

def send_alert(alert_title: str, alert_body: str, client: docker.DockerClient):
    with tempfile.TemporaryDirectory() as tempdir:
        output_dir = Path(tempdir)
        attachments = [
            collect_disk_report(output_dir),
            collect_cpu_report(output_dir),
            collect_ram_report(output_dir),
        ]
        resource_report = output_dir / "docker_resource_usage.txt"
        resource_report.write_text(collect_container_resource_usage(client), encoding="utf-8")
        attachments.append(resource_report)
        attachments.extend(collect_container_logs(client, output_dir))
        send_email(alert_title, alert_body, attachments)


def run_smoke_check(name: str, url: str) -> dict[str, object]:
    started_at = time.perf_counter()
    try:
        with url_request.urlopen(url, timeout=SMOKE_TESTS_TIMEOUT_SECONDS) as response:
            status_code = int(getattr(response, "status", 200))
            ok = 200 <= status_code < 400
            details = f"HTTP {status_code}"
    except url_error.HTTPError as exc:
        ok = False
        details = f"HTTP {exc.code}"
    except Exception as exc:  # pragma: no cover - defensiv fallback
        ok = False
        details = f"Fel: {str(exc)}"

    return {
        "name": name,
        "url": url,
        "ok": ok,
        "details": details,
        "duration_seconds": round(time.perf_counter() - started_at, 3),
    }


def _prune_smoke_history(today: dt.date) -> None:
    stale_days: list[dt.date] = []
    for day in DAILY_SMOKE_RESULTS:
        if (today - day).days > SMOKE_TESTS_HISTORY_DAYS:
            stale_days.append(day)
    for day in stale_days:
        DAILY_SMOKE_RESULTS.pop(day, None)


def run_smoke_tests(now: dt.datetime | None = None) -> dict[str, object]:
    current_time = now or dt.datetime.now()
    checks = [run_smoke_check(name, url) for name, url in SMOKE_TEST_TARGETS]
    total_checks = len(checks)
    passed_checks = sum(1 for check in checks if check["ok"])
    failed_checks = total_checks - passed_checks
    all_ok = failed_checks == 0

    day = current_time.date()
    day_bucket = DAILY_SMOKE_RESULTS.setdefault(day, [])
    day_bucket.append(
        {
            "timestamp": current_time.isoformat(timespec="seconds"),
            "checks": checks,
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "all_ok": all_ok,
        }
    )
    _prune_smoke_history(day)

    return {
        "timestamp": current_time.isoformat(timespec="seconds"),
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "all_ok": all_ok,
        "checks": checks,
    }


def maybe_run_smoke_tests(now: dt.datetime | None = None) -> None:
    global LAST_SMOKE_RUN_AT
    if not SMOKE_TESTS_ENABLED or not SMOKE_TEST_TARGETS:
        return

    current_time = now or dt.datetime.now()
    if LAST_SMOKE_RUN_AT is not None:
        elapsed_seconds = (current_time - LAST_SMOKE_RUN_AT).total_seconds()
        if elapsed_seconds < max(1, SMOKE_TESTS_INTERVAL_SECONDS):
            return

    summary = run_smoke_tests(current_time)
    LAST_SMOKE_RUN_AT = current_time

    if summary["all_ok"]:
        logger.info(
            "Smoke-tester lyckades: %s/%s",
            summary["passed_checks"],
            summary["total_checks"],
        )
        return

    failed_check_names = ", ".join(
        check["name"] for check in summary["checks"] if not check["ok"]
    )
    logger.warning(
        "Smoke-tester misslyckades: %s/%s (fel i: %s)",
        summary["passed_checks"],
        summary["total_checks"],
        failed_check_names or "okänt mål",
    )


def build_weekly_smoke_report(now: dt.datetime | None = None) -> str:
    current_time = now or dt.datetime.now()
    lines = [
        "Veckorapport för smoke-tester (daglig sammanställning):",
        "",
    ]
    for days_back in range(6, -1, -1):
        day = current_time.date() - dt.timedelta(days=days_back)
        entries = DAILY_SMOKE_RESULTS.get(day, [])
        if not entries:
            lines.append(f"- {day.isoformat()}: Inga körningar registrerade.")
            continue

        run_count = len(entries)
        total_checks = sum(int(entry["total_checks"]) for entry in entries)
        passed_checks = sum(int(entry["passed_checks"]) for entry in entries)
        failed_checks = total_checks - passed_checks
        success_rate = (passed_checks / total_checks * 100) if total_checks else 0.0
        lines.append(
            f"- {day.isoformat()}: {run_count} körningar, "
            f"{passed_checks}/{total_checks} godkända ({success_rate:.1f}%), "
            f"fel: {failed_checks}."
        )

        latest_failed_names = []
        for entry in reversed(entries):
            failed_checks_for_entry = [
                check["name"] for check in entry["checks"] if not check["ok"]
            ]
            if failed_checks_for_entry:
                latest_failed_names = failed_checks_for_entry
                break
        if latest_failed_names:
            lines.append(
                f"  Senast felande mål: {', '.join(latest_failed_names[:3])}"
            )

    lines.extend(
        [
            "",
            "Rapporten skickas automatiskt varje vecka från serverövervakningen.",
        ]
    )
    return "\n".join(lines)


def maybe_send_weekly_smoke_report(now: dt.datetime | None = None) -> None:
    global LAST_SMOKE_WEEKLY_REPORT_ID
    if not SMOKE_TESTS_ENABLED or not SMOKE_TEST_TARGETS:
        return

    current_time = now or dt.datetime.now()
    if current_time.weekday() != max(0, min(6, SMOKE_WEEKLY_REPORT_WEEKDAY)):
        return
    if current_time.hour != max(0, min(23, SMOKE_WEEKLY_REPORT_HOUR)):
        return
    if current_time.minute != max(0, min(59, SMOKE_WEEKLY_REPORT_MINUTE)):
        return

    iso_year, iso_week, _iso_weekday = current_time.isocalendar()
    weekly_report_id = f"{iso_year}-W{iso_week:02d}"
    if LAST_SMOKE_WEEKLY_REPORT_ID == weekly_report_id:
        return

    report_subject = f"Veckorapport: smoke-tester vecka {iso_week:02d}"
    report_body = build_weekly_smoke_report(current_time)
    send_email(report_subject, report_body, [])
    LAST_SMOKE_WEEKLY_REPORT_ID = weekly_report_id


def run_clamav_scan(client: docker.DockerClient):
    command = (
        "sh -lc 'clamscan -r -i /host "
        "--exclude-dir=^/host/proc --exclude-dir=^/host/sys --exclude-dir=^/host/dev "
        "--exclude-dir=^/host/run --exclude-dir=^/host/var/lib/docker "
        "|| true'"
    )

    container = client.containers.run(
        CLAMAV_SCAN_IMAGE,
        command=command,
        detach=True,
        remove=False,
        volumes={"/": {"bind": "/host", "mode": "ro"}},
        name=f"nightly-clamav-{int(time.time())}",
    )

    try:
        container.wait(timeout=CLAMAV_SCAN_TIMEOUT_SECONDS)
        scan_logs = container.logs().decode("utf-8", errors="replace")
    finally:
        container.remove(force=True)

    with tempfile.TemporaryDirectory() as tempdir:
        report_path = Path(tempdir) / "clamav_nightly_report.txt"
        report_path.write_text(scan_logs or "Ingen data från ClamAV-skanningen.", encoding="utf-8")
        send_email(
            "Nattlig ClamAV-rapport",
            "Nattlig ClamAV-skanning är klar. Se bifogad rapport.",
            [report_path],
        )


def maybe_run_clamav(client: docker.DockerClient, now: dt.datetime | None = None):
    global LAST_CLAMAV_RUN_DATE
    current_time = now or dt.datetime.now()
    if (
        current_time.hour == 0
        and current_time.minute == 0
        and LAST_CLAMAV_RUN_DATE != current_time.date()
    ):
        run_clamav_scan(client)
        LAST_CLAMAV_RUN_DATE = current_time.date()


def main():
    client = docker.from_env()
    previous_total, previous_idle = read_cpu_stat()

    while True:
        try:
            now = dt.datetime.now()
            disk_percent = get_disk_percent()
            ram_percent = get_ram_percent()
            cpu_percent, previous_total, previous_idle = get_cpu_percent(
                previous_total, previous_idle
            )

            for threshold in DISK_THRESHOLDS:
                if disk_percent >= threshold and not ALERT_STATE["disk"][threshold]:
                    ALERT_STATE["disk"][threshold] = True
                    send_alert(
                        f"Varning: diskutrymme över {threshold}%",
                        f"Diskanvändningen är nu {disk_percent:.2f}% och passerade {threshold}%.",
                        client,
                    )
                if disk_percent < max(0, threshold - 2):
                    ALERT_STATE["disk"][threshold] = False

            if ram_percent >= RAM_THRESHOLD and not ALERT_STATE["ram"]:
                ALERT_STATE["ram"] = True
                send_alert(
                    "Varning: RAM-användning över 80%",
                    f"RAM-användningen är nu {ram_percent:.2f}%.",
                    client,
                )
            if ram_percent < 75:
                ALERT_STATE["ram"] = False

            if cpu_percent >= CPU_THRESHOLD and not ALERT_STATE["cpu"]:
                ALERT_STATE["cpu"] = True
                send_alert(
                    "Varning: CPU-användning över 90%",
                    f"CPU-användningen är nu {cpu_percent:.2f}%.",
                    client,
                )
            if cpu_percent < 85:
                ALERT_STATE["cpu"] = False

            maybe_run_clamav(client, now=now)
            maybe_run_smoke_tests(now=now)
            maybe_send_weekly_smoke_report(now=now)
        except Exception as exc:
            with tempfile.TemporaryDirectory() as tempdir:
                error_file = Path(tempdir) / "monitor_error.txt"
                error_file.write_text(str(exc), encoding="utf-8")
                send_email(
                    "Varning: serverövervakning misslyckades",
                    "Övervakningscontainern fick ett fel. Se bifogad fil.",
                    [error_file],
                )

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
# Copyright (c) Liam Suorsa and Mika Suorsa
