# Copyright (c) Liam Suorsa and Mika Suorsa
import os
import smtplib
import ssl
from email.message import EmailMessage

from scripts import is_dev_mode_enabled


def _load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv  # pip install python-dotenv
    except ImportError:
        return

    load_dotenv()


def main() -> None:
    _load_dotenv_if_available()

    # --- Hämta env-variabler ---
    server = os.getenv("smtp_server")
    port = int(os.getenv("smtp_port", "587"))
    user = os.getenv("smtp_user")
    password = os.getenv("smtp_password")

    if not is_dev_mode_enabled(os.getenv("DEV_MODE", "false")):
        raise SystemExit("DEV_MODE måste vara aktiverat för att skicka testmejl.")

    if not server or not user or not password:
        raise SystemExit(
            "Saknar env: smtp_server, smtp_user eller smtp_password. Kontrollera din .env eller miljö."
        )
    recipient = (os.getenv("SMTP_TEST_RECIPIENT") or "").strip()
    if not recipient:
        raise SystemExit("Sätt SMTP_TEST_RECIPIENT till en giltig testadress innan utskick.")

    # --- Meddelande ---
    msg = EmailMessage()
    msg["Subject"] = "Testmejl"
    msg["From"] = user
    msg["To"] = recipient
    msg.set_content("Hej! Detta är ett testmejl.")

    # --- Skicka via STARTTLS på port 587 ---
    context = ssl.create_default_context()
    with smtplib.SMTP(server, port, timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)  # funkar nu utan server_hostname
        smtp.ehlo()
        smtp.login(user, password)
        smtp.send_message(msg)

    print("Testmejl skickat!")


if __name__ == "__main__":
    main()
