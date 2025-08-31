import os, smtplib, ssl
from email.message import EmailMessage

# --- Läs .env om möjligt (valfritt) ---
try:
    from dotenv import load_dotenv  # pip install python-dotenv
    load_dotenv()
except Exception:
    pass

# --- Hämta env-variabler ---
server = os.getenv("smtp_server")
port = int(os.getenv("smtp_port", "587"))
user = os.getenv("smtp_user")
password = os.getenv("smtp_password")

if not server or not user or not password:
    raise SystemExit("Saknar env: smtp_server, smtp_user eller smtp_password. Kontrollera din .env eller miljö.")

# --- Meddelande ---
msg = EmailMessage()
msg["Subject"] = "Testmail"
msg["From"] = user
msg["To"] = "liamsuorsa08@gmail.com"  # <-- byt till din adress
msg.set_content("Hej! Detta är ett testmail.")

# --- Skicka via STARTTLS på port 587 ---
context = ssl.create_default_context()
with smtplib.SMTP(server, port, timeout=30) as smtp:
    smtp.ehlo()
    smtp.starttls(context=context)   # funkar nu utan server_hostname
    smtp.ehlo()
    smtp.login(user, password)
    smtp.send_message(msg)

print("Testmail skickat!")



