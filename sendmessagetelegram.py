import requests

TOKEN = "8314468331:AAEd8ByzmwkM-7b3n0qgofSZsf97iWzx0OE"
CHAT_ID = "-1003218000558"
MESSAGE = "Hello"

requests.post(
    f"https://api.telegram.org/bot{TOKEN}/sendMessage",
    data={"chat_id": CHAT_ID, "text": MESSAGE}
)
