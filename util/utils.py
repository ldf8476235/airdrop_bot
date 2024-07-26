import base64
import json
import sys

import urllib3
from art import tprint
from loguru import logger


def setup():
    urllib3.disable_warnings()
    logger.remove()
    logger.add(
        sys.stdout,
        colorize=True,
        format="<light-cyan>{time:HH:mm:ss}</light-cyan> | <level> {level: <8}</level> | - <white>{"
        "message}</white>",
    )
    logger.add("./logs/logs.log", rotation="1 day", retention="7 days")


def show_dev_info():
    tprint("Feeeeng")
    print("\033[33m" + "AUTHOR: " + "\033[34m" + "Lee" + "\033[34m")
    print()



# def export_results(data: list[tuple[bool, Account]]):
#     if not os.path.exists("results"):
#         os.makedirs("results")
#
#     with open("results/success.txt", "w") as file:
#         file.write(
#             "\n".join(
#                 [
#                     (
#                         f"{wallet.auth_token}:{wallet.mnemonic}"
#                         if wallet.mnemonic
#                         else wallet.auth_token
#                     )
#                     for status, wallet in data
#                     if status
#                 ]
#             )
#         )
#
#     with open("results/failed.txt", "w") as file:
#         file.write(
#             "\n".join([f"{wallet.auth_token}:{wallet.mnemonic}"
#                        for status, wallet in data if not status])
#         )
#
#     with open("results/proxyfail.txt", "w") as file:
#         file.write(
#             "\n".join([f"{wallet.proxy}"
#                        for status, wallet in data if not status])
#         )
#     logger.info("Results exported to results/success.txt and results/failed.txt")


def base64url_decode(data: str):
    padding = "=" * (4 - len(data) % 4)
    data += padding
    return base64.urlsafe_b64decode(data)


def decode_id_token(token: str) -> dict[str, str]:
    parts = token.split(".")
    payload = parts[1]

    decoded_payload = base64url_decode(payload).decode("utf-8")
    user_info = json.loads(decoded_payload)
    return user_info
