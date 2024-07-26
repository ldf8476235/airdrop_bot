import asyncio

import ipdb
from loguru import logger

from models import Account
from loader import config, semaphore
from util.utils import *
from src.bot.bkbot import *

async def run_safe(account: Account):
    async with semaphore:
        bot = Bot(account)
        print(bot.session)
        status = await bot.start()
        return status, bot.account


async def run():
    logger.info(f"Bot Started:\n- Accounts: {len(config.accounts)}\n- Threads: {config.threads}\n\n")
    tasks = [asyncio.create_task(run_safe(account)) for account in config.accounts]

    results = await asyncio.gather(*tasks)
    # export_results(results)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    setup()
    show_dev_info()
    asyncio.run(run())