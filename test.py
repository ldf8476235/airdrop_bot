from models import Account
from better_proxy import Proxy
from src.bot.bkbot import *
import asyncio
import jwt

semaphore = asyncio.Semaphore(1)

async def run_safe(account: Account) -> tuple[bool, Account]:
    async with semaphore:
        bot = Bot(account)
        status = await bot.start()
        return status, bot.account

async def run():
    proxy = Proxy.from_str('http://maoztaee:9i90pecjersz@45.249.106.31:5728')
    account = Account(
        auth_token='a21161603d4bfc57a7985961ee2762c771c5c222',
        proxy=proxy,
        mnemonic='b29daaa944e95998d5a134dd2f132fcca781a1a130465e7203d6fc451729eb79',
    )
    tasks = asyncio.create_task(run_safe(account))
    results = await asyncio.gather(tasks)

if __name__ == '__main__':
    asyncio.run(run())


    # jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjI5YzgzZmZjLWEyODctNDNmOS1iMGY1LTAwZDBjYmQzYjc4YiIsImlhdCI6MTcxOTc0NjU3OH0.koZL3hhDX1ACgtpRnL5jlgf2-CkpyOgKWNhi8bUz7jI'
    #
    # # 解码 JWT
    # try:
    #     decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})  # 不验证签名
    #     print("Decoded Token:")
    #     print(decoded_token)
    # except jwt.DecodeError as e:
    #     print(f"解码失败：{e}")







