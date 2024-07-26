from loguru import logger
import asyncio

from src.project.blackpass import BlackPassAPI
from models import Account
from src.twitter.bk_twitter import TwitterConnectModded
from src.wallet.bk_wallet import Wallet
class Bot(BlackPassAPI):
    def __init__(self, account_data: Account):
        super().__init__(account_data)

        self.wallet = Wallet(account_data.mnemonic)
        if not account_data.mnemonic:
            account_data.mnemonic = self.wallet.mnemonic


    async def start(self) -> bool:
        try:
            twitter_connect = TwitterConnectModded(session=self.session, account_data=self.account)
            account = await twitter_connect.start()

            #
            # if not account:
            #     return False
            #
            # self.__init__(account)
            self.wallet.sign_login_message()
            # 登录项目方
            # status = await self.process_quests()
            # if status:
            #     await self.process_open_chests()
            #     return True

            return True

        except Exception as error:
            logger.error(
                f"Account: {self.account.auth_token} | Unhandled error: {error}"
            )
            return False

        finally:
            if self.account:
                logger.success(f"Account: {self.account.auth_token} | Finished")