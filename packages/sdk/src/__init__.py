from packages.config.src.config import connect,disconnect,init, ConfigService
from packages.network.src.chain import chain as Chain
from packages.did.src import Did_chain as Did
import packages.utils.src as Utils
from packages.chainspace.src import chainspace as Chainspace

class Permission:
    ASSERT = 1 << 0  # 0001
    DELEGATE = 1 << 1  # 0010
    ADMIN = 1 << 2  # 0100

