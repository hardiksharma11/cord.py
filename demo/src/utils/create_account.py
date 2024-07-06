import packages.sdk.src as Cord

def create_account(mnemonic=None):
    """
    `createAccount` creates a new account from a mnemonic
    :param mnenonic: The mnemonic phrase to use to generate the account. If not provided, a new mnemonic will be generated.
    :return: An object with two properties: account and mnemonic.
    """
    if mnemonic is None:
        mnemonic = Cord.Utils.crypto_utils.generate_mnemonic(24)
    return {
        'account': Cord.Utils.crypto_utils.create_from_mnemonic(mnemonic, 'ed25519'),
        'mnemonic': mnemonic
    }
