from web3 import Web3
from django.http import JsonResponse
from requests_http_signature import HTTPSignatureAuth
from rest_framework.decorators import api_view
from sign.models import BlockchainAccount, ClientSecret, NetworkType
from rest_framework.exceptions import PermissionDenied
from hdwallet import BIP44HDWallet
from hdwallet.symbols import ETH
from sign.settings import ROOT_EXT_KEY


def key_resolver(key_id, algorithm):  # used for HTTPSignatureAuth.verify(), do not change arg names!
    secret = ClientSecret.objects.get(key_id=key_id)
    return secret.key.encode('utf-8')


def get_pkey_from_child(child_idx):
    hd_wallet = BIP44HDWallet(symbol=ETH, account=0, change=False, address=0)
    hd_wallet.from_root_xprivate_key(ROOT_EXT_KEY)
    derived_wallet = hd_wallet.from_index(child_idx)
    priv = derived_wallet.private_key()
    return priv


@api_view(http_method_names=['POST'])
def sign_view(request):
    try:
        HTTPSignatureAuth.verify(request, key_resolver=key_resolver)
    except (AssertionError, ClientSecret.DoesNotExist):
        raise PermissionDenied

    tx_params = request.data
    if tx_params.get('to'):
        tx_params['to'] = Web3.toChecksumAddress(tx_params['to'])
    else:
        print('No destination address provided')

    try:
        account = BlockchainAccount.objects.get(address=tx_params.pop('from'))
    except BlockchainAccount.DoesNotExist:
        raise PermissionDenied

    if account.network_type == NetworkType.ETHEREUM_LIKE:
        if tx_params.get('child_idx'):
            priv = get_pkey_from_child(tx_params.pop('child_idx'))
        else:
            priv = account.private_key
        signed_tx = Web3().eth.account.sign_transaction(tx_params, priv)

        raw_hex_tx = signed_tx.rawTransaction.hex()
        return JsonResponse({'signed_tx': raw_hex_tx})
    elif account.network_type == NetworkType.BINANCE_CHAIN:
        raise PermissionDenied
