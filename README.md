Bitmerchant is a work-in-progress python library for common bitcoin/altcoin
merchant uses.

First goal is BIP32 wallets for linking user payments with their accounts.

# BIP32 wallets

[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#)
wallets are hierarchical deterministic wallets. They allow you to generate
bitcoin/altcoin addresses without exposing your private key to a potentially
insecure server. What this means for you as a merchant is that **you can accept
bitcoin/altcoin payments as securely as possible**.

To link a user with a new bitcoin address, you just need to provide the user's
ID to the `create_address` method:

```python
from bitmerchant.bip32 import create_address
from myapp.settings import master_public_key

payment_address = create_address(master_public_key, user_id)
```

This assumes that `user_id` is a unique positive integer and does not change
for the life of the user.

## Master public key

Master public keys are essential in producing secure public payment addresses.
To generate a master public key, you also need to generate a master PRIVATE
key.

Security wise, this is the most important part of generating secure public
payment addresses. A master public key and master private key are the only
way to retrieve the funds paid to a public address.

Master private keys must NEVER be put on the internet. They must NEVER be
located on a computer that is even *connected* to the internet. The only key
that should be online is your PUBLIC key. Your PRIVATE key should be written
down (yes, ON PAPER) and stored in a safe location, or on a computer that is
NEVER connected to the internet.

### Generating master keys

```python
from bitmerchant.bip32.master import create_master_keys

private_key, public_key = create_master_keys()
```
