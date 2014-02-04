# WORK IN PROGRESS

The README below is a goal I an working toward. This library is not ready
for public use.

# Bitmerchant
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

## Create a new wallet

If you haven't created a wallet yet, do so like this:

**IMPORTANT** You must back up your wallet's private key, otherwise you won't
be able to retrieve the coins sent to your public addresses.

```python
from bitmerchant.wallet import DogecoinWallet

my_wallet = DogecoinWallet.new_wallet()

# Then back up your private key

private_key = my_wallet.get_private_key()
print(private_key)
# WRITE DOWN THE RESULT AND STORE IT IN A SECURE LOCATION

public_key = my_wallet.get_public_key()
print(public_key)
# You can safely store your public key in your app's source code. There's
# no need to be paranoid about anyone getting it. All they can do is generate
# payment addresses that YOU control.
```

## Generating new public addresses

BIP32 wallets allow you to generate public addresses without revealing your
private key. 

```python
from bitmerchant.wallet import DogecoinWallet
from myapp.settings import master_public_key

payment_address = DogecoinWallet.create_address(master_public_key, user_id)
```

This assumes that `user_id` is a unique positive integer and does not change
for the life of the user. Now any payments received at `payment_address`
should be credited to the user identified by `user_id`.

# Staying secure

Public keys are PUBLIC. There's no need to protect your public key from
hackers or curious eyes. You can't spend any of your coins with the public
key, all you can do is generate new addresses.

You must have the PRIVATE key to spend any of your coins. If your private
key is stolen then the hacker also has control of all of your coins.
Generating a new wallet is the only point in dealing with cryptocurrency
that you need to be paranoid.

You should create your wallet on a computer that is not connected to the
internet. Ideally, this computer will *never* be connected to the internet
after you generate your private key. The safest way to do this is to run
Ubuntu on a livecd, install python and bitmerchant, and generate a new wallet.

Once you generate a new wallet you should write down the private key on a
piece of paper (or print it out ...but can you *really* trust your printer?)
and store it in a secure location.

```sh
sudo apt-get install python
sudo apt-get install pip

pip install bitmerchant
pip install ipython

# Then launch the ipython shell
ipython
```

Once inside your ipython shell, generate a new wallet:

```python
from bitmerchant.wallet import DogecoinWallet

my_wallet = DogecoinWallet.new_wallet()
private_key, public_key = my_wallet.get_keys()

print(private_key)
# Write down this private key.
# Double check it.
# Then shut down the computer without connecting to the internet.
```

## Master private key

Your master private key allows you to spend coins sent to any of your public
addresses. Guard this with your life, and never put it on a computer that's
connected to the internet.

Master private keys must NEVER be put on the internet. They must NEVER be
located on a computer that is even *connected* to the internet. The only key
that should be online is your PUBLIC key. Your PRIVATE key should be written
down (yes, ON PAPER) and stored in a safe location, or on a computer that is
NEVER connected to the internet.

Security wise, this is the most important part of generating secure public
payment addresses. A master private key is the onlyway to retrieve the funds
paid to a public address.

## Master public key

Master public keys are essential in producing secure public payment addresses.
You can generate an unlimited number of public addresses with your public key.
Each user in your system should have their own payment address.
