[![Build Status](https://travis-ci.org/sbuss/bitmerchant.png?branch=master)](https://travis-ci.org/sbuss/bitmerchant) [![Coverage Status](https://coveralls.io/repos/sbuss/bitmerchant/badge.png)](https://coveralls.io/r/sbuss/bitmerchant)

# Bitmerchant
Bitmerchant is a work-in-progress python library for common bitcoin/altcoin
merchant uses.

Bitmerchant currently supports:

1. Easy to use [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#) wallet for linking user payments with their accounts.

These features are planned (or in development where marked):

1. Regular and M-of-N transactions (under development)
2. A system that monitors the blockchain and sends out a signal when a payment is received at an address you're tracking.
3. Automatic forwarding transactions

---

If you find this library useful, please consider a small donation. Donations
will be used to reward developers for bugfixes.

|BTC|Doge|
|:-:|:--:|
|19jSqVd8bpevi3qacBedkAdDqEXtGAn5t7|DQ4b7RJfoniVwFsnrMJr6vi6n6UFeubdiv|
|![Donate BTC](https://raw.github.com/sbuss/bitmerchant/master/media/donation_btc_qr_code.gif)|![Donate DOGE](https://raw.github.com/sbuss/bitmerchant/master/media/donation_doge_qr_code.gif)|

# Installation

bitmerchant is on [pypi](https://pypi.python.org/pypi/bitmerchant), so
just use pip:

```sh
pip install bitmerchant
```

Then to verify it's working:

```python
from bitmerchant.wallet import Wallet

w = Wallet.from_master_secret("correct horse battery staple")
assert w.to_address() == "1AJ7EDxyRwyGNcL4scXfUU7XqYkmVcwHqe"
```


# BIP32 wallets

[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#)
wallets are hierarchical deterministic wallets. They allow you to generate
bitcoin/altcoin addresses without exposing your private key to a potentially
insecure server.

To link a user with a new bitcoin address, you just need to provide the user's
ID to the `create_new_address_for_user` method:

## TL;DR

```python
## DO THIS ON AN OFFLINE MACHINE, NOT YOUR WEBSERVER
from bitmerchant.wallet import Wallet

# Create a wallet, and a primary child wallet for your app
my_wallet = Wallet.new_random_wallet()
print(my_wallet.serialize_b58(private=True))  # Write this down or print it out and keep in a secure location
project_0_wallet = my_wallet.get_child(0, is_prime=True)
project_0_public = project_0_wallet.public_copy()
print(project_0_public.serialize_b58(private=False))  # Put this in your app's settings file


## THINGS BELOW ARE PUBLIC FOR YOUR WEBSERVER

# In your app's settings file, declare your public wallet:
WALLET_PUBKEY = "<public output from above>"

# Create a payment address for a user as needed:
from bitmerchant.wallet import Wallet
from myapp.settings import WALLET_PUBKEY

def get_payment_address_for_user(user):
    user_id = user.id
    assert isinstance(user_id, (int, long))
    wallet = Wallet.deserialize(WALLET_PUBKEY)
    wallet_for_user = wallet.create_new_address_for_user(user.id)
    return wallet_for_user.to_address()
```

<a id="security"></a>
## Security warning

BIP32 wallets have a vulnerability/bug that allows an attacker to recover
the master private key when given a master public key and a publicly-derived
private child. In other words:

```python
from bitmerchant.wallet import Wallet

w = Wallet.new_random_wallet()
child = w.get_child(0, is_prime=False)  # public derivation of a private child
w_pub = w.public_copy()
master_public_key = w_pub.serialize_b58(private=False)
private_child_key = child.serialize_b58(private=True)
```

Given `master_public_key` and `private_child_key`, the steps to recover the
secret master private key (`w`) are as simple as a subtraction on the
elliptic curve. This has been implemented as `Wallet.crack_private_key`,
because if it's possible to do this, then anyone should be able to do it so
the attack is well known:

```python
public_master = Wallet.deserialize(master_public_key)
private_child = Wallet.deserialize(private_child_key)
private_master = public_master.crack_private_key(private_child)
assert private_master == w  # :(
```

This attack can be mitigated by these simple steps:

1. NEVER give out your root master public key.
2. When uploading a master public key to a webserver, always use a prime child
of your master root.
3. Never give out a private child key unless the user you're giving it to
already has control of the parent private key (eg, for user-owned wallets).

Why "always use a prime child of your master root" in step 2?  Because prime
children use private derivation, which means they cannot be used to recover the
parent private key (no easier than brute force, anyway).

## Create a new wallet

If you haven't created a wallet yet, do so like this:

**IMPORTANT** You must back up your wallet's private key, otherwise you won't
be able to retrieve the coins sent to your public addresses.

```python
from bitmerchant.wallet import Wallet

my_wallet = Wallet.new_random_wallet()

# Then back up your private key

private_key = my_wallet.serialize()
print(private_key)
# Make sure that you can load your wallet successfully from this key
wallet_test = Wallet.deserialize(private_key)
assert my_wallet == wallet_test
# If that assertion fails then open a ticket!
# NOW WRITE DOWN THE PRIVATE KEY AND STORE IT IN A SECURE LOCATION
```

BIP32 wallets (or hierarchical deterministic wallets) allow you to create child
wallets which can only generate public keys and don't expose a private key to
an insecure server. You should create a new prime child wallet for every
website you run (or a new wallet entirely), and perhaps a new prime child for
each user (though that requires pre-generating a bunch of prime children
offline, since you need the private key). Try to use prime children where
possible (see [security](#security)).

It's a good idea to create at least *one* prime child wallet for use
on your website. The thinking being that if your website's wallet gets
compromised somehow, you haven't completely lost control because your master
wallet is secured on an offline machine. You can use your master wallet to move
any funds in compromised child wallets to new child wallets and you'll be ok.

Let's generate a new child wallet for your first website!

```python
# Lets assume you're loading a wallet from your safe private key backup
my_wallet = Wallet.deserialize(private_key)

# Create a new, public-only prime child wallet. Since you have the master
# private key, you can recreate this child at any time in the future and don't
# need to securely store its private key.
# Remember to generate this as a prime child! See the security notice above.
child = my_wallet.get_child(0, is_prime=True, as_private=False)

# And lets export this child key
public_key = my_wallet.serialize_b58(private=False)
print(public_key)
```

You can store your public key in your app's source code, as long as you
never reveal any private keys. See the [security notice](#security) above.

Be aware that if someone gets a hold of your public key then they can generate
all of your subsequent child addresses, which means they'll know exactly how
many coins you have. The attacker cannot spend any coins, however, unless they
are able to [recover the private key](#security).

## Generating new public addresses

BIP32 wallets allow you to generate public addresses without revealing your
private key. Just pass in the user ID that needs a wallet:

```python
from bitmerchant.wallet import Wallet
from myapp.settings import WALLET_PUBKEY  # Created above

master_wallet = Wallet.deserialize(WALLET_PUBKEY)
user_wallet = master_wallet.create_new_address_for_user(user_id)
payment_address = user_wallet.to_address()
```

This assumes that `user_id` is a unique positive integer and does not change
for the life of the user (and is less than 2,147,483,648). Now any payments
received at `payment_address` should be credited to the user identified by
`user_id`.

# Staying secure

## Public Keys

Public keys are mostly safe to keep on a public webserver. However, even though
a public key does not allow an attacker to spend any of your coins, you should
still try to protect the public key from hackers or curious eyes. Knowing the
public key allows an attacker to generate all possible child wallets and know
exactly how many coins you have. This isn't terrible, but nobody likes having
their books opened up like this.

As mentioned earlier, knowledge of a master public key and a non-prime private
child of that key is enough to be able to recover the master private key. Never
reveal private keys to users unless they already own the master private parent.

Your master public key can be used to generate a virtually unlimited number of
child public keys. Your users won't pay to your master public key, but instead
you'll use your master public key to generate a new wallet for each user.

## Private Keys

You must have the private key to spend any of your coins. If your private key
is stolen then the hacker also has control of all of your coins. With a BIP32
Wallet, generating a new master wallet is one of the only times that you need
to be paranoid (and you're not being paranoid if they really *are* out to get
you). Paranoia here is good because if anyone gets control of your master
wallet they can spend all funds in all child wallets.

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
from bitmerchant.wallet import Wallet

my_wallet = Wallet.new_random_wallet()

# Then back up your private key

private_key = my_wallet.serialize()
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
that should be online is your PUBLIC key. Your private key should be written
down (yes, on paper) and stored in a safe location, or on a computer that is
never connected to the internet.

Security wise, this is the most important part of generating secure public
payment addresses. A master private key is the only way to retrieve the funds
paid to a public address. You can use your master private key to generate the
private keys of any child wallets, and then transfer those to a networked
computer as necessary, if you want slightly smaller surface area for attacks.

Forthcoming versions of bitmerchant will allow you to generate transactions
offline that you can safely transfer to a networked computer, allowing you to
spend your child funds without ever putting a private key on a networked
machine.

# Development

I'd love for you to contribute to bitmerchant! If you can't write code, then
please open a ticket for feature requests or bugs you find!

If you can code and you'd like to submit a pull request, please be sure to
include tests. This library is quite well tested and I intend to keep coverage
above 95% indefinitely.

Rewards may be given out to developers depending on the severity of bugs
found/patched. The donation addresses mentioned at the top of this document
will be used to fund rewards.

## Testing

All of these work, though I typically use nosetest:

```sh
python setup.py test
nosetests
python -m unittest discover
```

## Packaging

See [packaging](PACKAGING.md)
