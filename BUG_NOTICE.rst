Bug Notice
==========

Versions of ``bitmerchant`` prior to ``0.1.8`` contained a caching bug that may
have resulted in calls to ``bip32.Wallet.get_child`` to return incorrect results.
All affected versions were removed from pypi, and no users are known to have
been affected by this bug.

The steps to reproduce the bug are unlikely and do not match the typical
usage patterns of ``bitmerchant``.

**At this time, no users are known to have been affected by this bug.**

If you have been affected by this bug and need help recovering any lost or
misplaced coins, please contact me directly at
steven.buss+bitmerchant@gmail.com.

The affected versions of ``bitmerchant`` have been removed from pypi. They
have not been untagged in git.

The two possible failure scenarios are: misplaced coins and stolen coins

Misplaced Coins
---------------

This is still unlikely, but slightly more likely than having your coins stolen.

In order to have misplaced coins as a result of the bug, all of the below
points must be true:

#. Your master private key must be available for your code to load, rather than in a secure offline backup
#. You call ``get_child`` directly, rather than ``create_new_address_for_user``
#. You call ``get_child(n, is_prime=False)`` and ``get_child(n, is_prime=True)``
    #. in the same python process
    #. on the same wallet object
    #. you display the public address of the second ``get_child`` call (in whichever order)

In this case, the bug would have resulted in the first ``get_child``'s address
being shown. You can easily recover these misplaced coins by updating to
``bitmerchant>=0.1.8``, regenerating the address you accidentally sent coins
to, and moving them to a corrected destination. The "deterministic" part of
"hierarchical deterministic wallets" really works to your advantage here.

Stolen Coins
------------

First, it is extremely unlikely that your code met all of the requirements
to be affected by this bug. If you can answer "yes" to every one of the points
below, then you should upgrade to ``bitmerchant>=0.1.8``, generate a new master
private key, and move all coins to the new wallet as soon as possible.

In order to have coins stolen as a result of the bug, all of the below points
must be true:

#. You expose your master public key to the public
#. Your master private key must be available for your code to load, rather than in a secure offline backup
#. You call ``get_child`` directly, rather than ``create_new_address_for_user``
#. You call ``get_child(n, is_prime=False)`` and ``get_child(n, is_prime=True)``
    #. in that order
    #. in the same python process
    #. on the same wallet object
    #. with the intention of only giving the prime child to the user
#. You give the public and private keys of child wallets to users
