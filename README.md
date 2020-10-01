[![Hackage](https://img.shields.io/hackage/v/fpe.svg)](https://hackage.haskell.org/package/fpe)
[![Build Status](https://travis-ci.com/galenhuntington/fpe.svg?branch=master)](https://travis-ci.com/galenhuntington/fpe)

_Format-preserving encryption_ encrypts data without changing its
format.  An example is encrypting a 16-digit credit card number
as 16 digits.  The encryption uses a key, which is secret, and an
optional _tweak_, which can be public and varies for each record
(such as the cardholder's name), and provides extra security.

This module implements FF1.  Another similar algorithm, FF3, is no
longer considered secure, and so is not included (yet).

For example usage, see `ff1test.hs`.
