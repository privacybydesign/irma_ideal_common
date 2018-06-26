# iDeal library

A library to communicate with Dutch banks using the iDeal protocol.

## Current status

This library is a work in progress and is not yet finished.

Implemented methods:

  * DirectoryRequest

Tested endpoints:

  * Volksbank/ING (integration environment)

## About iDeal

iDeal is a relatively simple RPC-like protocol, using
[signed XML messages](https://en.wikipedia.org/wiki/XML_Signature) over HTTPS.

This library was originally based on non-public documentation but at least one
version of it appears to be public: on the
[Rabobank website](https://www.rabobank.nl/images/ideal_merchant_integration_guide_29696264.pdf).
