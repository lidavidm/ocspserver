# ocspserver

This implements:
* an OCSP responder that is backed by a CFSSL `certdb`
* a RESTful API server that allows the addition and revocation of certificates to the `certdb`