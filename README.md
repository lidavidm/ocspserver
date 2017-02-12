# ocspserver

This implements:
* an OCSP responder that is backed by a CFSSL `certdb`
* a RESTful API server that allows the addition and revocation of certificates to the `certdb`

To use:

    ocspserver -ocsp-issuer ca.pem -ocsp-responder responder.pem -ocsp-responder-key responder-key.pem [-ocsp-interval 96h -ocsp-refresh-freq 15m]