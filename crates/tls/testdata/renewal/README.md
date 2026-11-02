# Renewal test fixtures

Test-only self-signed certificate returned by the fake ACME CA for `renewal-wiring` tests.

`renewed-example.com.pem` covers `example.com`/`www.example.com` and is valid 2026-01-01 through
2040-01-01, i.e. it has a later `notAfter` than the `../https/example.com.pem` fixture used for the
initial issuance, so tests can prove a renewal replaced the served certificate. It protects
nothing and is trusted by no client.
