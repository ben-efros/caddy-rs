# GeoIP test fixtures

Two real MaxMind DB files, copied unmodified from the official
[`maxmind/MaxMind-DB`](https://github.com/maxmind/MaxMind-DB) test data
(`test-data/GeoIP2-ISP-Test.mmdb`, `test-data/GeoIP2-Country-Test.mmdb`).

They are committed rather than generated so the tests exercise a **real** database parser against
**real** MaxMind DB binary format. A hand-built fake would only prove that the fake round-trips.

| File | Records used | IPs asserted |
|---|---|---|
| `GeoIP2-ISP-Test.mmdb` | ASN (`autonomous_system_number`) | `1.128.0.1` → 1221, `89.160.20.112` → 29518 |
| `GeoIP2-Country-Test.mmdb` | country (`country.iso_code`) | `2.125.160.216` → GB, `89.160.20.112` → SE |

Addresses with no record (`10.0.0.1`, `203.0.113.5`) are asserted to resolve to `None`, which is
the "unknown address" case, and is distinct from the "no database at all" case.

## Licence

Copyright (c) MaxMind, Inc. Dual-licensed under Apache-2.0 or MIT, at your option — see
[`LICENSE-APACHE`](https://github.com/maxmind/MaxMind-DB/blob/main/LICENSE-APACHE) and
[`LICENSE-MIT`](https://github.com/maxmind/MaxMind-DB/blob/main/LICENSE-MIT). These are synthetic
test databases, not production GeoIP data, so they carry no GeoLite2/GeoIP2 EULA obligations.

Do **not** replace these with a production DB-IP or MaxMind download: those are large (tens of MB)
and, for MaxMind, licence-encumbered.
