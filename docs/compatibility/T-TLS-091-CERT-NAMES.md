# T-TLS-091 compatibility note — certificate names and the subject commonName

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. The
entry below is the next free number there (**DIV-0115**) and is reproduced here so the change that
introduces it ships with its compatibility rationale. Move it into the register at merge time.

## Oracle verification (pinned Caddy v2.11.9)

Run against `/root/caddy-rs/.scratch/oracle-eval-2.11.9/caddy` (v2.11.9, certmagic v0.25.6) with
`load_files` certificates and a real TLS listener:

| certificate | SNI | oracle result |
|---|---|---|
| CN `cn-only.example`, no SAN extension | `cn-only.example` | handshake OK, certificate served |
| CN `cn-only.example`, no SAN extension | any other name | handshake refused (no matching certificate) |
| CN `cn-name.example`, SAN `DNS:san-name.example` | `san-name.example` | handshake OK |
| CN `cn-name.example`, SAN `DNS:san-name.example` | `cn-name.example` | handshake OK |

The last row is the important correction to the task premise: Caddy **does not ignore the subject
commonName when a SAN is present**. `certmagic v0.25.6 certificates.go fillCertFromLeaf` starts
`cert.Names` with `leaf.Subject.CommonName` and then appends `DNSNames`, `IPAddresses`,
`EmailAddresses` and `URIs`. The Go `crypto/x509` rule that ignores CN applies to *hostname
verification* (`VerifyHostname`), not to the certificate-name set Caddy uses for selection. The fix
therefore keeps the CN in addition to the SAN dNSName entries, and no CN+SAN divergence is
registered.

## The T-TLS-091 defect

`certificate_names()` passed `subject.content` (the content of the `Name` SEQUENCE, i.e. the first
RDN `SET`) to `common_name()`, which then read it as a complete TLV and required tag `0x30`. A
well-formed subject starts with an RDN `SET` (`0x31`), so `common_name()` always returned `None`
and every certificate without a subjectAltName `dNSName` failed with
`certificate has no subjectAltName dNSName entries and no subject commonName`.

`common_name()` now receives the already-parsed subject `Tlv` and walks the full DER path:
`Name SEQUENCE` → `RDN SET` → `AttributeTypeAndValue SEQUENCE` → OID `2.5.4.3` → value. It reads
every RDN (so a CN in a later RDN is found), keeps the last CN like Go's
`pkix.Name.FillFromRDNSequence`, decodes Go's `Name` string encodings, and returns a located error
for malformed structure or a non-string CN value.

## DIV-0115 — Non-dNSName subjectAltName entries are ignored when naming a certificate

- Status: accepted
- Area: TLS
- Caddy behaviour: certmagic's `fillCertFromLeaf` names a certificate from the subject commonName
  (deprecated but still accepted) plus every subjectAltName entry: `dNSName`, `iPAddress`,
  `rfc822Name` and `URI` (CN and the names are lowercased, and a SAN equal to the CN is not
  duplicated). A certificate whose only identity is an IP, email or URI SAN therefore loads.
- caddy-rs behaviour: `TlsCertificate` names now include the subject commonName in addition to the
  subjectAltName `dNSName` entries, so CN-only certificates load and match their CN (T-TLS-091)
  and a CN+SAN certificate is served for both names, matching the pinned oracle. iPAddress
  (`[7]`), rfc822Name (`[1]`) and URI (`[6]`) GeneralNames are still not turned into names; a
  certificate with only such an entry and no CN is rejected at load with
  `certificate has no subjectAltName dNSName entries and no subject commonName`, where Caddy
  accepts it. Subject commonName string encodings match Go (`UTF8String`, `PrintableString`,
  `IA5String`, `T61String` as Latin-1, `BMPString` as UTF-16BE and `NumericString`); any other
  value tag is a located `cannot read certificate names: subject commonName has unsupported value
  tag 0xNN` error.
- Rationale: caddy-rs' SNI resolver keys certificates by DNS name, and Caddy's IP/email/URI names
  do not participate in SNI selection either (they matter for IP site addresses, inventory and
  certificate placeholders). Rejecting a certificate that has only an IP SAN is a located,
  advertised load error rather than a silent approximation. Extending `certificate_names` to the
  remaining GeneralName forms is a residual gap outside T-TLS-091; it is listed here so the
  difference is not silent.
- Tracking: T-TLS-091
- Test: `crates/tls/src/tls_server.rs` (`cn_only_certificate_loads_and_matches_its_name`,
  `cn_and_san_certificate_prefers_san_and_keeps_cn_like_caddy`,
  `common_name_is_read_from_the_attribute_value_tlv`,
  `common_name_is_found_in_a_later_multi_rdn_subject`,
  `common_name_supports_go_string_encodings`, `non_string_common_name_value_fails_loudly`,
  `empty_subject_is_a_located_error_not_a_panic`,
  `malformed_subject_is_a_located_error_not_a_panic`, `cn_only_certificate_is_selected_over_tls`).

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`: insert the `## DIV-0115` section above (next free
number after DIV-0114), keeping every field line.

No `CONFIGURATION.md` or `CADDYFILE.md` row changes are required: this is certificate-name
extraction, not accepted configuration or emitted JSON.

If the Lead decides the non-dNSName SAN gap should not be registered as a divergence, omit
DIV-0115 entirely: the CN-only and CN+SAN behaviour itself matches the pinned oracle, so no other
register entry is needed.
