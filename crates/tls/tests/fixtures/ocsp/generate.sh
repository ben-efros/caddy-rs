#!/bin/bash
# Generates independent OCSP fixtures with the OpenSSL CLI (see the README next to the output).
set -euo pipefail
OUT="$1"
WORK=$(mktemp -d)
cd "$WORK"
SERIAL_HEX=8F2A6C41D9B37E5510A4C3D2E1F00B97   # high bit set: DER INTEGER carries a 00 prefix
DAYS=36500

newkey() { # type keyfile
  case "$1" in
    rsa2048) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$2" 2>/dev/null ;;
    p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2" ;;
    p384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$2" ;;
    ed25519) openssl genpkey -algorithm ED25519 -out "$2" ;;
  esac
}

# make_case <name> <ca-key-type> <good|revoked:reason> <direct|delegated> <byname|bykey> <nonce|nonce-none> [delegate-key-type]
make_case() {
  local name=$1 catype=$2 status=$3 mode=$4 rid=$5 nonce=$6 dtype=${7:-p256}
  local d="$OUT/$name"
  mkdir -p "$d"
  newkey "$catype" ca.key
  openssl req -x509 -new -key ca.key -subj "/O=caddy-rs ocsp fixtures/CN=Fixture CA $catype" \
    -days $DAYS -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out ca.pem
  newkey p256 leaf.key
  openssl req -new -key leaf.key -subj "/CN=leaf.example.test" -out leaf.csr
  cat > leaf.ext <<EOF
authorityInfoAccess=OCSP;URI:http://ocsp.example.test
subjectAltName=DNS:leaf.example.test
EOF
  openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 0x$SERIAL_HEX -days $DAYS \
    -extfile leaf.ext -out leaf.pem 2>/dev/null
  if [ "$status" = good ]; then
    printf 'V\t491231235959Z\t\t%s\tunknown\t/CN=leaf.example.test\n' "$SERIAL_HEX" > index.txt
  else
    printf 'R\t491231235959Z\t260101000000Z,%s\t%s\tunknown\t/CN=leaf.example.test\n' "${status#revoked:}" "$SERIAL_HEX" > index.txt
  fi
  local signer=ca.pem signkey=ca.key
  if [ "$mode" = delegated ]; then
    newkey "$dtype" resp.key
    openssl req -new -key resp.key -subj "/CN=Fixture OCSP Delegate" -out resp.csr
    cat > resp.ext <<EOF
extendedKeyUsage=critical,OCSPSigning
basicConstraints=CA:FALSE
EOF
    openssl x509 -req -in resp.csr -CA ca.pem -CAkey ca.key -set_serial 0x77 -days $DAYS -extfile resp.ext -out resp.pem 2>/dev/null
    signer=resp.pem; signkey=resp.key
  fi
  local nonce_flag=""
  [ "$nonce" = nonce-none ] && nonce_flag="-no_nonce"
  openssl ocsp -issuer ca.pem -cert leaf.pem $nonce_flag -reqout req.der >/dev/null 2>&1
  local keyid=""
  [ "$rid" = bykey ] && keyid="-resp_key_id"
  openssl ocsp -index index.txt -CA ca.pem -rsigner "$signer" -rkey "$signkey" -reqin req.der \
    -ndays 3650 $keyid -respout resp.der >/dev/null 2>&1
  openssl x509 -in leaf.pem -outform DER -out "$d/leaf.der"
  openssl x509 -in ca.pem -outform DER -out "$d/issuer.der"
  cp resp.der "$d/response.der"
  rm -f resp.pem resp.key resp.csr resp.ext
  echo "$name: $(stat -c %s "$d/response.der") bytes"
}

make_case rsa2048-direct-byname-good-nonce  rsa2048 good           direct    byname nonce
make_case p256-direct-bykey-good-nonce-none p256    good           direct    bykey  nonce-none
make_case p384-direct-byname-revoked-keycompromise p384 revoked:keyCompromise direct byname nonce
make_case ed25519-direct-byname-good        ed25519 good           direct    byname nonce
make_case rsa2048-delegated-byname-good     rsa2048 good           delegated byname nonce p256
make_case p256-delegated-bykey-revoked-superseded p256 revoked:superseded delegated bykey nonce-none p384
make_case p384-delegated-byname-good-ed25519-responder p384 good delegated byname nonce ed25519
rm -rf "$WORK"
