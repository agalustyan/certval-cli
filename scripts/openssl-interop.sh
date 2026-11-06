#!/usr/bin/env bash
# Runs certval (certval-cli's command) against openssl: `certval cms` and `openssl cms` against
# each other for the four operations both provide, and `certval ca`'s certificates, CRLs and OCSP
# responses checked by openssl, under every --crypto choice the certval binary offers, and reports
# a matrix of what each choice did with each case.
#
#   decrypt  openssl encrypts, certval decrypts: RSA key transport (PKCS #1 v1.5, OAEP with
#            SHA-1/256/384/512), ECDH on P-256/384/521 with each X9.63 KDF hash, ML-KEM-512/768/1024,
#            AES-CBC and AES-GCM content, and one message to several recipients
#   encrypt  certval encrypts, openssl decrypts: the same recipient types, plus each key wrap and
#            user keying material
#   sign     certval signs, openssl verifies: RSA PKCS #1 v1.5 and PSS, ECDSA on each curve, ML-DSA,
#            each digest, detached, PEM, without the signer's certificate, without ESSCertIDv2
#   verify   openssl signs, certval verifies and validates against the test CA: the same signers,
#            PSS with a maximal salt, detached, without signed attributes, PEM
#   issue    certval ca issue, openssl verifies: a CA for each RSA, EC and ML-DSA key (its
#            certificate issued by the test CA) issues a certificate from an openssl request, RSA
#            also with PSS, and P-256 from an ML-KEM public key
#   crl      certval ca crl, openssl verifies the CRL with the CA's certificate and finds the
#            revoked serial number in it, from the same CAs
#   ocsp     certval ca ocsp answers an openssl request (with a nonce) about a serial number it
#            reports revoked, openssl verifies the response against the saved request; from the
#            same CAs, and from a delegated responder of the P-256 CA
#   req      certval req signs a certificate request, which openssl req -verify accepts, and with
#            --x509 a self-signed certificate, which openssl verify accepts: each RSA, EC and ML-DSA
#            key, RSA also with PSS. pkcs11 is n/a: req takes no key on a token yet
#
# A test CA and keys are made with openssl in WORKDIR. ML-DSA needs openssl 3.5, and ML-KEM in CMS
# 3.6; with an older openssl those cases are left out and the summary says so. One case is expected
# to be refused by every choice: ECDH with openssl's default SHA-1 KDF, which certval-cms does not
# offer.
#
# Each case runs first with --only, so that the choice alone performs it. When that fails, it runs
# again without --only, with software behind the choice:
#
#   ok       the choice performed it alone, and openssl agrees with the result
#   sw       the choice declined part of it and software answered (e.g. GCM under Security.framework)
#   no       the choice declined, and software could not stand in, because the choice's own key
#            performs the operation (e.g. ML-DSA signing under AWS-LC)
#   n/a      the choice has no key for it (PKCS #11 holds only the keys pkcs11-tool can import)
#   refused  certval refused a case it is expected to refuse
#   FAIL     certval failed for a reason other than declining
#   DIFFER   certval succeeded and openssl did not accept or match the result, or the reverse for
#            an expected refusal
#   OSSL     openssl could not make the input for the case (the row is openssl's limit)
#
# Usage:
#   scripts/openssl-interop.sh [-c CERTVAL] [-s OPENSSL] [-w WORKDIR] [--crypto LIST]
#                              [--ops decrypt,encrypt,sign,verify,issue,crl,ocsp,req]
#                              [--pkcs11-module FILE] [--pkcs11-token LABEL] [--pkcs11-pin PIN]
#                              [--log FILE]
#
#   -c CERTVAL        the certval binary, built with the openssl feature to include that choice;
#                     defaults to $CERTVAL, then certval on PATH
#   -s OPENSSL        the openssl binary; defaults to $OPENSSL, then openssl on PATH
#   -w WORKDIR        where the keys, messages and results go; defaults to a new directory under
#                     $TMPDIR
#   --crypto LIST     the --crypto choices to run; defaults to every one the binary offers, without
#                     pkcs11 when no module is named
#   --ops LIST        run only these operations; issue, crl and ocsp are left out of the default
#                     when the certval binary has no `ca` command, and req when it has no `req`
#   --pkcs11-module, --pkcs11-token, --pkcs11-pin
#                     the module, token label and user PIN for pkcs11; default to
#                     $CERTVAL_PKCS11_MODULE, $CERTVAL_PKCS11_TOKEN_LABEL and
#                     $CERTVAL_PKCS11_USER_PIN, as certval-pkcs11's env script sets them
#   --log FILE        writes every openssl, certval and pkcs11-tool command the script runs to FILE,
#                     under a comment line for each case, ready to paste into a shell (the PIN
#                     included)
#
# For pkcs11, the RSA and EC keys are put on the token with pkcs11-tool (OpenSC) as token objects
# with an ID of this run's own, and removed when the script exits. Decrypting takes the key by the
# message's recipient identifiers and signing by --cert, as `certval cms` does without --key. Each
# is put on a second time with its CA certificate, for issue, crl and ocsp, which take the CA's key
# by --cert as well. The delegated OCSP responder's key stays a file, so pkcs11 is n/a for it.
#
# Exit status: 0 when every cell is ok, sw, no, n/a or refused; 1 when any is FAIL, DIFFER or OSSL;
# 2 on a usage error. Every non-ok cell's commands and messages are in WORKDIR/report.txt, the
# matrix in WORKDIR/summary.txt and one line per cell in WORKDIR/results.tsv.

set -euo pipefail

CERTVAL=${CERTVAL:-certval}
OPENSSL=${OPENSSL:-openssl}
WORK=
CRYPTOS=
OPS=
PKCS11_MODULE=${CERTVAL_PKCS11_MODULE:-}
PKCS11_TOKEN=${CERTVAL_PKCS11_TOKEN_LABEL:-}
PKCS11_PIN=${CERTVAL_PKCS11_USER_PIN:-}
LOG=

usage() {
    sed -n '/^# Usage:/,/^# For pkcs11/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case $1 in
        -c) CERTVAL=$2; shift 2 ;;
        -s) OPENSSL=$2; shift 2 ;;
        -w) WORK=$2; shift 2 ;;
        --crypto) CRYPTOS=$2; shift 2 ;;
        --ops) OPS=$2; shift 2 ;;
        --pkcs11-module) PKCS11_MODULE=$2; shift 2 ;;
        --pkcs11-token) PKCS11_TOKEN=$2; shift 2 ;;
        --pkcs11-pin) PKCS11_PIN=$2; shift 2 ;;
        --log) LOG=$2; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

command -v "$CERTVAL" >/dev/null || { echo "certval not found: $CERTVAL" >&2; exit 2; }
command -v "$OPENSSL" >/dev/null || { echo "openssl not found: $OPENSSL" >&2; exit 2; }
# Absolute, since certval and openssl run from inside WORKDIR.
absolute() { local p; p=$(command -v "$1"); case $p in /*) echo "$p" ;; *) echo "$(cd "$(dirname "$p")" && pwd)/$(basename "$p")" ;; esac; }
CERTVAL=$(absolute "$CERTVAL")
OPENSSL=$(absolute "$OPENSSL")
[ -n "$WORK" ] || WORK=$(mktemp -d "${TMPDIR:-/tmp}/certval-openssl-interop.XXXXXX")
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
PKI=$WORK/pki
mkdir -p "$PKI"
REPORT=$WORK/report.txt
RESULTS=$WORK/results.tsv
: > "$REPORT"
: > "$RESULTS"
if [ -n "$LOG" ]; then
    : > "$LOG"
    LOG=$(cd "$(dirname "$LOG")" && pwd)/$(basename "$LOG")
fi

# logcmd COMMAND...: appends COMMAND to the --log file, quoted for a shell.
logcmd() {
    [ -n "$LOG" ] || return 0
    { printf '%q' "$1"; shift; [ $# -eq 0 ] || printf ' %q' "$@"; printf '\n'; } >> "$LOG"
}
# logcase TEXT: a comment line in the --log file ahead of a case's commands.
logcase() {
    [ -n "$LOG" ] || return 0
    printf '\n# %s\n' "$*" >> "$LOG"
}

# The choices the binary offers, from its short help: "[possible values: software, openssl, ...]".
help=$("$CERTVAL" cms decrypt -h)
offered=$(printf '%s\n' "$help" | awk '/--crypto/ {c = 1} c && /possible values:/ {sub(/.*possible values: /, ""); sub(/\].*/, ""); gsub(/ /, ""); print; exit}')
[ -n "$offered" ] || { echo "could not read the --crypto choices from certval cms decrypt -h" >&2; exit 2; }
if [ -z "$CRYPTOS" ]; then
    CRYPTOS=$offered
    [ -n "$PKCS11_MODULE" ] || CRYPTOS=$(printf '%s\n' "$CRYPTOS" | tr ',' '\n' | grep -vx pkcs11 | paste -sd, -)
fi
for c in $(printf '%s\n' "$CRYPTOS" | tr ',' ' '); do
    case ",$offered," in *",$c,"*) ;; *) echo "$CERTVAL does not offer --crypto $c (it offers $offered)" >&2; exit 2 ;; esac
done
BACKENDS=$(printf '%s\n' "$CRYPTOS" | tr ',' ' ')

# issue, crl and ocsp need `certval ca`, which older binaries do not have.
HAS_CA=0
"$CERTVAL" ca -h >/dev/null 2>&1 && HAS_CA=1
HAS_REQ=0
"$CERTVAL" req -h >/dev/null 2>&1 && HAS_REQ=1
if [ -z "$OPS" ]; then
    OPS=decrypt,encrypt,sign,verify
    if [ "$HAS_CA" = 1 ]; then OPS=$OPS,issue,crl,ocsp; else echo "certval has no ca command: issue, crl and ocsp left out"; fi
    if [ "$HAS_REQ" = 1 ]; then OPS=$OPS,req; else echo "certval has no req command: req left out"; fi
fi
case ",$OPS," in
    *,issue,*|*,crl,*|*,ocsp,*) [ "$HAS_CA" = 1 ] || { echo "$CERTVAL has no ca command for issue, crl or ocsp" >&2; exit 2; } ;;
esac
case ",$OPS," in
    *,req,*) [ "$HAS_REQ" = 1 ] || { echo "$CERTVAL has no req command" >&2; exit 2; } ;;
esac

wanted() { case ",$OPS," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# contains TEXT PATTERN: whether TEXT holds PATTERN, matched in the shell. Not `printf | grep -q`:
# grep -q exits at the first match, and under pipefail the writer's SIGPIPE, which a text larger
# than the pipe buffer (an ML-DSA-87 response's dump) can get, fails the pipeline as a non-match.
contains() { case $1 in *"$2"*) return 0 ;; *) return 1 ;; esac; }

# ---- openssl's version decides the post-quantum cases

version=$("$OPENSSL" version | awk '{print $2}')
major=${version%%.*}
minor=${version#*.}; minor=${minor%%.*}
PQ_SIG=0; PQ_KEM=0
if [ "$major" -gt 3 ] || { [ "$major" = 3 ] && [ "$minor" -ge 5 ]; }; then PQ_SIG=1; fi
if [ "$major" -gt 3 ] || { [ "$major" = 3 ] && [ "$minor" -ge 6 ]; }; then PQ_KEM=1; fi

export OPENSSL_CONF=$PKI/openssl.cnf
printf '[req]\ndistinguished_name = dn\n[dn]\n' > "$OPENSSL_CONF"
if [ -n "$LOG" ]; then
    logcmd cd "$PKI"
    logcmd export "OPENSSL_CONF=$OPENSSL_CONF"
    logcase "the test PKI"
fi

ossl() { logcmd "$OPENSSL" "$@"; (cd "$PKI" && "$OPENSSL" "$@"); }

# ---- the test PKI

MSG=$PKI/message.txt
printf 'certval openssl-interop, a message longer than one AES block so that padding is exercised\n' > "$MSG"

echo "making the test PKI in $PKI"
ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt \
    -subj "/CN=certval openssl-interop CA" -days 2 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=keyCertSign,cRLSign 2>/dev/null
printf 'basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$PKI/ee.ext"

RSA_KEYS="rsa2048 rsa3072"
EC_KEYS="p256 p384 p521"
KEM_KEYS=""
DSA_KEYS=""
[ "$PQ_KEM" = 1 ] && KEM_KEYS="mlkem512 mlkem768 mlkem1024"
[ "$PQ_SIG" = 1 ] && DSA_KEYS="mldsa44 mldsa65 mldsa87"

genkey() {
    case $1 in
        rsa2048) ossl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" ;;
        rsa3072) ossl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$1.key" ;;
        p256) ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" ;;
        p384) ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1.key" ;;
        p521) ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$1.key" ;;
        mlkem512) ossl genpkey -algorithm ML-KEM-512 -out "$1.key" ;;
        mlkem768) ossl genpkey -algorithm ML-KEM-768 -out "$1.key" ;;
        mlkem1024) ossl genpkey -algorithm ML-KEM-1024 -out "$1.key" ;;
        mldsa44) ossl genpkey -algorithm ML-DSA-44 -out "$1.key" ;;
        mldsa65) ossl genpkey -algorithm ML-DSA-65 -out "$1.key" ;;
        mldsa87) ossl genpkey -algorithm ML-DSA-87 -out "$1.key" ;;
    esac
}

for k in $RSA_KEYS $EC_KEYS $KEM_KEYS $DSA_KEYS; do
    genkey "$k" 2>/dev/null
    issue="-CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ee.ext -out $k.crt"
    case $k in
        mlkem*)
            # An ML-KEM key cannot sign a request, so its certificate is made from the public key.
            ossl pkey -in "$k.key" -pubout -out "$k.pub"
            # shellcheck disable=SC2086
            ossl x509 -new -subj "/CN=$k" -force_pubkey "$k.pub" $issue 2>/dev/null ;;
        *)
            ossl req -new -key "$k.key" -subj "/CN=$k" -out "$k.csr"
            # shellcheck disable=SC2086
            ossl x509 -req -in "$k.csr" $issue 2>/dev/null ;;
    esac
done

# Each RSA, EC and ML-DSA key is also a CA, its certificate issued by the test CA, for issue, crl
# and ocsp; and the P-256 CA delegates OCSP to a responder of its own.
CA_KEYS="$RSA_KEYS $EC_KEYS $DSA_KEYS"
if wanted issue || wanted crl || wanted ocsp; then
    printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$PKI/ca.ext"
    for k in $CA_KEYS; do
        ossl req -new -key "$k.key" -subj "/CN=ca-$k" -out "ca-$k.csr"
        ossl x509 -req -in "ca-$k.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
            -extfile ca.ext -out "ca-$k.crt" 2>/dev/null
    done
    printf 'keyUsage=critical,digitalSignature\nextendedKeyUsage=OCSPSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$PKI/responder.ext"
    ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out responder.key 2>/dev/null
    ossl req -new -key responder.key -subj "/CN=ocsp responder for ca-p256" -out responder.csr
    ossl x509 -req -in responder.csr -CA ca-p256.crt -CAkey p256.key -CAcreateserial -days 2 \
        -extfile responder.ext -out responder.crt 2>/dev/null
fi

# ---- keys on a PKCS #11 token

ON_TOKEN=" "
TOKEN_IDS=""
P11_ARGS=()
p11tool() {
    local token=()
    [ -z "$PKCS11_TOKEN" ] || token=(--token-label "$PKCS11_TOKEN")
    logcmd pkcs11-tool --module "$PKCS11_MODULE" ${token[@]+"${token[@]}"} --login --pin "$PKCS11_PIN" "$@"
    pkcs11-tool --module "$PKCS11_MODULE" ${token[@]+"${token[@]}"} --login --pin "$PKCS11_PIN" "$@"
}
cleanup_token() {
    local id
    logcase "removing the keys from the token"
    for id in $TOKEN_IDS; do
        p11tool --delete-object --type privkey --id "$id" >/dev/null 2>&1 || true
        p11tool --delete-object --type cert --id "$id" >/dev/null 2>&1 || true
    done
}
case " $BACKENDS " in
    *" pkcs11 "*)
        [ -n "$PKCS11_PIN" ] || { echo "pkcs11 needs --pkcs11-pin (or CERTVAL_PKCS11_USER_PIN)" >&2; exit 2; }
        P11_ARGS=(--pkcs11-module "$PKCS11_MODULE" --pkcs11-pin "$PKCS11_PIN")
        [ -z "$PKCS11_TOKEN" ] || P11_ARGS+=(--pkcs11-token "$PKCS11_TOKEN")
        if command -v pkcs11-tool >/dev/null; then
            trap cleanup_token EXIT
            logcase "keys on the token"
            run_id=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
            n=0
            for k in $RSA_KEYS $EC_KEYS $KEM_KEYS $DSA_KEYS; do
                n=$((n + 1))
                id=$run_id$(printf '%02x' "$n")
                ossl pkcs8 -topk8 -nocrypt -in "$k.key" -outform DER -out "$k.p8"
                ossl x509 -in "$k.crt" -outform DER -out "$k.der"
                if p11tool --write-object "$PKI/$k.p8" --type privkey --id "$id" --label "certval-interop-$k" \
                        --usage-sign --usage-decrypt --usage-derive >/dev/null 2>&1; then
                    TOKEN_IDS="$TOKEN_IDS $id"
                    if p11tool --write-object "$PKI/$k.der" --type cert --id "$id" --label "certval-interop-$k" >/dev/null 2>&1; then
                        ON_TOKEN="$ON_TOKEN$k "
                    fi
                fi
            done
            if wanted issue || wanted crl || wanted ocsp; then
                for k in $CA_KEYS; do
                    n=$((n + 1))
                    id=$run_id$(printf '%02x' "$n")
                    ossl x509 -in "ca-$k.crt" -outform DER -out "ca-$k.der"
                    if p11tool --write-object "$PKI/$k.p8" --type privkey --id "$id" --label "certval-interop-ca-$k" \
                            --usage-sign >/dev/null 2>&1; then
                        TOKEN_IDS="$TOKEN_IDS $id"
                        if p11tool --write-object "$PKI/ca-$k.der" --type cert --id "$id" --label "certval-interop-ca-$k" >/dev/null 2>&1; then
                            ON_TOKEN="${ON_TOKEN}ca-$k "
                        fi
                    fi
                done
            fi
            echo "keys on the token: ${ON_TOKEN# }"
        else
            echo "pkcs11-tool not found: pkcs11 decrypts and signs with no key (n/a)"
        fi ;;
esac

# ---- running certval and recording what happened

CV_OUT=$WORK/certval.out
CV_ERR=$WORK/certval.err
CONTENT=$WORK/content.out

# The arguments that name the key for OP (decrypt or sign) with backend B: the files, or for
# pkcs11 the key on the token. Sets KEY_ARGS; returns 1 when B has no key for it.
key_args() {
    local op=$1 key=$2 b=$3
    KEY_ARGS=()
    if [ "$b" = pkcs11 ]; then
        case $ON_TOKEN in *" $key "*) ;; *) return 1 ;; esac
        [ "$op" = sign ] && KEY_ARGS=(--cert "$PKI/$key.crt")
        [ "$op" = ca ] && KEY_ARGS=(--cert "$PKI/$key.crt")
        return 0
    fi
    case $op:$key in
        ca:ca-*) KEY_ARGS=(--cert "$PKI/$key.crt" --key "$PKI/${key#ca-}.key") ;;
        *) KEY_ARGS=(--cert "$PKI/$key.crt" --key "$PKI/$key.key") ;;
    esac
}

cv() {
    local status=0
    logcmd "$CERTVAL" "$@"
    (cd "$PKI" && "$CERTVAL" "$@") > "$CV_OUT" 2> "$CV_ERR" || status=$?
    LAST_CMD="certval $*"
    return $status
}

record() {
    printf '%s\t%s\t%s\t%s\n' "$OP" "$CASE" "$1" "$2" >> "$RESULTS"
}

# note BACKEND OUTCOME TEXT: a non-ok cell, with what explains it, in the report.
note() {
    {
        printf '%s  %s  %s  %s\n' "$OP" "$CASE" "$1" "$2"
        printf '%s\n' "$3" | sed 's/^/    /'
    } >> "$REPORT"
}

# attempt BACKEND EXPECT CHECK ARGS...: runs certval ARGS with --crypto BACKEND, with --only and
# then without it if that fails, runs CHECK (a function) on success, and records the outcome.
# EXPECT is ok, or refuse for a case certval is expected to refuse.
attempt() {
    local b=$1 expect=$2 check=$3
    shift 3
    local cargs=(--crypto "$b")
    [ "$b" != pkcs11 ] || cargs+=("${P11_ARGS[@]}")
    local only_err outcome
    if cv "$@" "${cargs[@]}" --only; then
        if [ "$expect" = refuse ]; then
            outcome=DIFFER; note "$b" "$outcome" "expected a refusal, but certval succeeded: $LAST_CMD"
        elif $check; then
            outcome=ok
        else
            outcome=DIFFER; note "$b" "$outcome" "$LAST_CMD"$'\n'"$CHECK_MSG"
        fi
        record "$b" "$outcome"; return
    fi
    only_err=$(cat "$CV_ERR")
    if [ "$expect" = refuse ]; then
        record "$b" refused; return
    fi
    if [ "$b" != software ] && cv "$@" "${cargs[@]}"; then
        if $check; then
            outcome=sw; note "$b" "$outcome" "with --only: $only_err"
        else
            outcome=DIFFER; note "$b" "$outcome" "$LAST_CMD"$'\n'"$CHECK_MSG"
        fi
    elif contains "$only_err" 'not performed by this implementation'; then
        outcome=no; note "$b" "$outcome" "$LAST_CMD"$'\n'"$only_err"
    else
        outcome=FAIL; note "$b" "$outcome" "$LAST_CMD"$'\n'"with --only: $only_err"$'\n'"without: $(cat "$CV_ERR")"
    fi
    record "$b" "$outcome"
}

# The openssl side of a case could not be made: every backend's cell says so.
openssl_cannot() {
    local b
    for b in $BACKENDS; do record "$b" OSSL; done
    note "-" OSSL "$1"
}

# ---- checks, run after certval succeeds; each sets CHECK_MSG when it fails

CHECK_MSG=
content_matches() {
    if cmp -s "$CONTENT" "$MSG"; then return 0; fi
    CHECK_MSG="the decrypted content differs from the message"; return 1
}
RECIPS=""
openssl_decrypts() {
    local k out
    for k in $RECIPS; do
        if ! out=$(ossl cms -decrypt -binary -inform DER -in "$WORK/msg.der" -recip "$k.crt" -inkey "$k.key" 2>&1); then
            CHECK_MSG="openssl cms -decrypt as $k: $out"; return 1
        fi
        if [ "$out" != "$(cat "$MSG")" ]; then
            CHECK_MSG="openssl decrypted as $k to different content"; return 1
        fi
    done
}
VERIFY_EXTRA=()
openssl_verifies() {
    local out
    if ! out=$(ossl cms -verify -binary ${VERIFY_EXTRA[@]+"${VERIFY_EXTRA[@]}"} -in "$WORK/signed" -CAfile ca.crt -purpose any 2>&1 >"$WORK/verified.out"); then
        CHECK_MSG="openssl cms -verify: $out"; return 1
    fi
    if ! cmp -s "$WORK/verified.out" "$MSG"; then
        CHECK_MSG="openssl verified different content"; return 1
    fi
}
certval_validates() {
    if ! grep -q 'signature verified, certificate validated' "$CV_OUT"; then
        CHECK_MSG="certval: $(cat "$CV_OUT")"; return 1
    fi
    content_matches
}

# ---- decrypt: openssl encrypts, certval decrypts

# decrypt_case CASE RECIPIENTS DECRYPT_AS EXPECT CIPHER RSA_KEYOPTS EC_KEYOPTS: the keyopts are
# space-separated strings given after each RSA or EC -recip, since openssl applies -keyopt to the
# recipient before it.
decrypt_case() {
    CASE=$1; local recips=$2 as=$3 expect=$4 cipher=$5 rsa_opts=$6 ec_opts=$7
    logcase "$OP  $CASE"
    local r rargs=()
    for r in $recips; do
        rargs+=(-recip "$r.crt")
        # shellcheck disable=SC2206
        case $r in
            rsa*) rargs+=($rsa_opts) ;;
            p*) rargs+=($ec_opts) ;;
        esac
    done
    local err
    if ! err=$(ossl cms -encrypt -binary "-$cipher" -in "$MSG" -outform DER -out "$WORK/msg.der" "${rargs[@]}" 2>&1); then
        openssl_cannot "openssl cms -encrypt -$cipher ${rargs[*]}: $err"; return
    fi
    local b
    for b in $BACKENDS; do
        if ! key_args decrypt "$as" "$b"; then record "$b" n/a; continue; fi
        attempt "$b" "$expect" content_matches cms decrypt --in "$WORK/msg.der" --out "$CONTENT" ${KEY_ARGS[@]+"${KEY_ARGS[@]}"}
    done
}

oaep_keyopts() {
    case $1 in
        pkcs1v15) ;;
        oaep-sha1) echo "-keyopt rsa_padding_mode:oaep" ;;
        oaep-*) local h=${1#oaep-}; echo "-keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:$h -keyopt rsa_mgf1_md:$h" ;;
    esac
}

if wanted decrypt; then
    OP=decrypt
    echo "== decrypt (openssl encrypts, certval decrypts)"
    for k in $RSA_KEYS; do
        for kt in pkcs1v15 oaep-sha1 oaep-sha256 oaep-sha384 oaep-sha512; do
            decrypt_case "$k $kt aes-256-cbc" "$k" "$k" ok aes-256-cbc "$(oaep_keyopts $kt)" ""
        done
    done
    for c in aes-128-cbc aes-192-cbc aes-128-gcm aes-192-gcm aes-256-gcm; do
        decrypt_case "rsa2048 oaep-sha256 $c" rsa2048 rsa2048 ok "$c" "$(oaep_keyopts oaep-sha256)" ""
    done
    for k in $EC_KEYS; do
        for h in sha256 sha384 sha512; do
            for c in aes-128-cbc aes-256-gcm; do
                decrypt_case "$k ecdh-$h $c" "$k" "$k" ok "$c" "" "-keyopt ecdh_kdf_md:$h"
            done
        done
    done
    decrypt_case "p256 ecdh-sha1 (openssl's default) aes-256-cbc" p256 p256 refuse aes-256-cbc "" ""
    for k in $KEM_KEYS; do
        for c in aes-256-cbc aes-256-gcm; do
            decrypt_case "$k $c" "$k" "$k" ok "$c" "" ""
        done
    done
    multi="rsa2048 p256"; [ -z "$KEM_KEYS" ] || multi="$multi mlkem768"
    for k in $multi; do
        decrypt_case "to {$multi} as $k, aes-256-gcm" "$multi" "$k" ok aes-256-gcm \
            "$(oaep_keyopts oaep-sha256)" "-keyopt ecdh_kdf_md:sha256"
    done
fi

# ---- encrypt: certval encrypts, openssl decrypts

# encrypt_case CASE RECIPIENTS CERTVAL_ARGS...
encrypt_case() {
    CASE=$1; RECIPS=$2
    logcase "$OP  $CASE"
    shift 2
    local r rargs=() b
    for r in $RECIPS; do rargs+=(--recip "$PKI/$r.crt"); done
    for b in $BACKENDS; do
        attempt "$b" ok openssl_decrypts cms encrypt --in "$MSG" --out "$WORK/msg.der" "${rargs[@]}" "$@"
    done
}

if wanted encrypt; then
    OP=encrypt
    echo "== encrypt (certval encrypts, openssl decrypts)"
    for k in $RSA_KEYS; do
        for kt in pkcs1v15 oaep-sha1 oaep-sha256 oaep-sha384 oaep-sha512; do
            encrypt_case "$k $kt aes256-cbc" "$k" --key-transport "$kt" --content aes256-cbc
        done
    done
    for c in aes128-cbc aes192-cbc aes128-gcm aes192-gcm aes256-gcm; do
        encrypt_case "rsa2048 oaep-sha256 $c" rsa2048 --key-transport oaep-sha256 --content "$c"
    done
    for k in $EC_KEYS; do
        for h in sha256 sha384 sha512; do
            for c in aes128-cbc aes256-gcm; do
                encrypt_case "$k ecdh-$h aes256-wrap $c" "$k" --kdf "$h" --wrap aes256 --content "$c"
            done
        done
    done
    for w in aes128 aes192; do
        encrypt_case "p256 ecdh-sha256 $w-wrap aes256-cbc" p256 --kdf sha256 --wrap "$w" --content aes256-cbc
    done
    encrypt_case "p256 ecdh-sha256 with ukm aes256-cbc" p256 --kdf sha256 --ukm 00112233445566778899aabbccddeeff --content aes256-cbc
    for k in $KEM_KEYS; do
        for h in sha256 sha384 sha512; do
            encrypt_case "$k hkdf-$h aes256-wrap aes256-gcm" "$k" --kdf "$h" --wrap aes256 --content aes256-gcm
        done
        encrypt_case "$k hkdf-sha256 aes128-wrap aes128-cbc" "$k" --kdf sha256 --wrap aes128 --content aes128-cbc
    done
    [ -z "$KEM_KEYS" ] || encrypt_case "mlkem768 with ukm aes256-gcm" mlkem768 --ukm 00112233445566778899aabbccddeeff --content aes256-gcm
    multi="rsa2048 p256"; [ -z "$KEM_KEYS" ] || multi="$multi mlkem768"
    for c in aes256-cbc aes256-gcm; do
        encrypt_case "to {$multi} $c" "$multi" --content "$c"
    done
fi

# ---- sign: certval signs, openssl verifies

# sign_case CASE KEY CERTVAL_ARGS...; VERIFY_EXTRA holds openssl's extra verify arguments.
sign_case() {
    CASE=$1; local key=$2
    logcase "$OP  $CASE"
    shift 2
    local b
    for b in $BACKENDS; do
        if ! key_args sign "$key" "$b"; then record "$b" n/a; continue; fi
        attempt "$b" ok openssl_verifies cms sign --in "$MSG" --out "$WORK/signed" ${KEY_ARGS[@]+"${KEY_ARGS[@]}"} "$@"
    done
    VERIFY_EXTRA=()
}

if wanted sign; then
    OP=sign
    echo "== sign (certval signs, openssl verifies)"
    for k in $RSA_KEYS; do
        for d in sha256 sha384 sha512; do
            VERIFY_EXTRA=(-inform DER); sign_case "$k pkcs1v15 $d" "$k" --digest "$d"
            VERIFY_EXTRA=(-inform DER); sign_case "$k pss $d" "$k" --digest "$d" --pss
        done
    done
    for k in $EC_KEYS; do
        for d in sha256 sha384 sha512; do
            VERIFY_EXTRA=(-inform DER); sign_case "$k ecdsa $d" "$k" --digest "$d"
        done
    done
    for k in $DSA_KEYS; do
        VERIFY_EXTRA=(-inform DER); sign_case "$k sha512" "$k" --digest sha512
    done
    VERIFY_EXTRA=(-inform DER -content "$MSG"); sign_case "p256 detached" p256 --detached
    VERIFY_EXTRA=(-inform PEM); sign_case "p256 PEM" p256 --outform pem
    VERIFY_EXTRA=(-inform DER -certfile p256.crt); sign_case "p256 without the signer's certificate" p256 --include none
    VERIFY_EXTRA=(-inform DER); sign_case "p256 without ESSCertIDv2" p256 --no-ess-cert-id
fi

# ---- verify: openssl signs, certval verifies and validates

# verify_case CASE KEY CERTVAL_EXTRA OPENSSL_ARGS...; CERTVAL_EXTRA is a space-separated string.
verify_case() {
    CASE=$1; local key=$2 extra=$3
    logcase "$OP  $CASE"
    shift 3
    local err b
    if ! err=$(ossl cms -sign -binary -in "$MSG" -signer "$key.crt" -inkey "$key.key" -out "$WORK/signed" "$@" 2>&1); then
        openssl_cannot "openssl cms -sign $*: $err"; return
    fi
    for b in $BACKENDS; do
        # shellcheck disable=SC2086
        attempt "$b" ok certval_validates cms verify --in "$WORK/signed" --anchor "$PKI/ca.crt" --out "$CONTENT" $extra
    done
}

if wanted verify; then
    OP=verify
    echo "== verify (openssl signs, certval verifies and validates)"
    for k in $RSA_KEYS; do
        for d in sha256 sha384 sha512; do
            verify_case "$k pkcs1v15 $d" "$k" "" -nodetach -outform DER -md "$d"
            verify_case "$k pss $d" "$k" "" -nodetach -outform DER -md "$d" \
                -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:digest
        done
    done
    verify_case "rsa2048 pss sha256, maximal salt" rsa2048 "" -nodetach -outform DER -md sha256 \
        -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:max
    for k in $EC_KEYS; do
        for d in sha256 sha384 sha512; do
            verify_case "$k ecdsa $d" "$k" "" -nodetach -outform DER -md "$d"
        done
    done
    for k in $DSA_KEYS; do
        verify_case "$k sha512" "$k" "" -nodetach -outform DER -md sha512
    done
    verify_case "p256 detached" p256 "--content $MSG" -outform DER -md sha256
    verify_case "p256 without signed attributes" p256 "" -nodetach -outform DER -md sha256 -noattr
    verify_case "p256 PEM" p256 "" -nodetach -outform PEM -md sha256
fi

# ---- issue: certval ca issue, openssl verifies

# The digest each CA key signs with: the curve's own hash for ECDSA, which some implementations
# require, SHA-512 for ML-DSA (RFC 9882), SHA-256 otherwise.
ca_digest() {
    case $1 in
        p384) echo sha384 ;;
        p521|mldsa*) echo sha512 ;;
        *) echo sha256 ;;
    esac
}

ISSUER=
openssl_verifies_cert() {
    local out
    if ! out=$(ossl verify -CAfile ca.crt -untrusted "$ISSUER" "$WORK/issued.crt" 2>&1); then
        CHECK_MSG="openssl verify: $out"; return 1
    fi
}

# issue_case CASE CA_KEY CERTVAL_ARGS...
issue_case() {
    CASE=$1; local key=$2
    logcase "$OP  $CASE"
    shift 2
    ISSUER=ca-$key.crt
    local b
    for b in $BACKENDS; do
        if ! key_args ca "ca-$key" "$b"; then record "$b" n/a; continue; fi
        attempt "$b" ok openssl_verifies_cert ca issue --out "$WORK/issued.crt" --outform pem --days 1 \
            ${KEY_ARGS[@]+"${KEY_ARGS[@]}"} "$@"
    done
}

if wanted issue; then
    OP=issue
    echo "== issue (certval ca issue, openssl verifies)"
    for k in $CA_KEYS; do
        issue_case "ca-$k issues p256 $(ca_digest "$k")" "$k" --csr p256.csr --digest "$(ca_digest "$k")" \
            --key-usage digital-signature --eku email-protection --san-email p256@example.com
    done
    for k in $RSA_KEYS; do
        issue_case "ca-$k issues p256 pss sha256" "$k" --csr p256.csr --digest sha256 --pss
    done
    issue_case "ca-p256 issues a sub-CA" p256 --csr rsa2048.csr --ca --path-len 0
    [ -z "$KEM_KEYS" ] || issue_case "ca-p256 issues mlkem768 from its public key" p256 \
        --public-key mlkem768.pub --subject CN=mlkem768 --key-usage key-encipherment
fi

# ---- crl: certval ca crl, openssl verifies

CRL_SERIAL=0123456789ABCDEF
openssl_verifies_crl() {
    local out
    if ! out=$(ossl crl -inform DER -in "$WORK/ca.crl" -noout -verify -CAfile "$ISSUER" 2>&1); then
        CHECK_MSG="openssl crl -verify: $out"; return 1
    fi
    if ! out=$(ossl crl -inform DER -in "$WORK/ca.crl" -noout -text 2>&1) || ! contains "$out" "Serial Number: $CRL_SERIAL"; then
        CHECK_MSG="the CRL does not list $CRL_SERIAL"; return 1
    fi
}

if wanted crl; then
    OP=crl
    echo "== crl (certval ca crl, openssl verifies)"
    for k in $CA_KEYS; do
        CASE="ca-$k $(ca_digest "$k")"; ISSUER=ca-$k.crt
        logcase "$OP  $CASE"
        for b in $BACKENDS; do
            if ! key_args ca "ca-$k" "$b"; then record "$b" n/a; continue; fi
            attempt "$b" ok openssl_verifies_crl ca crl --out "$WORK/ca.crl" --crl-number 1 \
                --revoke "$CRL_SERIAL" --digest "$(ca_digest "$k")" ${KEY_ARGS[@]+"${KEY_ARGS[@]}"}
        done
    done
fi

# ---- ocsp: certval ca ocsp answers an openssl request, openssl verifies the response

openssl_verifies_ocsp() {
    local out
    # With -reqin and no -cert, openssl checks the response against the saved request, its nonce
    # included. The CA is an intermediate under ca.crt, which a delegated responder's certificate
    # chains through, so it is given with -verify_other.
    if ! out=$(ossl ocsp -reqin "$WORK/ocsp.req" -respin "$WORK/ocsp.resp" -CAfile ca.crt \
            -verify_other "$ISSUER" -resp_text 2>&1); then
        CHECK_MSG="openssl ocsp: $out"; return 1
    fi
    if ! contains "$out" 'Response verify OK'; then
        CHECK_MSG="openssl ocsp: $out"; return 1
    fi
    if ! contains "$out" 'Cert Status: revoked'; then
        CHECK_MSG="openssl ocsp: the status is not revoked: $out"; return 1
    fi
}

# ocsp_case CASE CA_KEY RESPONDER: RESPONDER is ca-KEY, or responder for the delegated one.
ocsp_case() {
    CASE=$1; local key=$2 responder=$3 err b
    ISSUER=ca-$key.crt
    logcase "$OP  $CASE"
    if ! err=$(ossl ocsp -issuer "ca-$key.crt" -serial "0x$CRL_SERIAL" -reqout "$WORK/ocsp.req" 2>&1); then
        openssl_cannot "openssl ocsp -reqout: $err"; return
    fi
    for b in $BACKENDS; do
        if [ "$responder" = responder ]; then
            [ "$b" != pkcs11 ] || { record "$b" n/a; continue; }
            KEY_ARGS=(--cert "$PKI/responder.crt" --key "$PKI/responder.key")
        elif ! key_args ca "ca-$key" "$b"; then
            record "$b" n/a; continue
        fi
        attempt "$b" ok openssl_verifies_ocsp ca ocsp --request "$WORK/ocsp.req" --issuer "ca-$key.crt" \
            --revoke "$CRL_SERIAL" --out "$WORK/ocsp.resp" --digest "$(ca_digest "$key")" \
            ${KEY_ARGS[@]+"${KEY_ARGS[@]}"}
    done
}

if wanted ocsp; then
    OP=ocsp
    echo "== ocsp (certval ca ocsp answers, openssl verifies)"
    for k in $CA_KEYS; do
        ocsp_case "ca-$k $(ca_digest "$k")" "$k" "ca-$k"
    done
    ocsp_case "delegated responder of ca-p256" p256 responder
fi

# ---- req: certval req signs a request or a self-signed certificate, openssl verifies

openssl_verifies_request() {
    local out
    if ! out=$(ossl req -in "$WORK/req.csr" -noout -verify 2>&1); then
        CHECK_MSG="openssl req -verify: $out"; return 1
    fi
}
openssl_verifies_self_signed() {
    local out
    if ! out=$(ossl verify -CAfile "$WORK/self.crt" "$WORK/self.crt" 2>&1); then
        CHECK_MSG="openssl verify: $out"; return 1
    fi
}

# req_case CASE KEY CHECK OUT CERTVAL_ARGS...: req with KEY's PKCS #8 file, writing OUT.
req_case() {
    CASE=$1; local key=$2 check=$3 out=$4 b
    logcase "$OP  $CASE"
    shift 4
    for b in $BACKENDS; do
        # req takes a key file into the implementation; a token's keys are not files.
        if [ "$b" = pkcs11 ]; then record "$b" n/a; continue; fi
        attempt "$b" ok "$check" req --key "$PKI/$key.key" --subject "CN=certval req $key" \
            --out "$WORK/$out" --outform pem "$@"
    done
}

if wanted req; then
    OP=req
    echo "== req (certval req signs, openssl verifies)"
    for k in $CA_KEYS; do
        d=$(ca_digest "$k")
        req_case "$k request $d" "$k" openssl_verifies_request req.csr --digest "$d" \
            --san-email "$k@example.com"
        req_case "$k self-signed $d" "$k" openssl_verifies_self_signed self.crt --digest "$d" \
            --x509 --ca --days 1
    done
    for k in $RSA_KEYS; do
        req_case "$k request pss sha256" "$k" openssl_verifies_request req.csr --digest sha256 --pss
    done
fi

# ---- the matrix

{
    echo "certval: $CERTVAL"
    echo "openssl: $OPENSSL ($("$OPENSSL" version))"
    echo "choices: $BACKENDS"
    [ "$PQ_SIG" = 1 ] || echo "left out: ML-DSA (openssl $version is older than 3.5)"
    [ "$PQ_KEM" = 1 ] || echo "left out: ML-KEM (openssl $version is older than 3.6)"
    echo
    awk -F '\t' -v backends="$BACKENDS" '
        BEGIN { nb = split(backends, b, " "); w = 52 }
        {
            row = $1 "  " $2
            if (!(row in seen)) { seen[row] = 1; rows[++nr] = row; if (length(row) > w) w = length(row) }
            cell[row, $3] = $4
            count[$4]++
        }
        END {
            printf "%-" w "s", ""
            for (i = 1; i <= nb; i++) printf "  %-18s", b[i]
            printf "\n"
            for (r = 1; r <= nr; r++) {
                printf "%-" w "s", rows[r]
                for (i = 1; i <= nb; i++) printf "  %-18s", ((rows[r], b[i]) in cell ? cell[rows[r], b[i]] : "-")
                printf "\n"
            }
            printf "\ncells:"
            for (o in count) printf "  %s %d", o, count[o]
            printf "\n"
        }' "$RESULTS"
} > "$WORK/summary.txt"

cat "$WORK/summary.txt"
echo
echo "results: $WORK/summary.txt, $RESULTS; explanations: $REPORT"
if grep -qE $'\t(FAIL|DIFFER|OSSL)$' "$RESULTS"; then exit 1; fi
exit 0
