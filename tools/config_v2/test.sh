#!/bin/sh

KEYSDIR=
SIGN=
VERIFY=

python config_gen.py

echo === SIGNING ===
${SIGN} ${KEYSDIR}/ecc_online_1.key.raw ${KEYSDIR}/rsa_online_1.key.der /tmp/test.conf

echo === VERIFYING ===
${VERIFY} ${KEYSDIR}/ecc_online_1.pub.raw ${KEYSDIR}/rsa_online_1.pub.der /tmp/test.conf
