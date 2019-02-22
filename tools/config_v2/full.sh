
KEYDIR=
SIGN=

# gen the set w/ online keys (signed by root keys)
python config_keys_gen.py ${KEYDIR}/ecc_online_1.pub.raw ${KEYDIR}/rsa_online_1.pub.der

# Move it over
mv /tmp/test_keys.conf ${KEYDIR}/set_online_1.conf

# sign it
${SIGN} ${KEYDIR}/ecc_offline_1.key.raw ${KEYDIR}/rsa_offline_1.key.der ${KEYDIR}/set_online_1.conf

# generate a config
python config_gen.py

# create a fully signed config
perl config_sign.pl online_1 /tmp/test.conf test/configs/ft.conf
