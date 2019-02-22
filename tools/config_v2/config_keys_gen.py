import sys
import base64
import struct
import urlparse
import cStringIO as StringIO

TAG_PINS = 7
TAG_SET_FLAGS = 9
TAG_KEY_ECC = 128
TAG_KEY_RSA = 129

def add_tag(conf, t, v):
	conf.write(chr(t))
	l = len(v)
	if l > 0x7f:
		u = (l >> 8)
		if u > 0x7f: raise Exception("value too big")
		u |= 0x80
		conf.write(chr(u))
		conf.write(chr(l&0xff))
	else:
		conf.write(chr(l))
	conf.write(v)

def add_pin( conf, pin, hostname ):
	if len(pin) != 32: raise Exception("bad pin length")
	add_tag(conf, TAG_PINS, pin + hostname + "\x00")

def gen_config_keys():
	conf = StringIO.StringIO()

	# Header
	conf.write( struct.pack("I", 0x017f5201) )

	# Signature (empty)
	sig = chr(0) * (64 + 256 + 64)
	conf.write( sig )

	# Magic2
	conf.write( struct.pack("I", 0x7f5201) )

	# Various status flags (must occur before keys)
	flags = 1  # 1=NonprodKeys
	add_tag(conf, TAG_SET_FLAGS, struct.pack("I", flags))

	# The public keys
	for fnom in sys.argv[1:]:
		with open(fnom, "r") as f:
			pubkey = f.read()
		if "ecc_" in fnom:
			print "- Adding ECC key %s" % fnom
			add_tag(conf, TAG_KEY_ECC, pubkey)
		elif "rsa_" in fnom:
			print "- Adding RSA key %s" % fnom
			add_tag(conf, TAG_KEY_RSA, pubkey)
		else:
			raise Exception("bad key file type")

	return conf.getvalue()


if __name__ == "__main__":
	with open('/tmp/test_keys.conf', 'w') as f:
		f.write( gen_config_keys() )
