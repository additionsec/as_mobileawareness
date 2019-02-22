import struct
import urlparse
import cStringIO as StringIO
import base64

PRODUCT_ASMA = 1
PLAT_IOS = (1<<1)
PLAT_ANDROID = (1<<2)


TAG_MINVER = 1
TAG_ORG = 2
TAG_FLAGS = 3
TAG_GENTS = 4
TAG_LIC = 5
TAG_MSGURL = 6
TAG_PINS = 7
TAG_SCB = 8
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

def add_license( conf, prod, platforms, wid, pkg ):
	flags = 0
	if len(pkg) > 255 or pkg=='': raise Exception('bad pkg')
	if prod > 255 or prod == 0: raise Exception('bad prod')
	if platforms > 0xffff or platforms == 0: raise Exception('bad platforms')
	if pkg == '.' and wid == 0: raise Exception('bad wid')
	lic = struct.pack("BBHIIB", prod, flags, platforms, 0xffffffff, wid, len(pkg)) + pkg
	add_tag(conf, TAG_LIC, lic)

def add_msg( conf, url ):
	u = urlparse.urlsplit(url)

	if u.scheme == 'http': port = 80
	elif u.scheme == 'https': port = 443
	else: raise Exception("bad scheme")

	hn = u.hostname + chr(0)
	if u.port: port = u.port
	p = u.path + chr(0)

	flags = len(hn)
	if u.scheme == 'https': flags |= 0x8000
	blob = struct.pack("HH", port, flags) + hn + p 
	add_tag(conf, TAG_MSGURL, blob)

def add_pin( conf, pin, hostname ):
	if len(pin) != 32: raise Exception("bad pin length")
	add_tag(conf, TAG_PINS, pin + hostname + "\x00")

def gen_config():
	conf = StringIO.StringIO()

	# Header
	conf.write( struct.pack("I", 0x017f5201) )

	# Signature (empty for now)
	sig = chr(0) * (64 + 256 + 64)
	conf.write( sig )

	# Magic2
	conf.write( struct.pack("I", 0x7f5201) )

	# Config values from here

	add_tag(conf, TAG_MINVER, struct.pack("I", 1))

	org = chr(0xee) * 32
	add_tag(conf, TAG_ORG, org)

	flags = 0x82 # 2:ProEdition 80:FDC
	add_tag(conf, TAG_FLAGS, struct.pack("I", flags))

	add_tag(conf, TAG_GENTS, struct.pack("I", 0))

	add_license( conf, PRODUCT_ASMA, PLAT_IOS|PLAT_ANDROID, 1, '.' )

	#add_msg( conf, "https://api.additionsecurity.com/asma/1/msg" )

	return conf.getvalue()


if __name__ == "__main__":
	with open('/tmp/test.conf', 'w') as f:
		f.write( gen_config() )
