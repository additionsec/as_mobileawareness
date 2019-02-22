#/usr/bin/perl

$MIX = 0x52add5ec;
$MIXSTR = sprintf("0x%x", $MIX);

$MASK = 0x5f75f75f;
$MASKSTR = sprintf("0x%x", $MASK);

while(<DATA>){
	tr/\r\n//d;

	$dat = $_;
	$orig = $dat;

	$varnom = uc($orig);
	$varnom =~ tr/A-Z0-9_//cd;

	# convert \r\n
	$dat =~ s/\\r/\r/g;
	$dat =~ s/\\n/\n/g;

	# add NULL
	$dat .= "\x00";

	# now pad to 4 byte boundary
	if( (length($dat) % 4) != 0 ){
		$dat .= "\x00" x (4 - (length($dat) % 4));
	}

	@v = unpack("V*", $dat);
	for( $i = 0; $i < ~~@v; $i++ ){
		if( $i == 0 ){
			$v[$i] ^= $MIX;
		} else {
			$mask = $i << 26 | $i << 18 | $i << 10 | $i;
			$v[$i] ^= $v[$i-1] ^ $MASK ^ $mask;
		}
	}

	print "static const uint32_t ", $varnom, "[] = {";
	foreach (@v){
		print sprintf("0x%x,", $_);
	}
	print "}; // \"$orig\"\n";
}

print <<EOT;

#define _STR_START      $MIXSTR
#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)

__attribute__ ((optnone,noinline))
static char *_decode( uint32_t sz, const uint32_t *in, uint32_t *work ){
        //ASSERT( sz <= WORK_MAX );
#pragma nounroll
        while( sz > 0 ){
                volatile uint32_t mask = sz << 26 | sz << 18 | sz << 10 | sz;
                work[sz] = in[sz] ^ in[sz-1] ^ $MASKSTR ^ mask;
                sz--;
        }
        work[0] = in[0] ^ _STR_START;
        return (char*)work;
}

EOT


__DATA__
UIDevice
currentDevice
identifierForVendor
