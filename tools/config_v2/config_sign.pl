#!/usr/bin/perl

$KEYSDIR='';
$SIGN='';

$KEYNOM = shift;
$INF = shift;
$OUTF = shift;

$SET = $KEYSDIR . "set_" . $KEYNOM . ".conf";
$ECC = $KEYSDIR . "ecc_" . $KEYNOM . ".key.raw";
$RSA = $KEYSDIR . "rsa_" . $KEYNOM . ".key.der";

die("missing input file") if(!-e $INF);
die("missing key set") if(!-e $SET);
die("missing ecc key") if(!-e $ECC);
die("missing rsa key") if(!-e $RSA);

system("$SIGN $ECC $RSA $INF");

open(IN, '<', $SET) or die("can't open key set");
$/ = undef;
$data = <IN>;
close(IN);

open(OUT, '>', $OUTF) or die("can't open output file");
binmode(OUT);
print OUT pack("I", 0x0fadd5ec);
print OUT pack("I", length($data));
print OUT $data;

open(IN, '<', $INF) or die("can't open input file");
$/ = undef;
$data = <IN>;
close(IN);

print OUT $data;
close(OUT);
