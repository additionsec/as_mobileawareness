
$c=1;

%NAMED = ();

%EXEMPT = (
	'AS_JNI_OnLoad'=>1,
	'AS_Initialize'=>1,
	'AS_Initialize_Unity'=>1,
	'AS_Register_Identity'=>1,
	'AS_Send_Message'=>1,
	'AS_Heartbeat'=>1,
	'AS_Login_Status'=>1,
	'AS_Network_Reachability'=>1,
	'AS_Version'=>1,
	'AS_SHA256'=>1,
	'AS_UUID_Default_Serial'=>1
);

%REQUIRE = (
	'ppoll_tfs'=>1,
	'ftruncate_tfs'=>1
);


while(<>){
	tr/\r\n//d;

	if( m/^[\da-fA-f]+ ([a-zA-Z]) (.+)$/ ){
		next if($1 eq 'U');
		$nom = $2;
		next if( $nom =~ m/^\./ );
		next if( defined $EXEMPT{$nom});
	} else {
		next;
	}

	if( defined $NAMED{$nom} ){
		print STDERR "Dupe: $nom\n";
		next;
	}

	$NAMED{$nom}++;
	print $nom, " .Lx." . $c . "\n";
	$c++;
}

foreach (keys %REQUIRE) {
	$nom = $_;
	next if(defined $NAMED{$nom});
	$NAMED{$nom}++;
	print $nom, " .Lx." . $c . "\n";
	$c++;
}
