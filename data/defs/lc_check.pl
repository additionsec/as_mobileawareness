
while(<>){
	@p = split(/\t/, $_);
	print $p[2]."\n" if( $p[2] =~ m/[A-Z]/);
}
