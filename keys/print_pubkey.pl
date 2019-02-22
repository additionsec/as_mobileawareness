
$f = shift;
open(IN,'<',$f) || die("open $f");
$k = <IN>;
chomp($k);
close(IN);

print '{';

while( $k =~ m/([a-f0-9]{2})/g ){
	print '0x',$1,',';
}
print "}\n";

