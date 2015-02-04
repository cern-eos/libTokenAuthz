#!/usr/bin/perl
my $ticket;

sub usage() {
    print STDERR "authzwrite.pl: <lfn> <turl> [<access>]\n";
    exit(-1);
}

my $lfn = (shift or usage());
my $turl  = (shift or usage());
my $access = (shift or "read");

$ticket .= "<authz>\n";
$ticket .= "  <file>\n";	
$ticket .= "    <lfn>$lfn</lfn>\n";
$ticket .= "    <access>$access</access>\n";
$ticket .= "    <turl>$turl</turl>\n";
$ticket .= "  </file>\n";	
$ticket .= "</authz>\n";
print $ticket;
