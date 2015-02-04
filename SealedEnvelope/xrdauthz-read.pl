#!/usr/bin/perl
sub usage() {
    print STDERR "xrdauthz-read.pl <host:port> <lfn> <pfn> <localfile>\n";
    exit(-1);
}

my $rndfile = "/tmp/authztest.";
$rndfile .= rand() . "." . rand();

my $hostport=(shift or usage());
my $lfn=(shift or "/dummy");
my $pfn=(shift or "/tmp/testfile");
my $localfile =(shfit or "/tmp/xrdauthz-rtest");

system("./authzwrite.pl $lfn $pfn >> $rndfile");
system("cat $rndfile");

my $envelope = `./encode $rndfile`;
chomp $envelope;
print "Doing:\nxrdcp root://$hostport/$lfn $localfile -OS\\\&authz=\"$envelope\"\n";
system("xrdcp root://$hostport/$lfn $localfile -OS=\\\&authz=\"$envelope\"");
unlink $rndfile;

