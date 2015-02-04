#!/usr/bin/perl


# run the performance test and create the keys
system("make test");
# install the keys:
system("mkdir -p $ENV{HOME}/.authz/xrootd; cp key.pem $ENV{HOME}/.authz/xrootd/key.pem; cp pkey.pem $ENV{HOME}/.authz/xrootd/pkey.pem");
# install the TkAuthz file for xrootd

open OUT ,"> $ENV{HOME}/.authz/xrootd/TkAuthz.Authorization";
print OUT<<EOF
KEY VO:*            PRIVKEY:$ENV{HOME}/.authz/xrootd/key.pem  PUBKEY:$ENV{HOME}/.authz/xrootd/pkey.pem
EXPORT PATH:/tmp    VO:*                   ACCESS:ALLOW    CERT:*
RULE PATH:/tmp/ AUTHZ:read|write|delete|write-once|read-write NOAUTHZ:| VO:* CERT:*
EOF
;
