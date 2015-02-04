#include "TTokenAuthz.h"

int main(int argc, char* argv[]) {
  printf("Creating Keys ....\n");
  system("/usr/bin/openssl genrsa -rand 12938467 -out key.pem 1024");
  system("/usr/bin/openssl req -new -inform PEM -key key.pem -outform PEM -out certreq.pem");
  system("/usr/bin/openssl x509 -days 3650 -signkey key.pem -in certreq.pem -req -out cert.pem");
  system("/usr/bin/openssl x509 -pubkey -in cert.pem > pkey.pem");

  TTokenAuthz* authz= TTokenAuthz::GetTokenAuthz("xrootd",true);
  printf("Access %d to path /tmp/ for ALICE\n", authz->PathIsExported("/tmp/alice/test","ALICE"));
  printf("Access %d to path /tmp/ for ALICE\n", authz->PathIsExported("/tmp/cms/test","ALICE"));
  printf("Access %d to path /tmp/ for *\n", authz->PathIsExported("/tmp/cms/test/","*"));
  printf("Access %d to path /tmp/ for *\n", authz->PathIsExported("/castor/cern.ch/user","*"));
  printf("Path /tmp/ needs authorization %d for read from ALICE\n", authz->PathHasAuthz("/tmp/","read","ALICE"));
  printf("Path /tmp/ needs authorization %d for write from ALICE\n", authz->PathHasAuthz("/tmp/","write","ALICE"));
  printf("Path /castor/ needs authorization %d for read from *\n", authz->PathHasAuthz("/castor/","read","*"));
  TAuthzXMLreader* axmlr = 0;
  float t1;
  float t2;
  int result;
  printf("TTokenAuthz::GetAuthz for /tmp/ returned %d  in %f/%f ms\n",(result=authz->GetAuthz("/tmp","&authz=alien&vo=ALICE",&axmlr,1,&t1,&t2)),t1,t2);
  printf("TTokenAuthz::GetAuthz: unable to %s for file /tmp [posixerror=%d]\n",authz->ErrorMsg(result),authz->PosixError(result));
  printf("TTokenAuthz::GetAuthz for /tmp/ returned %d  in %f/%f ms\n",(result=authz->GetAuthz("/tmp","&authz=sldkfjslkdjflskdjf&vo=ALICE",&axmlr,1,&t1,&t2)),t1,t2);
  printf("TTokenAuthz::GetAuthz: unable to %s for file /tmp [posixerror=%d]\n",authz->ErrorMsg(result),authz->PosixError(result));
}
