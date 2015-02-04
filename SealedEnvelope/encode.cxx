#include "TSealedEnvelope.h"
#include <iostream>
#include <sstream>
#include <netinet/in.h>
#include <unistd.h>
#include <zlib.h>
#include "spc_b64.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <sys/time.h>

int main(int argc, char* argv[]) {
  struct timeval abs_start_time;
  struct timeval abs_start1_time;
  struct timeval abs_start2_time;
  struct timezone tz;
  int fin;

  if (! argv[1]) {
    fprintf(stderr,"Usage: encode <filename> [<lifetime> [<certificate>]]\n");
    exit(-1);
  }

  if ( (fin = open(argv[1],O_RDONLY))<0) {
    fprintf(stderr,"Error: cannot open %s\n",argv[1]);
    exit(-1);
  }
  
  char buffer[16384];

  if ( (read(fin, buffer,16384)) <= 0) {
    fprintf(stderr,"Error: cannot read %s\n",argv[1]);
    exit(-1);
  }

  std::string encode;

  encode = buffer;

  gettimeofday (&abs_start_time, &tz);

  int cnt=0;
  TSealedEnvelope* sealed = new TSealedEnvelope("key.pem","pkey.pem","key.pem","pkey.pem","Blowfish","Andreas.Joachim.Peters",0);
  if (!sealed->Initialize(TSE_CODEC)) {
    exit(-1);
  }

  float encodingtime=0;
  
  gettimeofday (&abs_start1_time, &tz);

  unsigned int lifetime;
  std::string certificate;
  if (argv[2]) {
    lifetime = atoi(argv[2]);
    if (argv[3]) {
      certificate=argv[3];
    }
  }

  sealed->Trace(1);
  std::string env = sealed->encodeEnvelope(encode,lifetime,certificate);
  gettimeofday (&abs_start2_time, &tz);
  
  float abs_time1=((float)((abs_start2_time.tv_sec - abs_start1_time.tv_sec) *1000000 +
			    (abs_start2_time.tv_usec - abs_start1_time.tv_usec)))/1000.0;
  encodingtime+=abs_time1;
  sealed->Reset();
  std::cout << env << std::endl;
  close(fin);
}

