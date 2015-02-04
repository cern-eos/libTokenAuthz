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

  gettimeofday (&abs_start_time, &tz);

  TSealedEnvelope* decoder = GetEnvelope("key.pem","pkey.pem","Blowfish","Andreas.Joachim.Peters",0,0);
  if (!decoder) {
    exit(-99);
  }

#ifdef WITHTHREADS
  decoder->UnLock();
#endif

  if (!decoder->Initialize(TSE_DECODE)) {
    exit(-1);
  }
  float decodingtime=0;

  if (! argv[1]) {
    fprintf(stderr,"Usage: encode <filename>\n");
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
  std::string env = buffer;

  gettimeofday (&abs_start1_time, &tz);
  decoder = GetEnvelope("key.pem","pkey.pem","Blowfish","Andreas.Joachim.Peters",0,0);
  std::string unenv = decoder->decodeEnvelope(env);

  gettimeofday (&abs_start2_time, &tz);

  float abs_time1=((float)((abs_start2_time.tv_sec - abs_start1_time.tv_sec) *1000000 +
			   (abs_start2_time.tv_usec - abs_start1_time.tv_usec)))/1000.0;
  
  std::cout << unenv << std::endl;
  close(fin);
}
