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
#include "stdint.h"
#include <sys/time.h>
#include <curl/curl.h>
#include <atomic>

#ifdef WITHTHREADS
pthread_mutex_t lock;
#endif

static std::map<std::string , TSealedEnvelope*> sEnvelope;
static bool mutexinit=false;

TSealedEnvelope* GetEnvelope(const char* localprivatekey, const char* remotepublickey, const char* cipher,const char* creator, int compress, const char* vo) {
  const char* lvo;
  if (!vo) {
    lvo = "__no_vo__";
  } else {
    lvo = vo;
  }

  if (sEnvelope[lvo]) {
#ifdef WITHTHREADS
    sEnvelope[lvo]->Lock();
#endif
    sEnvelope[lvo]->Reset();
    return sEnvelope[lvo];
  } else {
#ifdef WITHTHREADS
    if (!mutexinit) {
      mutexinit=true;
      pthread_mutex_init(&lock,NULL);
    }
    pthread_mutex_lock(&lock);
#endif
    TSealedEnvelope* env = new TSealedEnvelope("",remotepublickey,localprivatekey,"",cipher,creator,compress);

#ifdef WITHTHREADS
    env->Lock();
    pthread_mutex_unlock(&lock);
#endif

    sEnvelope[lvo] = env;

    if (!sEnvelope[lvo]->IsInitialized()) {
      if (!sEnvelope[lvo]->Initialize(TSE_DECODE)) {
	delete sEnvelope[lvo];
	sEnvelope.erase(lvo);
	return 0;
      } 
    }
    sEnvelope[lvo]->Reset();
    return sEnvelope[lvo];
  }
}


#ifdef __MAIN__
int main() {
  struct timeval abs_start_time;
  struct timeval abs_start1_time;
  struct timeval abs_start2_time;
  struct timeval abs_start3_time;
  struct timezone tz;
  
  gettimeofday (&abs_start_time, &tz);

#ifdef WITHTHREADS
  printf("Starting ...\n");
  pthread_mutex_init(&lock,NULL);
  pthread_mutex_unlock(&lock);
  printf("Mutex done \n");
#endif

  int32_t cnt=0;
  TSealedEnvelope* sealed = new TSealedEnvelope("key.pem","pkey.pem","key.pem","pkey.pem","Blowfish","Andreas.Joachim.Peters",0);
  TSealedEnvelope* decoder = GetEnvelope("key.pem","pkey.pem","Blowfish","Andreas.Joachim.Peters",0,0);
  if (!sealed->Initialize(TSE_CODEC)) {
    exit(-1);
  }

  if (!decoder->Initialize(TSE_DECODE)) {
    exit(-1);
  }

  //  decoder->Verbose(1);
  //  sealed->Verbose(1);
  float encodingtime=0;
  float decodingtime=0;

#ifdef WITHTHREADS
  decoder->UnLock();
#endif

  while (1) {   
#ifdef WITHTHREADS
    sealed->Lock();
#endif
    gettimeofday (&abs_start1_time, &tz);
    cnt++;
    std::string env = sealed->encodeEnvelope(std::string("Das ist ein neuer Test"),0,std::string("none"));
    //    std::cout  << env;
    gettimeofday (&abs_start2_time, &tz);
    decoder = GetEnvelope("key.pem","pkey.pem","Blowfish","Andreas.Joachim.Peters",0,0);
    std::string unenv = decoder->decodeEnvelope(env);

    gettimeofday (&abs_start3_time, &tz);

    float abs_time1=((float)((abs_start2_time.tv_sec - abs_start1_time.tv_sec) *1000000 +
			    (abs_start2_time.tv_usec - abs_start1_time.tv_usec)))/1000.0;
    float abs_time2=((float)((abs_start3_time.tv_sec - abs_start2_time.tv_sec) *1000000 +
			    (abs_start3_time.tv_usec - abs_start2_time.tv_usec)))/1000.0;

    float totaltime=((float)((abs_start3_time.tv_sec - abs_start_time.tv_sec) *1000000 +
			    (abs_start3_time.tv_usec - abs_start_time.tv_usec)))/1000.0;

    encodingtime+=abs_time1;
    decodingtime+=abs_time2;

    //    std::cout << unenv;
    if (!(cnt%500)) {
      decoder->PrintHeader();
      printf("Performance: Codings: %.02f encodings/s\n",1000*cnt/encodingtime);
      printf("Performance: Codings: %.02f decodings/s\n",1000*cnt/decodingtime);
      printf("Performance: Overall  %.02f en-decodings/s\n",1000*cnt/totaltime);

    }
    if (cnt==1000)
      exit(0);
    if (!(cnt%10000)) {
      usleep(5000000);
    }
    sealed->Reset();
    decoder->Reset();
#ifdef WITHTHREADS
    sealed->UnLock();
    decoder->UnLock();
#endif
    //usleep(10000);
  }
}
#endif


bool
TSealedEnvelope::Initialize(int codingtype) {
#ifdef WITHTHREADS
  pthread_mutex_lock(&lock);
#endif
  fCodingType = codingtype;
  if ( (codingtype == TSE_ENCODE) || (codingtype == TSE_CODEC) ) {
    fEVP_LocalPrivateKey = ReadPrivateKey(fLocalPrivateKey.c_str());
    if (!fEVP_LocalPrivateKey) {
      fprintf(stderr,"SealedEnvelope::Initialize: Cannot read local private key %s\n",fLocalPrivateKey.c_str());
#ifdef WITHTHREADS
      pthread_mutex_unlock(&lock);
#endif
      return 0;
    }

    fEVP_RemotePublicKey = ReadPublicKey(fRemotePublicKey.c_str());
    if (!fEVP_RemotePublicKey) {
      fprintf(stderr,"SealedEnvelope::Initialize: Cannot read remote public key %s\n",fRemotePublicKey.c_str());
#ifdef WITHTHREADS
      pthread_mutex_unlock(&lock);
#endif
      return 0;
    }

    fEVP_RemotePublicKeySize = RSA_size(fEVP_RemotePublicKey->pkey.rsa);
    fEVP_LocalPrivateKeySize = RSA_size(fEVP_LocalPrivateKey->pkey.rsa);
  } else {
    fEVP_LocalPrivateKey = 0;
    fEVP_RemotePublicKey = 0;
  }

  

  if ( (codingtype == TSE_DECODE) || (codingtype == TSE_CODEC) ) {
    fEVP_LocalPublicKey  = ReadPublicKey(fLocalPublicKey.c_str());
    if (!fEVP_LocalPublicKey) {
      fprintf(stderr,"SealedEnvelope::Initialize: Cannot read local public key %s\n",fLocalPublicKey.c_str());
#ifdef WITHTHREADS
      pthread_mutex_unlock(&lock);
#endif
      return 0;
    }

    fEVP_RemotePrivateKey = ReadPrivateKey(fRemotePrivateKey.c_str());
    if (!fEVP_RemotePrivateKey) {
      fprintf(stderr,"SealedEnvelope::Initialize: Cannot read remote private key %s\n",fRemotePrivateKey.c_str());
#ifdef WITHTHREADS
      pthread_mutex_unlock(&lock);
#endif
      return 0;
    }

    fEVP_RemotePrivateKeySize = RSA_size(fEVP_RemotePrivateKey->pkey.rsa);
    fEVP_LocalPublicKeySize = RSA_size(fEVP_LocalPublicKey->pkey.rsa);
    
  } else {
    fEVP_LocalPublicKey   = 0;
    fEVP_RemotePrivateKey = 0;
  }

#ifdef WITHTHREADS
  pthread_mutex_unlock(&lock);
#endif
  // initialize the random number generator
  int32_t randomfd=open("/dev/urandom",O_RDONLY);
  if (randomfd<0) {
    fprintf(stderr,"SealedEnvelope::Initialize: Error opening /dev/urandom device\n");
    return 0;
  }
  
  int32_t rnd=0;
  if (!(read(randomfd,&rnd,4))) {
    if (randomfd) {
      close(randomfd);
    }
    fprintf(stderr,"SealedEnvelope::Initialize: Error initializing the random number generator\n");
    return 0;
  }
  
  close(randomfd);
  srand((uint32_t)rnd);
  fInitialized=1;
  return 1;
}

EVP_PKEY*
TSealedEnvelope::ReadPublicKey(const char* certfile) {
  FILE *fp = fopen (certfile, "r");
  X509 *x509;
  EVP_PKEY *pkey;

  if (!fp) {
     return NULL;
  }

  x509 = PEM_read_X509(fp, NULL, 0, NULL);

  if (x509 == NULL)
  {
     ERR_print_errors_fp (stderr);
     return NULL;
  }

  fclose (fp);

  pkey=X509_extract_key(x509);

  X509_free(x509);

  if (pkey == NULL)
     ERR_print_errors_fp (stderr);
  
  return pkey;

}

EVP_PKEY*
TSealedEnvelope::ReadPrivateKey(const char* keyfile) {
  FILE *fp = fopen(keyfile, "r");
  EVP_PKEY *pkey;
  
  if (!fp) {
    return NULL;
  }
  
  pkey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
  
  fclose (fp);
  
  if (pkey == NULL)
    ERR_print_errors_fp (stderr);
  
  return pkey;
}

std::string 
TSealedEnvelope::encodeEnvelope(std::string envelopein, int lifetime,std::string certificate ) {

  if ((fCodingType<0) || (fCodingType == TSE_DECODE)) {
    fprintf(stderr,"TSealedEnvelope::encodeEnvelope: you have to initialize as an encoder [%d]!\n",fCodingType);
    return "";
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  if (fVerbose) {
    std::cerr << "TSealedEnvelope::encodeEnvelope:" << std::endl;
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "=> envelope :" << std::endl;
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << envelopein << std::endl;
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "=> liftime : " << lifetime << std::endl;
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "=> certificate : " << certificate << std::endl;
  }
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  char cbuffer[4096];
  time_t lNow = time(NULL);
  sprintf(cbuffer,"%u",(int32_t)lNow);
  std::string sNow = std::string(cbuffer);
  std::string lDate = ctime(&lNow);
  std::string lExpDate = "never";
  time_t lExpires=0;

  if (lifetime) {
    lExpires = lNow + lifetime;
    lExpDate = ctime(&lExpires);
  } else {
    lExpires = 0;
  }
  sprintf(cbuffer,"%u",(int32_t)lExpires);
  std::string sExpires = std::string(cbuffer);
  /////////////////////////////////////////////////////////////////////
  // create an UUID
  
  fUUID="";
  int32_t i;
  //  for (i=0; i < 116; i++) {
  for (i=0; i < 16; i++) {
    char c = 1+(int32_t) (255.0*rand()/(RAND_MAX+1.0));
    fUUID+= c;
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  if (fVerbose) {
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "The symmetric CIPHER is " << fUUID.c_str() << std::endl;
  }
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  std::string lEnvelope;
  lEnvelope = "";
  lEnvelope += std::string("-----BEGIN ENVELOPE-----\n");
  lEnvelope += (std::string("CREATOR:     ") + fCreator + std::string("\n"));
  //  lEnvelope += (std::string("MD5:         ") + fMD5SUM + std::string("\n"));
  lEnvelope += std::string("UNIXTIME:    ") + sNow + std::string("\n");
  lEnvelope += std::string("DATE:        ") + lDate ;
  lEnvelope += std::string("EXPIRES:     ") + sExpires + std::string("\n");
  lEnvelope += std::string("EXPDATE:     ") + lExpDate + std::string("\n");
  lEnvelope += std::string("CERTIFICATE: ") + certificate + std::string("\n");
  lEnvelope += std::string("-----BEGIN ENVELOPE BODY-----\n");
  lEnvelope += envelopein+std::string("\n");
  lEnvelope += std::string("-----END ENVELOPE BODY-----\n");
  lEnvelope += std::string("-----END ENVELOPE-----\n");

  if (fTrace) {
    std::cerr << "Raw Envelope:" << std::endl;
    std::cerr << "***************************************************************************" << std::endl;
    std::cerr << lEnvelope << std::endl;
    std::cerr << "***************************************************************************" << std::endl;
  }

  // set the class variables
  fUnixTime = std::string(sNow);
  fExpires  = std::string(sExpires);
  fExpDate  = lExpDate;
  fCertificate = certificate;

  if (fCompress) {
    Bytef *dest = (Bytef*)codebuffer;
    uLongf dest_len = CODEBUFFERSIZE;
    if (!dest) {
      fprintf(stderr,"TSealedEnvelope::encodeEnvelope: cannot create compression buffer!\n");
      return "";
    }
    
    uint32_t lEnvelopeLength = lEnvelope.length()+1;
    
    if ( (compress2(dest, &dest_len, (const Bytef*) lEnvelope.c_str(),lEnvelopeLength ,0)) != Z_OK) {
      fprintf(stderr,"TSealedEnvelope::encodeEnvelope: cannot compress the envelope!\n");
      return "";
    }

    uint_fast8_t* base64encoded = spc_base64b_encode( dest, (size_t)dest_len, 1);

    lEnvelope = "";
    lEnvelope += std::string("-----BEGIN GZIP ENVELOPE-----\n");
    lEnvelope += std::string((char*)base64encoded);
    lEnvelope += std::string("\n");
    lEnvelope += std::string("-----END GZIP ENVELOPE-----\n");
    //    std::cerr << lEnvelope << std::endl;
    uint32_t lUUCodedLength = lEnvelope.length();
    // free the base64 codec buffer
    free(base64encoded);
  }
  // buffer to take the remote public encrypted UUID (the symmetric key)
  char sUUIDcrypt[4096];

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  if (fVerbose) {
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "TSealedEnvelope:encodeEnvelope: RSA_public_encrypt " << std::endl;
  }

  // encrypt UUID/CIPHER with the remote public key
  int32_t sUUIDcryptLen = RSA_public_encrypt(fUUID.length()+1, (uint_fast8_t*) fUUID.c_str(), (uint_fast8_t*) sUUIDcrypt,  fEVP_RemotePublicKey->pkey.rsa,RSA_PKCS1_PADDING); 


  if (sUUIDcryptLen<0) {
      fprintf(stderr,"TSealedEnvelope::encodedEnvelope: cannot local private key encrypt the UUID cipher!\n");
      return "";
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  if (fVerbose) {
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "TSealedEnvelope::encodeEnvelope: SPC_BASE64_ENCODE" << std::endl;
  }


  // uuencode encrypted cipher
  uint_fast8_t* sUUIDcryptBase64 = spc_base64b_encode( (uint_fast8_t*) sUUIDcrypt, sUUIDcryptLen, 1) ;

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  if (fVerbose) {
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "CIPHER LENGTH : " << strlen((char*)sUUIDcryptBase64) << std::endl;
  }
  

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  // we write the coded envelope as 
  // 1 htonl(uint32_t signature length)
  // 2 char signature[signature length];
  // 3 coded buffer

  uint32_t*     siglen           = (uint32_t*) codebuffer; 
  uint_fast8_t* signature        = (uint_fast8_t*) codebuffer+sizeof(uint32_t);
  uint32_t      signheaderlength = (fEVP_RemotePublicKeySize) + sizeof(uint32_t);

  *siglen = fEVP_LocalPrivateKeySize;

  // create the signature of the envelope
  uint_fast8_t hash[20];

  if (!SHA1( (uint_fast8_t*)lEnvelope.c_str(), lEnvelope.length(), hash)) {
    fprintf(stderr,"TSealedEnvelope::encodeEnvelope: cannot create the sha1 hash!\n");
    return "";
  }

  int32_t signing = RSA_sign( NID_sha1, hash, 20,
	       signature, siglen, fEVP_LocalPrivateKey->pkey.rsa);

  // convert it to a machine independent network address
  *siglen = htonl(*siglen);

  /////////////////////////////////////////////////////////////////////////////////////////////////////

  if (signing != 1) {
    uint32_t e = ERR_get_error();
    fprintf(stderr,"TSealedEnvelope::encodeEnvelope: cannot sign the envelope with the local private key! %d[%s %s %s] \n",e,ERR_func_error_string(e), ERR_lib_error_string(e),ERR_reason_error_string(e));
    return "";
  }

  // encrypt the envelope with the UUID/CIPHER
  EVP_CIPHER_CTX ectx;
  uint_fast8_t iv[EVP_MAX_IV_LENGTH_NEW+1];
  // write the initialization vector
  sprintf((char*)iv,"$KJh#(}q");

  int32_t keylen = fUUID.length();

  // the envelope starts after the signature lenght + signature
  char *sEnvelopeCrypt = ((char*) codebuffer + signheaderlength);

  if (!sEnvelopeCrypt) {
      fprintf(stderr,"TSealedEnvelope::encodedEnvelope: cannot create crypted envelope buffer!\n");
      return "";
  }

  uint_fast8_t* ekey;
  ekey = (uint_fast8_t*)fUUID.c_str();
  int32_t ekeylen;
  ekeylen = fUUID.length();

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  if (fVerbose) {
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "TSealedEnvelope::encodeEnvelope: EVP_Cipher Encoding" << std::endl;
  }


    //	init cipher context
	EVP_CIPHER_CTX_init(&ectx);
//	set up cipher for blowfish except key and iv
	EVP_CipherInit_ex(&ectx, EVP_bf_cbc(), NULL, NULL, NULL, 1);
	EVP_CIPHER_CTX_set_key_length(&ectx, ekeylen);
//	now, after the keylength is known by the cipher context, set up key and iv
	EVP_CipherInit_ex(&ectx, NULL, NULL, ekey, iv, 1);



  char* iptr = sEnvelopeCrypt;
  uint32_t sEnvelopeCryptLen=0;
 
  int32_t outbuflen1;
  int32_t outbuflen2;
  EVP_CipherUpdate(&ectx, (uint_fast8_t*)iptr, &outbuflen1, (uint_fast8_t*)lEnvelope.c_str(), lEnvelope.length());
  iptr+=outbuflen1;
  EVP_CipherFinal(&ectx, (uint_fast8_t*)iptr, &outbuflen2);
  iptr+=outbuflen2;
  // calculate the length of the crypted stuff
  sEnvelopeCryptLen=iptr-sEnvelopeCrypt;


  //////////////////////////////////////////////////////////////////////////////////////////////////////
  if (fVerbose) {
    std::cerr << "------------------------------------------------------------------------" << std::endl;
    std::cerr << "TSealedEnvelope::encodeEnvelope: SPC_BASE64_ENCODE" << std::endl;
  }


  // uuencode the envelope ... yawn .... but don't forget the signature before the crypted envelope !
  uint_fast8_t* sEnvelopeCryptBase64 = spc_base64b_encode((uint_fast8_t*) codebuffer, (int32_t) sEnvelopeCryptLen + signheaderlength ,1);

  std::string lSealedEnvelope = "";
  lSealedEnvelope += std::string("-----BEGIN SEALED CIPHER-----\n");
  lSealedEnvelope += std::string((char*)sUUIDcryptBase64);

  lSealedEnvelope += std::string("-----END SEALED CIPHER-----\n");
  lSealedEnvelope += std::string("-----BEGIN SEALED ENVELOPE-----\n");
  lSealedEnvelope += std::string((char*)sEnvelopeCryptBase64);
  lSealedEnvelope += std::string("-----END SEALED ENVELOPE-----\n"); 

  EVP_CIPHER_CTX_cleanup(&ectx);
  free(sUUIDcryptBase64);
  free(sEnvelopeCryptBase64);

  fEncodedEnvelope = lSealedEnvelope;

  return lSealedEnvelope;
}

std::string 
TSealedEnvelope::decodeEnvelope(std::string cryptedEnvelope) {
  if ((fCodingType<0) || (fCodingType == TSE_ENCODE)) {
    fprintf(stderr,"TSealedEnvelope::encodeEnvelope: you have to initialize as a decoder!\n");
    return "";
  }

    std::string lSealedCipher = "";
    std::string lSealedEnvelope = "";

    // reset all variables
    fMD5SUM="";
    fUnixTime="";
    fDate="";
    fExpires="";
    fExpDate="";
    fCertificate="";
    fEnvelopeHeader="";
    fEnvelopeBody="";

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "=> Crypted Envelope" << std::endl;
      std::cerr << cryptedEnvelope << std::endl;
    }

    // If authz is url encoded, then decode it
    if (cryptedEnvelope.find("-----BEGIN%20SEALED%20CIPHER-----") == 0)
    {
      CURL*curl = curl_easy_init();

      if (curl)
      {
        int out_len;
        char* decoded_url = curl_easy_unescape(curl, cryptedEnvelope.c_str(), 0, &out_len);

        if (decoded_url)
        {
          cryptedEnvelope.clear();
          cryptedEnvelope = std::string(decoded_url, out_len);

          if (fVerbose)
          {
            std::cerr << "Decoded authz" << std::endl
                      << "------------------------------------------------------------------------"
                      << std::endl
                      << cryptedEnvelope << std::endl
                      << "------------------------------------------------------------------------"
                      << std::endl;
          }

          curl_free(decoded_url);
        }

        // Clean up
        curl_easy_cleanup(curl);
      }
      else
      {
        fprintf(stderr, "SealedEnvelope::decodedEnvelope: failed to initialize "
                "curl to url decode the authz\n");
        return "";
      }
    }

    std::stringstream sin;
    std::string line;
    sin << cryptedEnvelope << std::endl;

    // parse the crypted Envelope
    std::string assign="";

    while ((std::getline(sin, line))) {
      //      std::cerr << "Reading: |" << line << "|" <<std::endl;
	if (line == std::string("-----BEGIN SEALED CIPHER-----")) {
	    assign = std::string("sealed_cipher");
	    continue;
	}
	if (line == std::string("-----END SEALED CIPHER-----")) {
	    if (assign != std::string("sealed_cipher")) {
		fprintf(stderr,"SealedEnvelope::decodeEnvelope: illegal format in encoded envelope sealed cipher %s\n", assign.c_str());
		return "";
	    }
	    assign = "";
	    continue;
	}

	if (line == std::string("-----BEGIN SEALED ENVELOPE-----")) {
	    assign = std::string("sealed_envelope");
	    continue;
	}

	if (line == std::string("-----END SEALED ENVELOPE-----")) {
	    if (assign != std::string("sealed_envelope")) {
		fprintf(stderr,"SealedEnvelope::decodedEnvelope: illegal format in encoded envelope sealed envelope\n");
		return "";
	    }
	    assign = "";
	    continue;
	}
	
	if (assign.length()>0) {
	    if (assign == std::string("sealed_cipher")) {
		lSealedCipher += line;
	    }
	    
	    if (assign == std::string("sealed_envelope")) {
		lSealedEnvelope += line;
	    }
	}
    }
    
    lSealedCipher += "\n";
    lSealedEnvelope += "\n";

    char* base64decoded=0;
    char* sUUIDcrypt;
    int32_t len = lSealedCipher.length();
    int32_t errors = 0; 

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "TSealedEnvelope::decodeEnvelope: SPC_BASE64_DECODE" << std::endl;
    }


    sUUIDcrypt = (char*)spc_base64b_decode((uint_fast8_t*) lSealedCipher.c_str(), (size_t*) &len, 1 , &errors);

    if (!sUUIDcrypt) {
      std::cerr << "Error: cannot base64 decode the buffer" << std::endl;
      return std::string("");
    }

    std::string sUUID;
    sUUID.resize(4096 + fEVP_RemotePrivateKeySize);

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "TSealedEnvelope::decodeEnvelope: RSA_PUBLIC_DECRYPT len:" << (int) len << std::endl;
    }

    if (len == 0) {
      std::cerr << "Error: nothing could be decrypted " << std::endl;
      return std::string("");
    }

    // decrypt UUID/cipher with remote private key
    int sUUIDcryptLen = RSA_private_decrypt(len, (uint_fast8_t*) sUUIDcrypt, (uint_fast8_t*) sUUID.c_str(),  fEVP_RemotePrivateKey->pkey.rsa,RSA_PKCS1_PADDING); 

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "TSealedEnvelope::decodeEnvelope: the symmetric CIPHER len: " << sUUIDcryptLen << " is: -not shown- " << std::endl;
    }

    len = lSealedEnvelope.length();
    base64decoded = (char*) spc_base64b_decode((uint_fast8_t*) lSealedEnvelope.c_str(),(size_t*)&len, 1,&errors);

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "TSealedEnvelope::decodeEnvelope: Base64 Error is : " << errors << "Len is: " << len << " to " << lSealedEnvelope.length() << std::endl;
      std::cerr << lSealedEnvelope << std::endl;
    }

    std::string fUUID(sUUID.c_str());

    free(sUUIDcrypt);
    
    // uncrypt the base64decoded envelope with the obtained cipher
    EVP_CIPHER_CTX ectx;
    uint_fast8_t iv[EVP_MAX_IV_LENGTH_NEW+1];
    // write the initialization vector
    sprintf((char*)iv,"$KJh#(}q");
    
    int32_t keylen = fUUID.length();

    uint32_t siglen = *((uint32_t*) base64decoded);

    // convert back from a machine independent network address
    siglen = ntohl(siglen);

    uint32_t signheaderlength = fEVP_LocalPublicKeySize + sizeof(uint32_t);
    
    if (siglen > fEVP_LocalPublicKeySize) {
      fprintf(stderr,"TSealedEnvelope::decodeEnvelope: illegal signature length %u found!\n",siglen);
      return "";
    }
    

    uint_fast8_t signature[512]; 
    memcpy(signature, (uint_fast8_t*) base64decoded +sizeof(uint32_t), siglen);

    char *sEnvelopeDecrypt = codebuffer;
    
    if (!sEnvelopeDecrypt) {
	fprintf(stderr,"TSealedEnvelope::decodeEnvelope: cannot create uncrypted envelope buffer!\n");
	return "";
    }

    uint_fast8_t* ekey;
    ekey = (uint_fast8_t*)fUUID.c_str();
    int32_t ekeylen = fUUID.length();

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "TSealedEnvelope::decodeEnvelope: EVP_Cipher Decoding" << std::endl;
    }


    //	init cipher context
	EVP_CIPHER_CTX_init(&ectx);
//	set up cipher for blowfish except key and iv
	EVP_CipherInit_ex(&ectx, EVP_bf_cbc(), NULL, NULL, NULL, 0);
	EVP_CIPHER_CTX_set_key_length(&ectx, ekeylen);
//	now, after the keylength is known to the cipher context, set up key and iv
	EVP_CipherInit_ex(&ectx, NULL, NULL, ekey, iv, 0);

    uint_fast8_t* optr = (uint_fast8_t*)sEnvelopeDecrypt;
    int32_t len1=0;
    int32_t len2=0;
    EVP_CipherUpdate(&ectx,optr,&len1,(uint_fast8_t*)base64decoded+signheaderlength,len-signheaderlength);
    optr+=len1;
    EVP_CipherFinal(&ectx,optr,&len2);
    // terminate anyway the string with 0
    sEnvelopeDecrypt[len1+len2]= 0;

    std::string lEnvelopeDecoded(sEnvelopeDecrypt);
    EVP_CIPHER_CTX_cleanup(&ectx);

    free(base64decoded);     // parse the envelope

    // build the sha1 hash
    uint_fast8_t hash[20];

    assign = "";

    std::string lEnvelope       = "";
    std::string lEnvelopeBody   = "";



    /////////////////////////////////////////////////////////////////////////////
    // parse the crypted Envelope
    /////////////////////////////////////////////////////////////////////////////


    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "TSealedEnvelope::decodeEnvelope: Parsing for GZIP " << std::endl;
      std::cerr << lEnvelopeDecoded << std::endl;
    }


    // check if we have an compressed envelope
    std::stringstream sCompressedEnvelope;
    sCompressedEnvelope << lEnvelopeDecoded << std::endl;    

    std::string lUnsealedCompressed = "";
    
    while ((std::getline(sCompressedEnvelope, line))){ 
      if ( line  == std::string("-----BEGIN GZIP ENVELOPE-----")) {
	assign = std::string("unsealed_compress");
	continue;
      }
      if ( line == std::string("-----END GZIP ENVELOPE-----")) {
	//	lUnsealedCompressed.erase(lUnsealedCompressed.length()-2,2);
	if (assign != std::string("unsealed_compress")) {
	  fprintf(stderr,"SealedEnvelope::decodeEnvelope: illegal format in unsealed encoded envelope\n");
	  return "";
	}
	continue;
      }	

      if (assign == ""){
	continue;
      }
      
      //      if (*(line.c_str()) == 1) {
      //	continue;
      //      }
      
      if (!line.length()) {
	continue;
      }
      //      std::cerr << "Adding line |" << line.length() << "|" << std::endl;
      lUnsealedCompressed += line;
      //      lUnsealedCompressed += std::string("\n");
    }

    if ( lUnsealedCompressed != "") {
      //////////////////////////////////////////////////////////////////////////////////////////////////////
      if (fVerbose) {
	std::cerr << "------------------------------------------------------------------------" << std::endl;      
	std::cerr << "TSealedEnvelope::decodeEnvelope: Uncompressing the envelope ..." << std::endl;
	std::cerr << "------------------------------------" << std::endl;
	std::cerr << "TSealedEnvelope::decodeEnvelope: " << lUnsealedCompressed << std::endl;
	std::cerr << "------------------------------------" << std::endl;
      }
      len = lUnsealedCompressed.length();
      errors=0;
      // base64 decoding
      char* sCompressDecode64 = (char*)spc_base64b_decode((uint_fast8_t*) lUnsealedCompressed.c_str(), (size_t*) &len, 0 , &errors);
      // uncompress
      Bytef *dest = (Bytef*) codebuffer;
      uLongf dest_len = CODEBUFFERSIZE;

      if (!dest) {
	fprintf(stderr,"TSealedEnvelope::decodeEnvelope: cannot get uncompress memory!\n");
	return "";
      }

      //////////////////////////////////////////////////////////////////////////////////////////////////////
      if (fVerbose) {
	std::cerr << "------------------------------------------------------------------------" << std::endl;
	std::cerr << "TSealedEnvelope::decodeEnvelope: uncompresing envelope " << std::endl;
      }

      if ( (uncompress(dest, &dest_len, (const Bytef*) sCompressDecode64, len)) != Z_OK) {
      	fprintf(stderr,"TSealedEnvelope::decodeEnvelope: cannot uncompress the envelope!\n");
	return "";
      }
      
      lEnvelopeDecoded=std::string((char*)dest);
      free(sCompressDecode64);
    }

    
    if (!SHA1( (uint_fast8_t*)lEnvelopeDecoded.c_str(), (uint32_t)lEnvelopeDecoded.length(), hash) ) {
      fprintf(stderr,"TSealedEnvelope::decodeEnvelope: cannot build the sha1 hash sum!");
      return "";
    }
    
    // verify the signature of the envelope
    int32_t verify = RSA_verify(NID_sha1, hash, 20,
		   signature, siglen, fEVP_LocalPublicKey->pkey.rsa);

    if (verify != 1) {
      	fprintf(stderr,"TSealedEnvelope::decodeEnvelope: cannot verify the signature of the envelope buffer [%d]!\n",verify);
	return "";
    }



    std::stringstream sEnvelope;
    sEnvelope << lEnvelopeDecoded << std::endl;

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "TSealedEnvelope::decodeEnvelope: Parsing for HEADER+BODY " << std::endl;
    }
    
    while ((std::getline(sEnvelope, line))){ 
      //	std::cerr << line << std::endl;
	// parse each line .... puuh 
	if ( line  == std::string("-----BEGIN ENVELOPE-----") ) {
            assign = std::string("unsealed_envelope");
	    continue;
        }
	
        if ( line == std::string("-----END ENVELOPE-----") ) {
            if (assign != std::string("unsealed_envelope")) {
                fprintf(stderr,"SealedEnvelope::decodeEnvelope: illegal format in unsealed envelope\n");
                return "";
            }
	    continue;
        }

        if ( line == std::string("-----BEGIN ENVELOPE BODY-----")) {
            assign = std::string("unsealed_envelopebody");
	    continue;
        }
	
	if ( line == std::string("-----END ENVELOPE BODY-----")) {
            if (assign != std::string("unsealed_envelopebody")) {
                fprintf(stderr,"SealedEnvelope::decodeEnvelope: illegal format in unsealed envelope\n");
                return "";
            }
            assign = std::string("unsealed_envelope");
	    continue;
        }
	
        if ( assign == "") {
	    continue;
        }

	if (assign == std::string("unsealed_envelope")) {
	    // parse the single lines
	    
	    lEnvelope += line + std::string("\n");;
	}
	
	if (assign == std::string("unsealed_envelopebody")) {
	    lEnvelopeBody += line + std::string("\n");
	}
    }

    fEnvelopeHeader = lEnvelope;
    fEnvelopeBody   = lEnvelopeBody;

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    if (fVerbose) {
      std::cerr << "------------------------------------------------------------------------" << std::endl;
      std::cerr << "TSealedEnvelope::decodeEnvelope: Parsing for HEADER info " << std::endl;
    }

    /////////////////////////////////////////////////////////////////////////////
    // parse the envelope header information
    /////////////////////////////////////////////////////////////////////////////

    std::stringstream sEnvelopeHeader;
    sEnvelopeHeader << lEnvelope << std::endl;    
    
    while ((std::getline(sEnvelopeHeader, line))){ 
      // look for tags
      if ((line.find("CREATOR:",0)) == 0) {
	fCreator=line.substr(13);
      }
      if ((line.find("UNIXTIME:",0)) == 0) {
	fUnixTime=line.substr(13);
      }
      if ((line.find("DATE:",0)) == 0) {
	fDate=line.substr(13);
      }
      if ((line.find("EXPIRES:",0)) == 0) {
	fExpires=line.substr(13);
      }
      if ((line.find("EXPDATE:",0)) == 0) {
	fExpDate=line.substr(13);
      }
      if ((line.find("CERTIFICATE:",0)) == 0) {
	fCertificate=line.substr(13);
      }
    }

    assign = "";
    
    return lEnvelopeBody;
}


bool 
TSealedEnvelope::CheckValidityTime() { 
    time_t env_time = atoi(fExpires.c_str());
    char senv_time[4096];
    sprintf(senv_time,"%d",env_time);
    if (strcmp(fExpires.c_str(),senv_time)) {
      fprintf(stderr,"TSealedEnvelope: Envelope Timestamp is illegal: |%s|%s|!\n",fExpires.c_str(),senv_time);
      return false;
    }
    
    time_t tdiff = (time(NULL)- env_time);
    if ( (tdiff > 0) && (env_time !=0) ) {
      fprintf(stderr,"TSealedEnvelope: Envelope has expired since %u secondes!\n", tdiff);
      return false;
    }
    
    return true;
  }
	
