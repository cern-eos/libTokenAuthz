#include <iostream>
#include <string>

/////////////////////////////////
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#ifdef WITHTHREADS
#include <pthread.h>
#endif

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>

#include <atomic>

#define EVP_MAX_IV_LENGTH_NEW 8

/////////////////////////////////

#define CODEBUFFERSIZE 16*1024*1024

#define TSE_ENCODE 0
#define TSE_DECODE 1
#define TSE_CODEC  2

class TSealedEnvelope {
 private:
  std::string fLocalPrivateKey;
  std::string fLocalPublicKey;
  std::string fRemotePrivateKey;
  std::string fRemotePublicKey;
  std::string fVO;
  int         fCodingType;
  bool fCompress;
  bool fVerbose;
  bool fTrace;
  std::atomic<bool> fInitialized;
  std::string fCipheralgorithm;
  std::string fCreator;
  std::string fMD5SUM;
  std::string fUnixTime;
  std::string fDate;
  std::string fExpires;
  std::string fExpDate;
  std::string fCertificate;
  std::string fEnvelopeHeader;
  std::string fEnvelopeBody;
  std::string fEncodedEnvelope;
  char* codebuffer;

  EVP_PKEY* fEVP_LocalPrivateKey;
  EVP_PKEY* fEVP_LocalPublicKey;
  EVP_PKEY* fEVP_RemotePrivateKey;
  EVP_PKEY* fEVP_RemotePublicKey;


  size_t fEVP_RemotePrivateKeySize;
  size_t fEVP_RemotePublicKeySize;
  size_t fEVP_LocalPublicKeySize;
  size_t fEVP_LocalPrivateKeySize;

  std::string fUUID;

#ifdef WITHTHREADS
  pthread_mutex_t envelopelock;
#endif

 public:
  TSealedEnvelope(const char* localprivatekey="", const char* localpublickey="", const char* remoteprivatekey="", const char* remotepublickey="", const char* cipher="", const char* creator="", int compress=0) {
    fLocalPrivateKey = std::string(localprivatekey);
    fLocalPublicKey  = std::string(localpublickey);
    fRemotePrivateKey = std::string(remoteprivatekey);
    fRemotePublicKey  = std::string(remotepublickey);

    fCompress = compress;
    fVerbose = 0;
    fTrace = 0;
    fCreator = "SealedEnvelope V";
    fCreator += std::string(PACKAGE_VERSION);
    if (strlen(creator)) {
      fCreator = std::string(creator);
    }
    fCipheralgorithm = std::string(cipher);

    fMD5SUM="";
    fUnixTime="";
    fDate="";
    fExpires="";
    fExpDate="";
    fCertificate="";
    fEnvelopeHeader="";
    fEnvelopeBody="";
    codebuffer = (char*)malloc(CODEBUFFERSIZE);
    fInitialized=0;
    fVO="";
#ifdef WITHTHREADS
    pthread_mutex_init(&envelopelock,NULL);
#endif
  }

  EVP_PKEY *ReadPublicKey(const char*);
  EVP_PKEY *ReadPrivateKey(const char*);

  ~TSealedEnvelope() {
    if (codebuffer) {
      free(codebuffer);
    }
  }


  void Verbose(bool verbose=true) {
    fVerbose=verbose;
  }

  void Trace(bool trace=true) {
    fTrace=trace;
  }

  void PrintHeader() {
    std::cout << "TSealedEnvelope: ================================================" << std::endl;
    std::cout << "TSealedEnvelope: CREATOR:     "<< fCreator << std::endl;
    std::cout << "TSealedEnvelope: MD5:         "<< fMD5SUM << std::endl;
    std::cout << "TSealedEnvelope: UNIXTIME:    "<< fUnixTime << std::endl;
    std::cout << "TSealedEnvelope: DATE:        "<< fDate << std::endl;
    std::cout << "TSealedEnvelope: EXPIRES:     "<< fExpires << std::endl;
    std::cout << "TSealedEnvelope: EXPDATE:     "<< fExpDate << std::endl;
    std::cout << "TSealedEnvelope: CERTIFICATE: "<< fCertificate << std::endl;
    std::cout << "TSealedEnvelope: ================================================" << std::endl;
  }

  std::string encodeEnvelope(std::string envelopein, int lifetime ,std::string certificate);

  int encodeEnvelopePerl(const char* envelopein, int lifetime, const char* certificate) {
    std::string result = encodeEnvelope(std::string(envelopein),lifetime,std::string(certificate));
    if (result.length()) {
      return 1;
    } else {
      return 0;
    }
  }

  std::string decodeEnvelope(std::string envelope);

  int decodeEnvelopePerl(const char* envelope) {
    std::string result = decodeEnvelope(std::string(envelope));
    if (result.length()) {
      return 1;
    } else {
      return 0;
    }
  }
  
  // info functions
  const char* GetCreate() {return fCreator.c_str();}
  const char* GetMD5SUM() {return fMD5SUM.c_str();}
  const char* GetUnixTime() {return fUnixTime.c_str();}
  const char* GetExpires() {return fExpires.c_str();}
  const char* GetExpDate() {return fExpDate.c_str();}
  const char* GetCertificate() {return fCertificate.c_str();}
  const char* GetEncodedEnvelope() {return fEncodedEnvelope.c_str();}
  const char* GetDecodedEnvelope() { return fEnvelopeBody.c_str();}
  const char* GetDecodedEnvelopeHeader() { return fEnvelopeHeader.c_str();}

  int         GetCodingType() { return fCodingType;}

  // verify functions
  bool        CheckValidityTime();


  bool Initialize(int codingtype);
  bool        IsInitialized() { return fInitialized;}
  void Reset() {
    fMD5SUM="";
    fUnixTime="";
    fDate="";
    fExpires="";
    fExpDate="";
    fCertificate="";
    fEnvelopeHeader="";
    fEnvelopeBody="";
    fEncodedEnvelope="";
    //    fCodingType=-1; this we don't reset
    codebuffer[0] = 0;
  }

#ifdef WITHTHREADS 
  int Lock() {
    //    printf("MUTEX: envelopelock locked\n");
    return pthread_mutex_lock(&envelopelock);
  }
#endif

#ifdef WITHTHREADS
  int UnLock() {
    //    printf("MUTEX: envelopelock unlocked\n");
    return pthread_mutex_unlock(&envelopelock);
  }
#endif
};

extern TSealedEnvelope* GetEnvelope(const char* privatekey, const char* publickey, const char* cipher,const char* creator, int compress, const char* vo);

