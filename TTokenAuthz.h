#ifndef __TTOKENAUTHZ_H
#define __TTOKENAUTHZ_H

//////////////////////////////////////////////////////////////////
/// @file TTokenAuthz.h
///
///
/// @author Andreas-Joachim Peters <andreas.joachim.peters@cern.ch>
///
/// Initial version: 1.9.2005
///
/// Version info: $Id: TTokenAuthz.h,v 1.3 2005/10/06 13:32:17 apeters Exp $


#include <string>
#include <map>
#include <list>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <pthread.h>
#include <TAuthzXMLreader.h>

static pthread_mutex_t ttokenauthz_lock;

class TTokenAuthz {
 public:
  /// structure to define private and public key for a vo
  /// filled from KEY statements in a configuration file
  struct vo_def {
    std::string vo;
    std::string privkey;
    std::string pubkey;
  };

  /// structure to define export of paths for a given vo and certificate
  /// filled from EXPORT statements in a configuration file
  struct path_def {
    std::string path;
    std::string vo;
    bool access;
    std::string cert;
  };

  /// structure to define authorization rules for certain paths/vo/cert and acces types
  /// filled from RULE statements in a configuration file
  struct rule_def {
    std::string path;
    std::string authz;
    std::string noauthz;
    std::string vos;
    std::string cert;
  };

  std::list<struct vo_def> vos;        ///< list of vo_def structures defining the keys to use for a given VO
  std::list<struct path_def> exports;  ///< list of path_def structures defining the paths to be exported for a given vo/certifcate
  std::list<struct rule_def> rules;    ///< list of rule_def structures defining the authorization policies for a given path/vo/certifcate
    
  /**
     the class constructor. DON'T USE! Use the factory function GetTokenAuthz for that purpose
     
  */

  TTokenAuthz(const char* name=0,bool verbose=false);
  
  bool isVerbose;
  /**
5A     the class destructor
  */
  ~TTokenAuthz();

  /// The enum list of return values for the GetAuthz function
  enum AuthzError {kAuthzOK, kNoAuthz,kNoPubKey,kNoPrivKey,kErrorInitEnv, kAuthzUnreadable,kAuthzExpired,kAuthzParseXml};

  /**
     function to return a text explaination for a given return value of the GetAuthz function
  */
  const char* ErrorMsg(int enr) {
    switch(enr) {
    case kAuthzOK: return "Authz OK!";break;
    case kNoAuthz: return "get authz for lfn";break;
    case kNoPubKey: return "read public key for decoding [env var: SEALED_ENVELOPE_REMOTE_PUBLIC_KEY[_<VO>]=<>]";break;
    case kNoPrivKey: return  "read private key for decoding [env var: SEALED_ENVELOPE_LOCAL_PRIVATE_KEY[_<VO>]=<>]";break;
    case kErrorInitEnv: return "initialize envelope decryption";break;
    case kAuthzUnreadable: return "read provided authz for";break;
    case kAuthzExpired: return "authorize access -> authz expired for";break;
    case kAuthzParseXml: return "read the authz xml information for";break;
    default:
      return "undefined error";
      break;
    }
  }; 
  
  /** 
      conversion function to map GetAuthz return values to posix errors
  */

  int PosixError(int enr) {
    switch (enr) {
    case kAuthzOK: return 0; break;
    case kNoAuthz: return   ENOMSG; break;
    case kNoPubKey: return  ENOENT; break;
    case kNoPrivKey: return ENOENT; break;
    case kErrorInitEnv: return ENOENT;break;
    case kAuthzUnreadable: return EACCES; break;
    case kAuthzExpired: return ETIMEDOUT; break;
    case kAuthzParseXml: return EINVAL; break;
    default:
      return -1;break;
    }
  } 
			    
  static void Tokenize(const char* strptr,
		       std::map<std::string,std::string>& tokenhash,
		       const std::string& delimiters = " ");

  static const char* GetPath(const char* path);

  bool PathIsExported(const char* path, const char* vo, const char* cert="*");
  bool PathHasAuthz(const char* path, const char* accessmode, const char* vo, const char* cert="*");
  bool CertNeedsMatch(const char* path, const char* vo);

  int GetAuthz(const char *filename, const char *opaque, TAuthzXMLreader** authz, bool debug=0, float* abstime=0, float* abstime2=0);
  static TTokenAuthz* GetTokenAuthz(const char* name=0, bool verbose=false);

};
#endif
