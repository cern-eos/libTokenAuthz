//////////////////////////////////////////////////////////////////
/// @file TTokenAuthz.cxx
///
/// @brief This class implements the token authorization functionality for rule checking and token decoding
///
/// @author Andreas-Joachim Peters <andreas.joachim.peters@cern.ch>
///
/// Initial version: 1.9.2005
///
/// Version info: $Id: TTokenAuthz.cxx,v 1.8 2006/07/05 14:38:24 apeters Exp $
///
//////////////////////////////////////////////////////////////////


/** @mainpage TokenAuthz
 *  \section Information General Information
 *  The TokenAuthz module is used to define rules for namespace access based on user certificates and VO membership.
 *  The policies to access a part of the namespace as also the rules, on which branch of the namespace token authorization
 *  has to be applied, can be defined through configuration files.
 *  The class provides functions to check the defined namespace rules and in case of token authorization acts as a
 *  wrapper class for the TSealedEnvelope and TAuthzXMLreader class. The 1st decodes authorization information using
 *  private and public keys, which are defined for specific VOs in the configuration file. The 2nd class decodes 
 *  the decrypted authorization xml envelope into key-value pairs.
 *  \section ConfigurationFiles Location of Configuration Files
 *  The TokenAuthz Authorization Object looks per default in the following locations for configuration files: \n
 *  1	Environment Variable: export TTOKENAUTHZ_AUTHORIZATIONFILE="<authzfile>" \n
 *  2	/etc/grid-security/<module-name>/TkAuthz.Authorization \n
 *  3	$HOME/.globus/<module-name>/TkAuthz.Authorization \n
 *  4	$HOME/.authz/<module-name>/TkAuthz.Authorization \n
 *  \n
 *  \section DefaultBehaviour Default Behaviour without Configuration Files
 *  If no one of these configuratino files is found, the default behaviour is to disable the authorization for the complete namespace and to  \n
 *  export the complete namespace. \n
 *  \section ConfigfileStructure Structure of a Configuratino File
 *  The structure can be best understood by inspecting the example files in the 'conf' directory. \n
 *  The module works with the principle, the the first matching rule is applied. So, order \n
 *  your rules in an appropriate way.   \n
 *   \n
 *  Configuration File: "TkAuthz.Authorization" \n
 *   \n
 *  ##################################################################### \n
 *  # Description: \n
 *  # ------------------------------------------------------------------- \n
 *  # This file describes, which namespace paths are exported and can \n
 *  # enforce token authorization for specific VO's and paths. \n
 *  # \n
 *  # Structure: \n
 *  # ------------------------------------------------------------------- \n
 *  # The file contiains three section: \n
 *  # KEYS: \n
 *  # ======= \n
 *  # this section assigns to each VO the private and public key pairs \n
 *  # to be used, to decode and verify authorization tokens \n
 *  # \n
 *  # EXPORT: \n
 *  # ======= \n
 *  # this section defines, which namespace path's are exported. \n
 *  # The rules can allow or deny part of the namespace for individual \n
 *  # VO's and certificates \n
 *  # \n
 *  # RULES: \n
 *  # ======= \n
 *  # this section contains specific ruls for each namespace path, if \n
 *  # token authorization has to be applied, to which operations and \n
 *  # for which VO and certificates it has to be applied. \n
 *   \n
 *  # ------------------------------ Warning ---------------------------- \n
 *  # the key words \n
 *  #       KEY, EXPORT, RULE \n
 *  #       VO, PRIVKEY, PUBKEY \n
 *  #       PATH, AUTHZ, NOAUTHZ, CERT \n
 *  # have to be all uppercase! Values are assigned after a ':' \n
 *  # ------------------------------------------------------------------- \n
 *   \n
 *   \n
 *  ##################################################################### \n
 *  # Key section \n
 *  ##################################################################### \n
 *  # \n
 *  # Syntax:KEY  VO:<voname>     PRIVKEY:<keyfile>      PUBKEY:<keyfile> \n
 *  # \n
 *  #  ------------------------------------------------------------------ \n
 *  # VO:* defines the default keys for unspecified vo \n
 *   \n
 *  #KEY VO:ALICE  PRIVKEY:key.pem PUBKEY:pkey.pem \n
 *  #KEY VO:CMS    PRIVKEY:<pkey>  PUBKEY:<pubkey> \n
 *  #KEY VO:*      PRIVKEY:<pkey>  PUBKEY:<pubkey> \n
 *   \n
 *  ###################################################################### \n
 *  # Export Section \n
 *  ##################################################################### \n
 *  # \n
 *  # Syntax: EXPORT PATH:<path> 	VO:<vo>	ACCESS:<ALLOW|DENY>	CERT:<*|cert> \n
 *  #		 \n
 *  #  ------------------------------------------------------------------ \n
 *  # - PATH needs to be terminated with / \n
 *  # - ACCESS can be ALLOW or DENY \n
 *  # - VO can be wildcarded with VO:* \n
 *  # - CERT can be wildcarded with CERT:* \n
 *  # - the first matching rule is applied  \n
 *   \n
 *  #EXPORT PATH:/tmp/alice/ VO:ALICE ACCESS:ALLOW CERT:* \n
 *  #EXPORT PATH:/tmp/cms/   VO:CMS   ACCESS:DENY CERT:* \n
 *  #EXPORT PATH:/castor/    VO:*     ACCESS:ALLOW CERT:* \n
 *   \n
 *  ###################################################################### \n
 *  # RULES Section \n
 *  ###################################################################### \n
 *  # \n
 *  #  Syntax: RULE PATH:<path> AUTHZ:<tag1|tag2|...|> NOAUTHZ:<tag1|tag2|...|> VO:<vo1|vo2|....|> CERT:<IGNORE|*|cert> \n
 *  #    \n
 *  #  ------------------------------------------------------------------ \n
 *  # - PATH  defines the namespace path \n
 *  # - AUTHZ defines the actions which have to be authorized \n
 *  # - NOAUTHZ defines the actions which don't have to be authorized \n
 *  # - VO is a list of VO's, where this rule applies \n
 *  # - CERT can be IGNORE,* or a specific certificate subject \n
 *  #   IGNORE means, that the envelope certificate must not match the \n
 *  #   USER certificate subject. * means, that the rule applies for any \n
 *  #   certificate and the certificate subjects have to match. \n
 *   \n
 *   \n
 *  #RULE PATH:/tmp/ AUTHZ:write|delete|write-once| NOAUTHZ:read| VO:ALICE|CMS| CERT:IGNORE \n
 *  #RULE PATH:/tmp/ AUTHZ:read| NOAUTHZ:| VO:ALICE|CMS| CERT:* \n
 *   \n
 */



#include "TTokenAuthz.h"
#include "TSealedEnvelope.h"
#include <list>
#include <vector>
#include <iostream>
#include <fstream>

/** 
 */
static TTokenAuthz* sTokenAuthz=0; ///< the singleton object maintained by the class factory function GetTokenAuthz

/**
     Constructor to create an authorization instance object
     @param name     name of the authorization instance - it is used to find configuration files in the default locations under the subdir <name>
     @param verbose  switch on verbosity
     @return  nothing
  */

TTokenAuthz::TTokenAuthz(const char* name, bool verbose) {
  isVerbose = verbose;
  if (verbose) 
    if (name) {
      fprintf(stdout,"TTokenAuthz::TTokenAuthz %s Initializing Instance %s\n",PACKAGE_STRING,name);
    } else {
      fprintf(stdout,"TTokenAuthz::TTokenAuthz %s Initializing unnamed Instance \n",PACKAGE_STRING);
    }

  std::list<std::string> configpaths;

  if (getenv("TTOKENAUTHZ_AUTHORIZATIONFILE")) {
    configpaths.push_back(std::string(getenv("TTOKENAUTHZ_AUTHORIZATIONFILE")));
  } else {
    if (verbose)fprintf(stdout,"TTokenAuthz::TTokenAuthz No Authorizationfile set via environment variable 'TTOKENAUTHZ_AUTHORIZATIONFILE'\n");
  }

  std::string extraname = "";
  if (name) {
    extraname = name;
    extraname += "/";
  }

  configpaths.push_back("/etc/grid-security/" + extraname + "TkAuthz.Authorization");
  if (getenv("HOME")) {
    std::string pstring = getenv("HOME");
    pstring +=  "/.globus/";
    pstring += extraname;
    pstring += "TkAuthz.Authorization";
    configpaths.push_back(pstring);
    pstring = getenv("HOME");
    pstring +=  "/.authz/";
    pstring += extraname;
    pstring += "TkAuthz.Authorization";
    configpaths.push_back(pstring);
  }
  
  std::list<std::string>::iterator confname;

  std::string authorizationfile="";

  for (confname=configpaths.begin(); confname != configpaths.end(); ++confname) {
    struct stat buf;
    if (!stat((*confname).c_str(),&buf)) {
      if ( (buf.st_mode & S_IWGRP) || (buf.st_mode & S_IWGRP) ) {
	fprintf(stderr,"TTokenAuthz::TTokenAuthz Authorizationfile '%s' has insecure permission! Not used!\n",(*confname).c_str());
      } else {
	if (verbose)fprintf(stdout,"TTokenAuthz::TTokenAuthz Using Authorizationfile '%s'!\n",(*confname).c_str());
	authorizationfile=(*confname);
	break;
      }
    } else {
      if (verbose)fprintf(stdout,"TTokenAuthz::TTokenAuthz No Authorizationfile like '%s' found\n",(*confname).c_str());
    }
  }

  if (!authorizationfile.length()) {
      struct path_def pdef;
      pdef.path = "/";
      pdef.cert = "*";
      pdef.vo   = "*";
      pdef.access = 1;
      exports.push_back(pdef);
      if (verbose)fprintf(stdout,"TTokenAuthz::TTokenAuthz No Authorizationfile found at all - exporting / to all!\n");
  }

  std::ifstream authzfile(authorizationfile.c_str());
  char buffer[1025];
  memset(buffer,1024,0);

  while (authzfile.getline(buffer,sizeof(buffer))) {
    int length=strlen(buffer);
    // ignore comments
    if (buffer[0] == '#') 
      continue;
    if (length == 0) 
      continue;
    if (verbose) fprintf(stdout,"TTokenAuthz::TTokenAuthz ------------------------------------------------------\n");
    if (verbose) fprintf(stdout,"TTokenAuthz::TTokenAuthz <read> =>  %s\n",buffer);
    if (verbose) fprintf(stdout,"TTokenAuthz::TTokenAuthz ------------------------------------------------------\n");
    std::vector<std::string>linetokens;
    char* tokenptr=buffer;

    while ((tokenptr!=0) && (tokenptr <= (buffer+1024))) {
      // skip blanks
      while ( ((*tokenptr)==' ') || ((*tokenptr)=='\t') ) {
	tokenptr++;
      }
      
      const char* tbegin=tokenptr;
      while ( (tokenptr != (buffer+1024) && ((*tokenptr)!= ' ') && ((*tokenptr)!='\t') && ((*tokenptr) !=0) )) {
	tokenptr++;
      }
      *tokenptr=0;
      tokenptr++;
      linetokens.push_back(std::string(tbegin));
      if ( (tokenptr >= (buffer+1024) || (tokenptr> (buffer+length)))) {
	tokenptr=0;
      }
    }    

    // fill the maps'
    if (linetokens[0] == "KEY") {
      // this is a key definition line
      if ( (linetokens.size()<4) ||
           (linetokens[1].substr(0,3) != "VO:") ||
	   (linetokens[2].substr(0,8) != "PRIVKEY:") ||
	   (linetokens[3].substr(0,7) != "PUBKEY:") ) {
	fprintf(stderr,"TTokenAuthz::TTokenAuthz Error: Illegal format in KEY section\n");
	continue;
      }
      struct vo_def vdef;
      vdef.vo      = linetokens[1].substr(3);
      vdef.privkey = linetokens[2].substr(8);
      vdef.pubkey  = linetokens[3].substr(7);
      vos.push_back(vdef);
      if (verbose)fprintf(stdout,"TTokenAuthz::TTokenAuthz Creating VO '%s'\n",vdef.vo.c_str());
      if (verbose)fprintf(stdout,"                         PrivKey:    '%s'\n",vdef.privkey.c_str());
      if (verbose)fprintf(stdout,"                         PubKey:     '%s'\n",vdef.pubkey.c_str());
    }
    if (linetokens[0] == "EXPORT") {
      if ( (linetokens.size() < 5) ||
	   (linetokens[1].substr(0,5) != "PATH:") ||
	   (linetokens[2].substr(0,3) != "VO:") ||
	   (linetokens[3].substr(0,7) != "ACCESS:") || 
	   (linetokens[4].substr(0,5) != "CERT:") ) {
	fprintf(stderr,"TTokenAuthz::TTokenAuthz Error: Illegal format in EXPORT section\n");
	continue;
      }
      struct path_def pdef;
      pdef.path = linetokens[1].substr(5);
      pdef.vo   = linetokens[2].substr(3);
      pdef.access = (linetokens[3].substr(7)== "ALLOW")?1:0;
      pdef.cert = linetokens[4].substr(5);
      exports.push_back(pdef);
      if (verbose)fprintf(stdout,"TTokenAuthz::TTokenAuthz Exporting '%s' for VO '%s' with access='%d' for cert='%s'\n",pdef.path.c_str(),pdef.vo.c_str(),pdef.access,pdef.cert.c_str());
    }
    if (linetokens[0] == "RULE") {
      if ( (linetokens.size() < 6) ||
	   (linetokens[1].substr(0,5) != "PATH:") ||
	   (linetokens[2].substr(0,6) != "AUTHZ:") ||
	   (linetokens[3].substr(0,8) != "NOAUTHZ:") ||
	   (linetokens[4].substr(0,3) != "VO:") ||
	   (linetokens[5].substr(0,5) != "CERT:") ) {
	fprintf(stderr,"TTokenAuthz::TTokenAuthz Error: Illegal format in RULE section\n");
	continue;
      }
      struct rule_def rdef;
      rdef.path    = linetokens[1].substr(5);
      rdef.authz   = linetokens[2].substr(6);
      rdef.noauthz = linetokens[3].substr(8);
      rdef.vos     = linetokens[4].substr(3);
      rdef.cert    = linetokens[5].substr(5);

      rules.push_back(rdef);
      if (verbose)fprintf(stdout,"TTokenAuthz::TTokenAuthz Rule-Def: path='%s' authz='%s' noauthz='%s' vo='%s' cert='%s'\n",rdef.path.c_str(),rdef.authz.c_str(),rdef.noauthz.c_str(),rdef.vos.c_str(),rdef.cert.c_str());
    
    }
  }
}

TTokenAuthz::~TTokenAuthz() {

}


/**
     Help function to split a character string with a certain delimiter into a has map with each token
     @param strptr     pointer to the string to be tokenized                                                                                       
     @param tokenhash  hash where the split fields are stored back
     @param delimiters delimiter to be used to tokenize the input string
     @return  nothing
  */

void
TTokenAuthz::Tokenize(const char* strptr,
		      std::map<std::string,std::string>& tokenhash,
		      		      const std::string& delimiters) {
  
  if (!strptr) {
    return;
  }
  
  std::string str=strptr;
  
  // Skip delimiters at beginning.
  std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
  // Find first "non-delimiter".
  std::string::size_type pos     = str.find_first_of(delimiters, lastPos);
  
  while (std::string::npos != pos || std::string::npos != lastPos)
    {
      // Found a token, add it to the map.
      std::string tokenstring = str.substr(lastPos, pos - lastPos);
      // split by =
      std::string::size_type equalpos;
      if ( (equalpos=tokenstring.find("="))!= std::string::npos) {
        std::string tokenkey = tokenstring.substr(0,equalpos);
        std::string tokenvalue = tokenstring.substr(equalpos+1);
        tokenhash[tokenkey] = tokenvalue;
        //      printf("Setting Token %s = %s \n",tokenkey.c_str(),tokenvalue.c_str());
      }
      
      // Skip delimiters.  Note the "not_of"
      lastPos = str.find_first_not_of(delimiters, pos);
      // Find next "non-delimiter"
      pos = str.find_first_of(delimiters, lastPos);
    }
}


//////////////////////////////////////////////////////////////////////////////
// helper function to find the path in an url
const char* 
TTokenAuthz::GetPath(const char* path) {
  // find in an url the path only
  std::string spath(path);
  std::string::size_type protdelimiter;
  std::string::size_type pathdelimiter;
  if ( (protdelimiter = spath.find("://")) != std::string::npos) {
    if ( (pathdelimiter = (spath.substr(protdelimiter+3)).find("/") ) != std::string::npos) {
      return path + protdelimiter + 3 + pathdelimiter;
    }
    return path;
  }
  return path;
}



/**
     Rule Check to verify, that a given path requires a certificate match with the subject in an envelope token
     @param path       path for which to check a rule                                                                                              
     @param vo         vo for which to check a rule                
     @return  true, if the certificate needs to match the subject in an envelope token, otherwise false
  */
bool
TTokenAuthz::CertNeedsMatch(const char* path, const char* vo) {
  std::string fullpath=path;
  std::list<struct rule_def>::iterator i;
  for (i=rules.begin();i!=rules.end();++i) {
    int len = (*i).path.length();
    // path match
    if ( fullpath.substr(0,len) == ((*i).path )){ 
      // vo match
      std::string vostring=std::string(vo) + std::string("|");
      if ( ( ((*i).vos.find(vostring)) != std::string::npos) || ( (*i).vos == "*|") ) {
	// get match
	if ( ((*i).cert != "IGNORE") && ((*i).cert != "*"))
	  return true;
	else 
	  return false;
      }
    }
  }
  // no rule found, guess we don't need to match
  return false;
}

/**
     Rule Check to verify, that a path is exported at all
     @param path       path for which to check if it is exported                                                                                   
     @param vo         vo for which to check for the export (can be just "*")
     @param certsubject subject for which to check for the export (can be just "*")
     @return  true, if path is exported for that vo/certsubject, otherwise false
  */
bool 
TTokenAuthz::PathIsExported(const char* path, const char* vo, const char* certsubject) {
  std::string fullpath=path;
  std::list<struct path_def>::iterator i;
  for (i=exports.begin();i!=exports.end();++i) {
    int len = (*i).path.length();
    if ( ( (*i).vo != std::string("*") ) && (*i).vo != std::string(vo) )
      continue;
    if ( fullpath.substr(0,len) == ((*i).path )) {
      //      std::cout << "cert: " << (*i).cert << "  path: " << (*i).path << "  access: " << (*i).access << "\n";
      if ( ((*i).cert == std::string("*")) || (certsubject && ((*i).cert == certsubject)) ) 
	return ((*i).access);
    }
  }
  return false;
}

/**
     Rule Check to verify, that a path needs to be authorized 
     @param path       path for which to check if it is exported                                                                                   
     @accessmode       specifies the access mode 
     @param vo         vo for which to check the need of Authz (can be just "*")
     @param certsubject subject for which to check the need of Authz (can be just "*")
     @return  true, if path has to authorized for that vo/certsubject, otherwise false
*/

bool
TTokenAuthz::PathHasAuthz(const char* path, const char* accessmode, const char* vo, const char* certsubject) {
  std::string fullpath=path;
  std::list<struct rule_def>::iterator i;
  for (i=rules.begin();i!=rules.end();++i) {
    int len = (*i).path.length();
    // path match
    if ( fullpath.substr(0,len) == ((*i).path )){ 
      if (isVerbose) fprintf(stdout,"Rule matches path ....\n");
      // vo match
      std::string vostring=std::string(vo) + std::string("|");
      if ( ( ((*i).vos.find(vostring)) != std::string::npos) || ( (*i).vos == "*|") ) {
	// acces mode match in authz 
	std::string modestring=std::string(accessmode) + std::string("|");
	if ( ((*i).authz.find(modestring)) != std::string::npos) {
	  if (isVerbose) fprintf(stdout,"Rule matches access %s",accessmode);
	  if ( ((*i).cert == "*") || ( ((*i).cert == "IGNORE")) || ( certsubject && ((*i).cert == certsubject)) ) {
	    return true;
	  } else {
	    return false;
	  }
	}
      }
    }
  }
  return false;
}


/**
     Static Authorization method to retrieve an authorization object of type TAuthzXMLreader, \\
     with an xml-decoded envelope to access key-value pairs in an envelope
     @param fileName   file name to extrace authorization information out of an envelope                                                       
     @param opaque     opaque information containing an  authz envelope tag and an  vo tag ("&authz=<...>&vo=<...>)
     @param authz      *authz is set by this function to the TAutzhXMLreader object => is a return value
     @param debug      switch on debugging output                                
     @param abstime1   *abstime1 is set to the time for the authz decoding + initialization
     @param abstime2   *abstime2 is set to the time for the pure authz decoding
     @return  kAuthzOK if authorization executed, incase of any error (decoding error etc.) the corresponding error value is returned (see TTokenAuthz.h)
*/
int
TTokenAuthz::GetAuthz(const char *fileName, const char *opaque, TAuthzXMLreader** authz, bool debug, float* abstime1, float* abstime2){
  static const char *epname = "GetAuthz";
  struct timeval abs_start_time;
  struct timeval abs_start_time2;
  struct timeval abs_stop_time;
  struct timezone tz;
  gettimeofday (&abs_start_time, &tz);

  std::map<std::string,std::string> env;

  Tokenize(opaque,env,"&");

  if ((!opaque) || (!env["authz"].length())) {
    return kNoAuthz;
  }

  std::string rpkstring = "";
  std::string lpkstring = "";

  const char* vo=0;

  if (env["vo"].length()) {
    // to support many VO's, we support different keys per VO
    vo = env["vo"].c_str();
  } else {
    vo = "*";
  }

  // the preliminary alien backdoor
  if (env["authz"] == "alien") {
    return kAuthzOK;
  }
    
  // loop over the configured vo's and find the right key's
  std::list<struct vo_def>::iterator i;
  for (i=vos.begin(); i != vos.end(); ++i) {
    if ( (*i).vo == vo ) {
      rpkstring = (*i).pubkey;
      lpkstring = (*i).privkey;
    }
  }
  const char* remotepubkey  = (rpkstring.c_str());
  const char* localprivkey  = (lpkstring.c_str());


  gettimeofday (&abs_start_time2, &tz);

  if ( (!remotepubkey) || (!strlen(remotepubkey)) ) {
    return kNoPubKey;
  }

  if ( (!localprivkey) || (!strlen(localprivkey)) ) {
    return kNoPrivKey;
  }
  
  TSealedEnvelope* envelope = 0;

  if (!(envelope=GetEnvelope(localprivkey,remotepubkey,"Blowfish","",0,vo))) {
    return kErrorInitEnv;
  }

  if (debug) {
    envelope->Verbose(1);
  }

  std::string body = envelope->decodeEnvelope(env["authz"]);

  if (debug){
    envelope->PrintHeader();
  }

  // check if something useful has been found ....
  if (!body.length()) {
    envelope->UnLock();
    return kAuthzUnreadable;
  }

  if (!(envelope->CheckValidityTime())) {
    envelope->UnLock();
    return kAuthzExpired;
  }

  envelope->UnLock();
  (*authz) = new TAuthzXMLreader((char*)body.c_str());

  if (!((*authz)->OK())) {
    delete (*authz);
    (*authz)=0;
    return kAuthzParseXml;
  } else {
    if (debug){(*authz)->Print();};
  }

  gettimeofday (&abs_stop_time, &tz);

  float abs_time=((float)((abs_stop_time.tv_sec - abs_start_time.tv_sec) *1000000 +
                              (abs_stop_time.tv_usec - abs_start_time.tv_usec)))/1000.0;
  float abs_time2=((float)((abs_stop_time.tv_sec - abs_start_time2.tv_sec) *1000000 +
                              (abs_stop_time.tv_usec - abs_start_time2.tv_usec)))/1000.0;

  if (abstime1) {
    *abstime1 = abs_time;
  }
  if (abstime2) {
    *abstime2 = abs_time2;
  }
  return kAuthzOK;
}


/**
     Thread safe Factory function to maintain a name singleton of the TTokenAuthz instance
     @param name       pseudo-name of the singleton instance to return
     @param verbose    verbose during initialization
     @return  pointer to the named TTokenAuthz singleton
*/
TTokenAuthz*
TTokenAuthz::GetTokenAuthz(const char* name,bool verbose) {
  if (sTokenAuthz) {
    return sTokenAuthz;
  }
  pthread_mutex_lock(&(ttokenauthz_lock));
  sTokenAuthz=new TTokenAuthz(name,verbose);
  pthread_mutex_unlock(&(ttokenauthz_lock));
  return sTokenAuthz;
}

#ifdef __MAIN__
int main(int argc, char* argv[]) {
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
#endif
