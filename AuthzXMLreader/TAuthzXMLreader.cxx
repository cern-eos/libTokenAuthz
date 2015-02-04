
//#include <libxml/libxml.h>
#include "libxml/xmlreader.h"
#include <string.h>
#include <string>
#include <iostream>
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "TAuthzXMLreader.h"

void 
TAuthzXMLreader::Print() {
  printf("TAuthzXMLreader: =============================================\n");
  
  std::map<std::string,std::map<std::string,std::string> >::const_iterator iit;
  
  for ( iit = fAuthz.begin(); iit != fAuthz.end(); ++iit ) {
    std::cout << "TAuthzXMLreader: --------------------------------------------" << std::endl;
    std::cout << "TAuthzXMLreader: LFN : " << iit->first << std::endl;
    std::cout << "TAuthzXMLreader: --------------------------------------------" << std::endl;
    // loop over all keys inside the lfn hashes
    std::map<std::string, std::string>::const_iterator it;
    for ( it = (iit->second).begin(); it != (iit->second).end(); ++it ) {
      std::cout << "TAuthzXMLreader: " << it->first << "\t\t : \t" << it->second << std::endl;
    }
  }
  printf("TAuthzXMLreader: =============================================\n");
}


TAuthzXMLreader::TAuthzXMLreader(char* xmlinput) {
  int ret;
  fOK=false;
  
  xmlTextReaderPtr reader;

  //  reader = xmlNewTextReaderFilename("my.xml");
  if (!xmlinput) {
    fOK=false;
    return;
  }
  reader =   xmlReaderForMemory(xmlinput,strlen(xmlinput),0,0,0);

  if (!reader) {
    return;
  }
  
  //<authz>
  ret = xmlTextReaderRead(reader);
    if ((!ret) || ((xmlStrcmp(xmlTextReaderConstName(reader), (const xmlChar*) "authz")))) {
    fprintf(stderr,"authzXMLreader: <authz> not found - aborting\n");
    xmlFreeTextReader(reader);;
    xmlCleanupParser();
    xmlMemoryDump();
    return; 
  }
  
  ret = xmlTextReaderRead(reader);
  
  do {
    std::map <std::string,std::string> lauthz;
    
    //<file>
    ret = xmlTextReaderRead(reader);
    
    if ( std::string((char*)xmlTextReaderConstName(reader)) == std::string("authz")) {
      break;
    }
    
    if ((!ret) || ((xmlStrcmp(xmlTextReaderConstName(reader), (const xmlChar*) "file")))) {
      fprintf(stderr,"authzXMLreader: begin <file> not found - %s aborting\n",(char*)xmlTextReaderConstName(reader));
      xmlFreeTextReader(reader);;
      xmlCleanupParser();
      xmlMemoryDump();
      return;
    }  
    
    ret = xmlTextReaderRead(reader);
    if (!ret) {
      fprintf(stderr,"authzXMLreader: begin <file> error - aborting\n");
      xmlFreeTextReader(reader);;
      xmlCleanupParser();
      xmlMemoryDump();
      return ;
    }
    
    
    
    do {
      ret = xmlTextReaderRead(reader);
      //	  printf(":: %s\n",xmlTextReaderConstName(reader));
      if (!ret) {
	fprintf(stderr,"authzXMLreader: tag not found - aborting\n");
	xmlFreeTextReader(reader);;
	xmlCleanupParser();
	xmlMemoryDump();
	return;
      }
      
      std::string tag = std::string( (char*) (xmlTextReaderConstName(reader)));
      if (tag == std::string("authz")) {
	    break;
      }
      if (tag == std::string("file")) {
	break;
      }
      
      ret = xmlTextReaderRead(reader);
      if (!ret) {
	fprintf(stderr,"authzXMLreader: cannot find entry for tag %s\n",tag.c_str());
	fOK=false;
	xmlFreeTextReader(reader);;
	xmlCleanupParser();
	xmlMemoryDump();
	return;
      }

      // printf("%s: %d\n",(char*)xmlTextReaderConstName(reader),xmlTextReaderConstValue(reader));

      if (xmlTextReaderConstValue(reader)) {
	std::string value = std::string( (char*) (xmlTextReaderConstValue(reader)));
	
	// assign the value in a hashmap
	lauthz[tag.c_str()] = value;
	ret = xmlTextReaderRead(reader);
      }

      if (!ret) {
	fprintf(stderr,"authzXMLreader: cannot find terminate for tag %s\n",tag.c_str());
	fOK=false;
	xmlFreeTextReader(reader);;
	xmlCleanupParser();
	xmlMemoryDump();
	return;
      }
      std::string endtag = std::string( (char*) (xmlTextReaderConstName(reader)));
      ret = xmlTextReaderRead(reader);
      if (!ret) {
	fprintf(stderr,"authzXMLreader: cannot find terminate for tag %s\n",tag.c_str());
	fOK=false;
	xmlFreeTextReader(reader);;
	xmlCleanupParser();
	xmlMemoryDump();
	return;
      } 
      if (( endtag != tag)) {
	fprintf(stderr,"authzXMLreader: cannot find end sectionfor tag %s\n",tag.c_str());
	xmlFreeTextReader(reader);;
	xmlCleanupParser();
	xmlMemoryDump();
	return;
      }
      
    } while (ret); // loop inside <file>
    
    if ((!ret) || ((xmlStrcmp(xmlTextReaderConstName(reader), (const xmlChar*) "file")))) {
      fprintf(stderr,"authzXMLreader: <file> not found - aborting\n");
      xmlFreeTextReader(reader);;
      xmlCleanupParser();
      xmlMemoryDump();
      return;
    }  
    ret = xmlTextReaderRead(reader);
    if ((!ret)) {
      fprintf(stderr,"authzXMLreader: <file> not found - aborting\n");
      xmlFreeTextReader(reader);;
      xmlCleanupParser();
      xmlMemoryDump();
      return;
    }  
    
    fAuthz[lauthz["lfn"].c_str()] = lauthz;
    fAuthz[lauthz["pfn"].c_str()] = lauthz;

    // add another map value from the condensed guid
    if (lauthz["guid"].c_str()) {
      // condense the guid repesentation
      char condensedguid[33];
      int guidlen = lauthz["guid"].length();
      int digit=0;
      for (int i=0; i< guidlen; i++) {
	const char* c = lauthz["guid"].c_str()+i;
	if (*c == '-') 
	  continue;
	if (digit > 32) 
	  break;
	condensedguid[digit] = tolower(*c);
	digit++;
      }
      if (digit == 32) {
	condensedguid[32]= 0;
	fAuthz[condensedguid] = lauthz;
      }
    }
  } while (ret); // loop inside <authz>
  fOK=true;

  xmlFreeTextReader(reader);
  xmlCleanupParser();
  xmlMemoryDump();
}

TAuthzXMLreader::~TAuthzXMLreader() {
 
}


#ifdef __MAIN__
int main(int argc, char* argv[]) {
  char* buffer = (char*) malloc(1024*1024);
  if (!buffer) {
    exit(-1);
  }

  if (argc != 2) {
    fprintf(stderr,"usage: <prog> <xml-file>\n");
    exit(-1);
  }

  int fd = open(argv[1],O_RDONLY);
  if (fd>=0) {
    printf("Reading ...\n");
    int nread= read(fd, buffer, 1024*1024);
    if (nread<0) {
      fprintf(stderr,"READ error\n");
      exit(-1);
    }
    buffer[nread]=0;
    printf("%s\n",buffer);
    TAuthzXMLreader* authz = new TAuthzXMLreader(buffer);
    authz->Print();
    close(fd);
  } else {
    fprintf(stderr,"Cannot read xml file %s\n",argv[1]);
  }
  
  //  printf("turl %s \n",authz->GetKey(argv[1],"turl"));
}
    
#endif

