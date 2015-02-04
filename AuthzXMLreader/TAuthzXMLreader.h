#include <map>
#include <string>

class TAuthzXMLreader {
 private:
    std::string fXML;
    bool fOK;
    std::map<std::string, std::map<std::string,std::string> > fAuthz;

 public:
    void Print();
    const char* GetKey(const char* lfn, const char* key) {
      if (!fOK) {
	return 0;
      }
      if (key) {
	return (fAuthz[lfn])[key].c_str();
      } else {
	return 0;
      }
    }

    bool OK() {
      return fOK;
    }

   
    TAuthzXMLreader(char* xmlbuffer);
    ~TAuthzXMLreader();
 };
