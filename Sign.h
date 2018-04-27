#ifndef __SIGN_H__
#define __SIGN_H__

#include <algorithm>
#include <exception>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>
#include "transcode.h"
#include <string.h>
#include <sstream>
#include <iostream>


const int BufferSize = 2048; //at least the same as modulus
const int MaxBlockSize = 256;


namespace aux {
class md_ctx_free 
{
private:
  EVP_MD_CTX* ptr_;
public:
  md_ctx_free(EVP_MD_CTX* ptr) : ptr_(ptr) {} 
  void operator() () 
  { if(ptr_) 
      EVP_MD_CTX_free(ptr_); 
  }  
  
};

class evp_pkey_free
{
private:
  EVP_PKEY* ptr_;
public:
  evp_pkey_free(EVP_PKEY* ptr) : ptr_(ptr) {}
  void operator() ()
  {
    if(ptr_)
      EVP_PKEY_free(ptr_);
  }
};

} //namespace aux


class CSign
{
private:

  EVP_PKEY* m_pkey;
  EVP_MD_CTX *m_ctx;
  bool m_isSign;
public:
  CSign(EVP_PKEY *pKey, const EVP_MD *md, bool isSign);
   ~CSign() noexcept;
  CSign(const CSign&);
  CSign &operator= (const CSign&);
  void Reset(EVP_PKEY *pKey, const EVP_MD *md, bool isSign);
  void Update (const unsigned char* data, size_t datalen) ;
  void Update (const char *data, size_t datalen = 0)  ;//len == 0 means using strlen() to calculate the max length.
  void Update (const std::vector<unsigned char> &data) ;
  unsigned int Sign (unsigned char *sign) const;
  std::vector<unsigned char> Sign () const;
  int Verify (unsigned char *sign, int signlen) const;
  int Verify (std::vector<unsigned char> &signvec) const;

  unsigned int Hash_Sign (const unsigned char *data, size_t datalen, unsigned char* sign) ;
  std::vector<unsigned char> Hash_Sign (const unsigned char *data, size_t datalen) ;
  std::vector<unsigned char> Hash_Sign (const std::vector<unsigned char> &data) ;
  int Hash_Verify(const unsigned char *data, size_t datalen, unsigned char *sign, int signlen);
  int Hash_Verify(const std::vector<unsigned char> &data, std::vector<unsigned char> &sign);
  const bool IsSignMode() const { return m_isSign;}
  void Swap(CSign& ci);
  friend void swap(CSign& a, CSign& b)
  {
    a.Swap(b);
  }
 
};


#endif //~__SIGN_H__
