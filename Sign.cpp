#include "Sign.h"
#include "ScopeGuard.h"
#include <utility>
#include "error.h"

CSign::CSign(EVP_PKEY *pKey, const EVP_MD *md, bool isSign) : m_isSign(isSign)
{
  if(! EVP_PKEY_up_ref(pKey) )
  {
    std::string str("EVP_PKEY_up_ref() fail, in CSign::CSign(EVP_PKEY* pKey, bool isSign)!");
    throw SSLError(str);   
  }
  m_pkey = pKey;
  aux::evp_pkey_free pkey_free(m_pkey);
  aux::ScopeGuard pkey_gd(pkey_free);
  
  int type = EVP_PKEY_base_id(m_pkey);
  switch (type) {
    case EVP_PKEY_RSA:
      break;
    default :
      std::string str("Sorry, only RSA is supported so far!");
      throw Error(str);
  }
  
  if (!(m_ctx = EVP_MD_CTX_new()))
  {
    std::string str("EVP_MD_CTX_new() fail, in CSign::CSign(EVP_PKEY* pKey, bool isSign)!");
    throw SSLError(str);    
  }
  aux::md_ctx_free mctx_free(m_ctx);
  aux::ScopeGuard mctx_gd(mctx_free);

  if ( !(EVP_SignInit(m_ctx, md)) ) {
    std::string str("EVP_PKEY_up_ref() fail, in CSign::CSign(EVP_PKEY* pKey, bool isSign)!");
    throw SSLError(str);    
  }

  pkey_gd.dismiss();
  mctx_gd.dismiss();
}

CSign::CSign(const CSign& rhs)
{
  if (!EVP_MD_CTX_copy(m_ctx, rhs.m_ctx))
  {
    std::string str("EVP_MD_CTX_copy fail!");
    throw SSLError(str);
  }
  aux::md_ctx_free mctx_free(m_ctx);
  aux::ScopeGuard mctx_gd(mctx_free);

  if(! EVP_PKEY_up_ref(rhs.m_pkey) )
  {
    std::string str("EVP_PKEY_up_ref() fail, in CSign::CSign(const CSign& rhs)!");
    throw SSLError(str);   
  }
  m_pkey = rhs.m_pkey;
  m_isSign = rhs.m_isSign;

  mctx_gd.dismiss();
}

CSign &CSign::operator=(const CSign& other)
{
  CSign tmp(other);
  this->Swap(tmp);
  return *this;
}

CSign::~CSign()
{
  aux::md_ctx_free mctx_free(m_ctx);
  aux::ScopeGuard mctx_gd(mctx_free);
  aux::evp_pkey_free pkey_free(m_pkey);
  aux::ScopeGuard pkey_gd(pkey_free);
}

void CSign::Reset( EVP_PKEY *pKey, const EVP_MD *md, bool isSign)
{
  CSign tmp(pKey, md, isSign);
  Swap(tmp);
}

void CSign::Swap(CSign& rhs)
{
  using std::swap;
  swap(m_pkey, rhs.m_pkey);
  swap(m_ctx, rhs.m_ctx);//passing temporary object, try bind to a non-const lval 
  swap(m_isSign, rhs.m_isSign);
}

void CSign::Update(const std::vector<unsigned char> &data) 
{
  Update(reinterpret_cast<const unsigned char*> (&data.front()), data.size());
}

void CSign::Update(const char *data, size_t len) 
{
  if(!len)
    len = strlen(data);
  Update(reinterpret_cast<const unsigned char*> (data), len);
}

void CSign::Update(const unsigned char *data, size_t len) 
{
  if (! EVP_SignUpdate(m_ctx, data, len)) {
    std::string str("EVP_SignUpdate() fail, in CSign::Update(const unsigned char* data, size_t len)!");
    throw SSLError(str);      
  }
}

unsigned int CSign::Sign (unsigned char *sign) const
{
  if (!m_isSign) {
    std::string str("Sorry, the CSign object is now at verify mode!");
    throw Error(str);
  }
  unsigned int sign_len = 0;
  if (!EVP_SignFinal(m_ctx, sign, &sign_len, m_pkey)) {
    std::string str("EVP_SignFinal() fail, in CSign::Final(unsigned char* data, size_t len)!");
    throw SSLError(str);      
  }
  return sign_len;
}

std::vector<unsigned char> CSign::Sign() const
{
  if (!m_isSign) {
    std::string str("Sorry, the CSign object is now at verify mode!");
    throw Error(str);
  }
  std::vector<unsigned char> vec;
  int maxsize = EVP_PKEY_size(m_pkey);
  vec.resize(maxsize);
  int realsize = Sign(reinterpret_cast<unsigned char*>(&vec.front()));
  vec.resize(realsize);
  return vec;
}

int CSign::Verify (unsigned char *sign, int signlen) const
{
  if(m_isSign) {
    std::string str("Sorry, the CSign object is now at verify mode!");
    throw Error(str);
  }
  int ret = EVP_VerifyFinal(m_ctx, sign, signlen, m_pkey);
  if (ret == -1) {
    std::string str("EVP_VerifyFinal() fail, in CSign::Verify(unsigned char* sign, int signlen)!");
    throw SSLError(str);      
  }
  return ret;
}

int CSign::Verify (std::vector<unsigned char> &signvec) const
{
  return Verify(&signvec.front(), signvec.size());
}

unsigned int CSign::Hash_Sign(const unsigned char *data, size_t len, unsigned char *sign) 
{
  Update(data, len);
  return Sign(sign);
}

std::vector<unsigned char> CSign::Hash_Sign(const unsigned char *data, size_t len) 
{
  Update(data, len);
  return Sign();
}

std::vector<unsigned char> CSign::Hash_Sign(const std::vector<unsigned char> &data) 
{
  return Hash_Sign(reinterpret_cast<const unsigned char*> (&data.front()), data.size());
}

int CSign::Hash_Verify(const unsigned char *data, size_t datalen, unsigned char *sign, int signlen)
{
  Update(data, datalen);
  return Verify(sign, signlen);
}

int CSign::Hash_Verify(const std::vector<unsigned char> &data, std::vector<unsigned char> &sign) 
{
  return Hash_Verify(&data.front(), data.size(), &sign.front(), sign.size()); 
}
/*
namespace std {
  template<>
  void swap<CSign> (CSign& a, CSign& b)
  {
    a.Swap(b);
  }
  
}
*/

