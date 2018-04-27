#include "Sign.h"
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "ScopeGuard.h"
#include <algorithm>

void ShowHelpInfo()
{
  printf("Usage: siver [option]...\n\n");
  printf("-s/--sign (sign mode) \n");
  printf("-v/--verify (verify mode) \n");
  printf("-d/--digest (digest algorithom) you can choose[sha1|sha256|sha512], sha256 is default\n");
  printf("-k/--key (prikey for sign or pubkey for verify) pem or der format is fine\n");
  printf("-i/--input (data file) for sign or verify.txt\n");
  printf("-g/--signfile (sign file) it's output file in signmode, while input file in verifymode \n");
  printf("-f/--format (output/input format) [binary|hex|base64], binary is default\n");
  printf("-n/--nonewline (if format is hex or base64, then it'll not create a new line every-64-character!)");
  printf("-h/--help (show the help info)\n");
  printf("\n");
}

void ReadKey(EVP_PKEY **pkey, const char *key, bool isSign)
{
  FILE *fp_key = nullptr;
  if ((key == nullptr) || (pkey == nullptr))
  {
    throw Error(std::string("ReadKey:nullptr is inputed!"));
  }
  if (!(fp_key = fopen(key,"rb")))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024); 
    std::stringstream oss; 
    oss <<  "key file \"" << key << "\" open failed!\nerrno=" << errno << ", ErrMess:" << msg  << std::endl; 
    throw Error(oss.str());
  }
  aux::file_close fp_key_close(fp_key);
  aux::ScopeGuard fpkey_gd(fp_key_close);

  char line[256];
  memset(line,0,256);
  if (!fgets(line, sizeof(line), fp_key))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024); 
    std::stringstream oss; 
    oss <<  "key file \"" << key << "\" read failed!\nerrno=" << errno << ", ErrMess:" << msg  << std::endl; 
    throw Error(oss.str());
  }
  rewind(fp_key);
  if(isSign)
  {
    if (!strcmp(line, "-----BEGIN RSA PRIVATE KEY-----\n"))
    {  
      if (!(*pkey = PEM_read_PrivateKey(fp_key, nullptr, nullptr, nullptr)))
      {
        std::string str("ReadKey: PEM_read_PrivateKey() failed!");
        throw SSLError(str);
      }
    }
    else
    {
      if (!( *pkey = d2i_PrivateKey_fp(fp_key, nullptr)))
      {
        std::string str("ReadKey: d2i_RSAPrivateKey_fp() failed!");
        throw SSLError(str);
      }
    }
  }
  else
  {
    if (!strcmp(line, "-----BEGIN PUBLIC KEY-----\n"))
    {  
      if (!(*pkey = PEM_read_PUBKEY(fp_key, nullptr, nullptr, nullptr)))
      {
        std::string str("ReadKey: PEM_read_PUBKEY() failed!");
        throw SSLError(str);
      }
    }
    else
    {
      if (!( *pkey = d2i_PUBKEY_fp(fp_key, nullptr)))
      {
        std::string str("ReadKey: d2i_PUBKEY_fp() failed!");
        throw SSLError(str);
      }
    }
  }
 
}

void DoWork(CSign &ci, const char *input, const char *signfile, const char *format, bool with_new_line)
{
  if((input == nullptr) || (signfile == nullptr) || (format == nullptr))
    throw Error(std::string("DoWork:nullptr is inputed!"));
  FILE* fp_in = nullptr, *fp_sign = nullptr;
  unsigned char inbuf[BufferSize];
  unsigned char *outData = nullptr;
  int outlen = 0;
  int offset = 0;
  int readlen = 0;
  int writelen = 0;
  MODE mode = Binary;
  if(!strcmp(format, "binary"))
    mode = Binary;
  else if(!strcmp(format, "hex"))
    mode = Hex;
  else if(!strcmp(format, "base64"))
    mode = Base64;
  else
  {
    std::stringstream oss;
    oss << "CSign::Encrypt: Unknown format " << format;
    throw Error(oss.str());
  }
  if (!(fp_in = fopen(input, "rb")))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    std::stringstream oss;
    oss << "DoWork: file(" << input <<") open failed!\nerrno=" << errno <<", ErrMess:" << msg << std::endl;
    throw Error(oss.str());
  }
  aux::file_close fp_in_close(fp_in);
  aux::ScopeGuard fp_in_gd(fp_in_close);

  while(readlen = fread(inbuf, 1, BufferSize, fp_in))
  {
    ci.Update(inbuf, readlen);
  }

  if ( feof(fp_in) )
  {
    if(ci.IsSignMode())
    {
      std::vector<unsigned char> sign;
      sign = ci.Sign();
        
      std::vector<unsigned char> outvec;
      size_t outcount = 0;
      if(mode) 
      {
        TransCode(back_inserter(outvec), sign.begin(), sign.size(), outcount,  mode, 1, NULL, offset, with_new_line, 0);
        outData = &outvec.front();
        outlen = outcount;
      }
      else
      {
        outData = reinterpret_cast<unsigned char*> (&sign.front());
        outlen = sign.size();
      }

      if(outlen != 0)
      {
        if (signfile)
        {
          if (!(fp_sign = fopen(signfile, "wb")))
          {
            char errmsg[1024];
            char* msg = strerror_r(errno, errmsg, 1024);
            std::stringstream oss;
            oss << "DoWork: file(" << signfile <<") open failed!\nerrno=" << errno <<", ErrMess:" << msg << std::endl;
            throw Error(oss.str());
          }
          aux::file_close fp_sign_close(fp_sign);
          aux::ScopeGuard fp_sign_gd(fp_sign_close);
      
          if (!(writelen = fwrite(outData, 1, outlen, fp_sign)))
          {
            char errmsg[1024];
            char* msg = strerror_r(errno, errmsg, 1024);
            std::stringstream oss;
            oss << "DoWork: file(" << signfile <<") write failed!\nerrno=" << errno <<", ErrMess:" << msg << std::endl;
            throw Error(oss.str());
          }
        }
        else
          fwrite(outData, 1 ,outlen, stdout);
      }
    }
    else //Verify-Mode
    {
      int res = 0;
      if (!(fp_sign = fopen(signfile, "rb")))
      {
        char errmsg[1024];
        char* msg = strerror_r(errno, errmsg, 1024);
        std::stringstream oss;
        oss << "DoWork: file(" << signfile <<") open failed!\nerrno=" << errno <<", ErrMess:" << msg << std::endl;
        throw Error(oss.str());
      }
      aux::file_close fp_sign_close(fp_sign);
      aux::ScopeGuard fp_sign_gd(fp_sign_close);
       
      unsigned char signbuf[BufferSize];
      std::vector<unsigned char> outvec;
      size_t incount = 0;
      size_t size =0;
      while (readlen = fread(signbuf, 1, BufferSize, fp_sign))
      {
        if(mode) 
        {
          TransCode(back_inserter(outvec), signbuf, readlen, incount,  mode, 0, NULL, offset, with_new_line, 0);
        }
        else
        {
          size = outvec.size();
          outvec.resize(size + readlen);
          std::copy_n(signbuf, readlen, outvec.begin() + size);
        }
      }

      if (feof(fp_in))
      {
        res = ci.Verify(outvec);
        if (res)
        {
          std::cout << "Verify PASS!" << std::endl;
        }
        else
          std::cout << "Verify FAIL!" << std::endl;
      }
      else
      {
        char errmsg[1024];
        char* msg = strerror_r(errno, errmsg, 1024);
        std::stringstream oss;
        oss << "DoWork: file(" << signfile <<") read failed!\nerrno=" << errno <<", ErrMess:" << msg << std::endl;
        throw Error(oss.str());
      }
    }  // if(ci.IsSignMode())
  }
  else //  if ( feof(fp_in) )
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    std::stringstream oss;
    oss << "DoWork: file(" << input << ") read failed!\nerrno=" << errno << ", ErrMess:" << msg << std::endl;
    throw Error(oss.str());
  }
}


int main(int argc , char * argv[])
{

  int ret = 0;
  int c = 0;
  int option_index = 0;
  const char *digest = nullptr;
  const char *key = nullptr;
  const char *input = nullptr;
  const char *signfile = nullptr;
  const char *format = nullptr;
  bool with_new_line = true;
  bool isSign = true;
  const EVP_MD* md = nullptr;
  EVP_PKEY* pkey = nullptr;
  /**     
   *  定义命令行参数列表，option结构的含义如下（详见 man 3 getopt）：
   *  struct option {
   *      const char *name;      //参数的完整名称，对应命令中的 --xxx
   *      int  has_arg;   //该参数是否带有一个值，如 –config xxx.conf
   *      int *flag;      //一般设置为nullptr
   *      int  val;       //解析到该参数后getopt_long函数的返回值，为了方便维护，一般对应getopt_long调用时第三个参数
   *  };
   */
  unsigned char isSet = 0;
  static struct option arg_options[] =
  {
    {"sign", 0, nullptr, 's'},
    {"verify", 0, nullptr, 'v'},
    {"digest", 1, nullptr, 'd'},
    {"key", 1, nullptr, 'k'},
    {"input", 1, nullptr, 'i'},
    {"signfile", 1, nullptr, 'g'},
    {"format", 1, nullptr, 'f'},
    {"nonewline",0, nullptr,'n'},
    {"help", 0, nullptr, 'h'},
    {nullptr, 0, nullptr, 0}
  };

  /**
   *  注意：传递给getopt_long的第三个参数对应了命令行参数的缩写形式，如-h, -v, -c等，
   *  如果字符后面带有冒号，则说明该参数后跟一个值，如-c xxxxxx             
   */

  //begin with ':'，then when getopt() encounters an option with a missing argument, it returns ':'; otherwise, it
  //returns '?'
  while ((c = getopt_long(argc, argv, ":svd:k:i:g:f:nh", arg_options, &option_index)) != -1) 
  {
    switch (c) 
    {
    case 'h':
      ShowHelpInfo();
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      return 0;
    case 's':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      isSign = true;
      isSet |= 1;
      break;
    case 'v':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      isSign = false;
      isSet |= 2;
      break;
    case 'd':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      digest = optarg;
      break;
    case 'k':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      key = optarg;
      isSet |= 8;
      break;
    case 'i':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      input = optarg;
      isSet |= 16;
      break;
    case 'g':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      signfile = optarg;
      break;
    case 'f':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      format = optarg;
      break;
    case 'n':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      with_new_line = false;
      break;

    case '?':
      fprintf (stderr, "Unknown option -%c\n", optopt);
      ShowHelpInfo();
      return -1;
    case ':':
      fprintf (stderr, "Option -%c requires an argument\n", optopt);
      ShowHelpInfo();
      return -1;
    default:
      abort();  
    }
  }
  if ((isSet & 3) == 3)
  {
    fprintf (stderr, "you can not set -s(for sign) and -v(for verify) at the same time!\n");
    ShowHelpInfo();
    return -1;
  }  
  if ((isSet &  8) == 0)
  {
    fprintf (stderr, "lack of key file!\n");
    ShowHelpInfo();
    return -1;
  }
  if ((isSet & 16) == 0)
  {
    fprintf(stderr, "lack of input file!\n");
    ShowHelpInfo();
    return -1;
  } 
  if ((isSet & 2) && (signfile == nullptr))
  {
    fprintf(stderr, "sign file has to be inputed in verify-mode!\n");
    ShowHelpInfo();
    return -1;
  }

//default para
  if (digest == nullptr)
  { 
    fprintf (stdout, "default digest(sha256) is used!\n");
    digest = "sha256";
  }
  if (format == nullptr)
  { fprintf (stdout, "default format(binary) is used!\n");
    format = "binary";
  }
  if (signfile == nullptr)
  {
    char tmp[20];
    if(isSign)
      sprintf(tmp, "newfile.sign.%s", format);
    else
      sprintf(tmp, "newfile.verify.%s", format);
    signfile = tmp;
    printf("a new file \"%s\" is created!\n", signfile);
  }

  OpenSSL_add_all_algorithms();
  try
  {
    if (!strcmp(digest, "sha1"))
      md = EVP_sha1();
    else if (!strcmp(digest, "sha256"))
      md = EVP_sha256();
    else if (!strcmp(digest, "sha512"))
      md = EVP_sha512();
    else
    {
      fprintf (stderr, "Unknown digest algor: %s!\n", digest);
      ShowHelpInfo();
      return -1;
    }
    if (strcmp(format, "binary") && strcmp(format, "hex") && strcmp(format, "base64"))
    {
      fprintf (stderr, "Unknown formate: %s!\n", format);
      ShowHelpInfo();
      return -1;
    }
 
    ReadKey(&pkey, key, isSign);
    aux::evp_pkey_free pkey_free(pkey);
    aux::ScopeGuard pkey_gd(pkey_free);
   
    CSign si(pkey, md, isSign);
    DoWork(si, input, signfile, format, with_new_line);
   
    EVP_cleanup();
    return 0; 
  }
  catch (const std::exception  &e)
  {
    std::cout << e.what() << std::endl;
    EVP_cleanup();
    return -1;
 }
}


