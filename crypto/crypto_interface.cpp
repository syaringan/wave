/*************************************************************************
    > File Name: crypto_interface.cpp
    > Author: 付鹏飞
 ************************************************************************/
#include "crypto_interface.h"
#include <assert.h>
#include <iostream>
#include <sstream>

using std::stringstream;
using std::cout;
using std::endl;
using std::cerr;
#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;

#include "cryptopp/pubkey.h"
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;



using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECIES;
using CryptoPP::EC2N;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;
#include "cryptopp/pubkey.h"
using CryptoPP::DL_PrivateKey_EC;
using CryptoPP::DL_PublicKey_EC;


#include "cryptopp/asn.h"
#include "cryptopp/oids.h"
using CryptoPP::OID;

#include "cryptopp/cryptlib.h"
using CryptoPP::PK_Encryptor;
using CryptoPP::PK_Decryptor;
using CryptoPP::g_nullNameValuePairs;
using CryptoPP::Exception;

#include "cryptopp/hmac.h"
using CryptoPP::HMAC;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA224;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;



#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/ccm.h"
using CryptoPP::CCM;

void StringToChar(string s, char* buf)
{
	int len = s.size();
	int i ;

	for(i = 0; i < len; i++)
		*(buf+i) = s[i];
	*(buf+len) = '\0';
}
void CharToString(string& s, char* buf, int len)
{
		s.clear();
		for(int i = 0; i < len; i++)
		{
			s.push_back(*(buf+i));
		}
}

char char_2_number(char* a)
{
    switch( a[0] )
    {
        case '0':
           return 0;
        case '1':
           return 1;
        case '2':
           return 2;
        case '3':
           return 3;
        case '4':
           return 4;
        case '5':
           return 5;
        case '6':
           return 6;
        case '7':
           return 7;
        case '8':
           return 8;
        case '9':
           return 9;
        case 'a':
           return 10;
        case 'A':
           return 10;
        case 'b':
           return 11;
        case 'B':
           return 11;
        case 'c':
           return 12;
        case 'C':
           return 12;
        case 'd':
           return 13;
        case 'D':
           return 13;
        case 'e':
           return 14;
        case 'E':
           return 14;
        case 'f':
           return 15;
        case 'F':
           return 15;
    }
}

int ECDSA_224_get_key( char* privatekey_buf, int* prlen, char* public_key_x_buf, int* xlen, char* public_key_y_buf, int* ylen)
{
    if(prlen[0] < 28)
    {
         cout<<" in ECDSA_224_get_key : the privatekey_buf's length is too short!!!"<<endl;
         return -2;
    }
    if( (xlen[0] < 28) || (ylen[0] < 28) )
    {
         cout<<" in ECDSA_224_get_key : the publickey_buf's length is too short!!!"<<endl;
         return -2;
    }

    AutoSeededRandomPool prng;

    ECDSA<ECP, SHA224>::PrivateKey privatekey;

    privatekey.Initialize( prng, CryptoPP::ASN1::secp224r1() );

    if( !privatekey.Validate( prng, 3 ) )
        return -1;


    string p0;
    privatekey.Save(StringSink(p0).Ref());

    //cout<<"产生的私钥为："<<std::hex<<p0<<endl;
    // cout<<"大小为"<<p0.size()<<endl;

    string s1;
    StringSource ss0(p0, true, new HexEncoder(new StringSink(s1)));
    //cout << "all things' length is " << s1.length() << " bytes" << endl;
    //cout << "  " << s1 << endl;

    int i = 0;
    int len = p0.length();
    int j = len - 28;
    for(i=0; i<28; i++)
        privatekey_buf[i] = p0[j++];
    *prlen = 28;

    //cout<<"prlen = "<<prlen[0]<<endl;


    ECDSA<ECP, SHA224>::PublicKey publickey;
    privatekey.MakePublicKey(publickey);
    if( !publickey.Validate( prng, 3 ) )
        return -1;



    string p1;
    publickey.Save(StringSink(p1).Ref());

    //cout<<"产生的公钥为："<<std::hex<<p1<<endl;
    //cout<<"大小为"<<p1.size()<<endl;

    string s2;
    StringSource ss1(p1, true, new HexEncoder(new StringSink(s2)));

    //cout << "all things' length is " << s2.length() << " bytes" << endl;
    //cout << "  " << s2 << endl;


    len = p1.length();
    j = len - 56;
    for(i=0; i<28; i++)
        public_key_x_buf[i] = p1[j++];
    j = len - 28;
    for(i=0; i<28; i++)
        public_key_y_buf[i] = p1[j++];
    *xlen = 28;
    *ylen = 28;



    /*  以下产生压缩后的公钥，用于获得前面的参数
    ECDSA<ECP, SHA224>::PublicKey compresskey;
    privatekey.MakePublicKey(compresskey);
    compresskey.AccessGroupParameters().SetPointCompression(true);

    string p2;
    compresskey.Save(StringSink(p2).Ref());
    cout<<"产生的compress key为："<<std::hex<<p2<<endl;
    cout<<"大小为"<<p2.size()<<endl;

    string s3;
    StringSource ss2(p2, true, new HexEncoder(new StringSink(s3)));
    cout << "all things' length is " << s3.length() << " bytes" << endl;
    cout << "  " << s3 << endl;
    */


    return 0;
}



int ECDSA_224_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                            char *public_key_y, int public_key_y_len,

                                            char *compress_key, int* compress_key_len,
                                            char *flag)
{

    if( (public_key_x_len< 28) || (public_key_y_len<28) )
    {
        cout << "in ECDSA_224_uncompress_key_2_compress_key : the input public_key is too short! the public_key is invalid!" << endl;
        return -1;
    }
    if( compress_key_len[0] < 28 ) 
    {
        cout << "in ECDSA_224_uncompress_key_2_compress_key : the output compress_key's buffer is too short!!" << endl;
        return -2;
    }


    unsigned char last_char = public_key_y[27];
    unsigned char tmp = last_char % 2;
    int i = 0;
    *flag = -1;
    if( tmp == 0 )
        *flag = 2;
    if( tmp == 1 )
        *flag = 3;
    for(i=0; i<28; i++)
        compress_key[i] = public_key_x[i];
    *compress_key_len = 28;
    return 0;
}



/*
 *old_flag是压缩公钥的flag,y为奇数时,old_flag应该等于3,y为偶数时,old_flag应该等于2
 *new_flag是解压后公钥的flag,无论如何,new_flag都等于4,因为未压缩时,flag等于4
 */
int ECDSA_224_compress_key_2_uncompress(char *compress_key, int compress_key_len,
                                        char old_flag, 

                                        char *public_key_x_buf, int* public_key_x_len,
                                        char *public_key_y_buf, int* public_key_y_len)
{
    if( (compress_key_len)< 28 )
    {
        cout << "in ECDSA_224_compress_key_2_uncompress: the input compress key is too short! it is invalid!!" << endl;
        return -1;
    } 
    if( ((*public_key_x_len)<28) || ((*public_key_y_len)<28) )
    {
        cout << "in ECDSA_224_compress_key_2_uncompress: the length of output uncompress_key's buffer is too short!" << endl;
        return -2;
    }

    AutoSeededRandomPool prng;
    int i = 0;
    int j = 0;

    char *c_key;
    c_key = (char *)malloc(29*sizeof(char));
    c_key[0] = old_flag;
    for(i=1; i<29; i++)
       c_key[i] = compress_key[i-1];
    i=0;
    j=0;
    string compresskey;
    CharToString(compresskey, c_key, 29);

    string parameters("3081DB3081B806072A8648CE3D02013081AC020101302806072A8648CE3D0101021D00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001303C041CFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE041CB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4041D02B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21021D00FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D020101031E00");

    char *pmt;
    pmt = (char *)malloc(386*sizeof(char));
    StringToChar(parameters, pmt);
    char *pm;
    pm = (char *)malloc(193*sizeof(char));
    j = 0;
    for(i=0; i<193; i++)
    {
        pm[i] = ( char_2_number(pmt+j)*16 ) + char_2_number(pmt+j+1);
        j = j + 2;
    }

    string parameters_;
    CharToString(parameters_, pm, 193);

    string parameters_and_compresskey;
    parameters_and_compresskey = parameters_ + compresskey;

    ECDSA<ECP, SHA224>::PublicKey publickey;
    publickey.AccessGroupParameters().SetPointCompression(true);
    publickey.Load(StringSource(parameters_and_compresskey, true).Ref());


    bool validate = publickey.Validate(prng, 3);

   if(validate == false)
   {
       //cout << "in ECDSA_224_compress_key_2_uncompress : the input uncompress key is invalid!!" << endl;
       return -1;
   }


    ECP::Point point = publickey.GetPublicElement();
    Integer y = point.y;

    string public_y;
    char *public_key_y;
    public_key_y = (char *)malloc(57*sizeof(char));      //是57而不是56的原因是最后一个字符会输出h,以代表16进制

    stringstream streamy;
    streamy << std::hex << y;
    streamy >> public_y;

    StringToChar(public_y, public_key_y);

    *public_key_x_len = 28;
    *public_key_y_len = 28;

    for(i=0; i<28; i++)
        public_key_x_buf[i] = compress_key[i];

    char *tmp;
    tmp = (char *)malloc(57*sizeof(char));
    j = 0;
    int len = (int)public_y.length();
    if( len < 57 )
    {
       for(i=0; i<57; i++)
            tmp[i] = public_key_y[i];
       j=0;
       for(i=57-len; i<57; i++)
            public_key_y[i] = tmp[j++];
       j=0;
       for(i=0; i<57-len; i++)
            public_key_y[i] = '0';
    }

    j = 0;
    for(i=0; i<28; i++)
    {
        public_key_y_buf[i] = ( char_2_number(public_key_y+j)*16 ) + char_2_number(public_key_y+j+1);
        j = j + 2;
    }

    free(c_key);
    free(pmt);
    free(pm);
    free(public_key_y);
    free(tmp);

    return 0;
}



int ECDSA_224_sign_message(char* private_key_buf, int prilen,
                           char* mess_buf, int mess_len,

			   char* r,int *r_len, 
                           char* s,int *s_len)
{
    if( prilen < 28 )
    {
         cout<<" in ECDSA_224_sign_message : the input private_key is too short, the private_key is invalid!!!"<<endl;
         return -1;
    }
    if( r_len[0] < 28 )
    {
         cout<<" in ECDSA_224_sign_message : the output r_len is too short !!!"<<endl;
         return -2;
    }
    if( s_len[0] < 28 )
    {
         cout<<" in ECDSA_224_sign_message : the output s_len is too short !!!"<<endl;
         return -2;
    }

    AutoSeededRandomPool prng;

    bool result = false;
    string message, signed_message;
    CharToString(message, mess_buf, mess_len);

    string privatekey_;
    CharToString(privatekey_, private_key_buf, prilen);

    string private_key;
    StringSource ss1(privatekey_, true, new HexEncoder(new StringSink(private_key)));
    private_key.push_back('h');

    Integer integer_privatekey;
    stringstream stream;
    stream << private_key;
    stream >> integer_privatekey;

    ECDSA<ECP, SHA224>::PrivateKey privatekey;

    result = false;
    privatekey.Initialize(prng, CryptoPP::ASN1::secp224r1());

    result = privatekey.Validate(prng, 3);
    if(!result)
        return -1;


    privatekey.SetPrivateExponent(integer_privatekey);

    result = false;
    StringSource(message, true,
		new SignerFilter(prng,
		ECDSA<ECP, SHA224>::Signer(privatekey),
		new StringSink(signed_message)
		)	//SignerFilter
		);  //StringSource
    result = !signed_message.empty();

    if(result == false)
	return -1;
    /*
    if((int)signed_message.length() >= signed_mess_len[0])
    {
         cout<<"in ECDSA_224_sign_message : signature's length is longer than the input signature's buf's length!!"<<endl;
         return -1;
    }
    */
    char* signed_mess_buf = (char*)malloc(56*sizeof(char));
    StringToChar(signed_message, signed_mess_buf);
    //*signed_mess_len = (int)signed_message.length();
    int i = 0;
    for(i=0; i<28; i++)
         r[i] = signed_mess_buf[i];
    r_len[0] = 28;
    int j = 28;
    for(i=0; i<28; i++)
         s[i] = signed_mess_buf[j++];
    s_len[0] = 28;

    return 0;
}


int ECDSA_224_verify_message(char* public_key_x_buf, int xlen,
                             char* public_key_y_buf, int ylen,
                             char* r,int r_len,
                             char* s,int s_len,
                             char* mess_buf, int mess_len)
{
    if( (xlen<28) || (ylen<28) )
    {
        cout << "in ECDSA_224_verify_message : the input public_key is too short! the input public_key is invalid!" << endl;
        return -1;
    }
    if( r_len < 28 )
    {
        cout << "in ECDSA_224_verify_message : the input r_len is too short!!" << endl;
        return -1;
    }
    if( s_len < 28 )
    {
        cout << "in ECDSA_224_verify_message : the input s_len is too short!!" << endl;
        return -1;
    }
/*
    if( signed_mess_len[0] < 56 )
    {
         cout<<" in ECDSA_224_verify_message : the input signature's length is too short!!!"<<endl;
         return -1;
    }
*/

    bool result = false;
    AutoSeededRandomPool prng;

    char* signed_mess_buf = (char*)malloc(56*sizeof(char));
    int i = 0;
    for(i=0; i<28; i++)
        signed_mess_buf[i] = r[i];
    int j = 28;
    for(i=0; i<28; i++)
        signed_mess_buf[j++] = s[i];
    int signed_mess_len = 56;

    string message, signed_message;
    CharToString(message, mess_buf, mess_len);
    CharToString(signed_message, signed_mess_buf, signed_mess_len);

    string public_key_xs, public_key_ys;
    CharToString(public_key_xs, public_key_x_buf, xlen);
    CharToString(public_key_ys, public_key_y_buf, ylen);

    string public_x;
    StringSource ss1(public_key_xs, true, new HexEncoder(new StringSink(public_x)));
    public_x.push_back('h');

    string public_y;
    StringSource ss2(public_key_ys, true, new HexEncoder(new StringSink(public_y)));
    public_y.push_back('h');

    Integer  integer_public_x;
    Integer  integer_public_y;

    stringstream streamx, streamy;
    streamx << public_x;
    streamx >> integer_public_x;

    streamy << public_y;
    streamy >> integer_public_y;

    ECP::Point q;
    q.identity = false;
    q.x = integer_public_x;
    q.y = integer_public_y;

    ECDSA<ECP, SHA224>::PublicKey publickey;
    publickey.Initialize(CryptoPP::ASN1::secp224r1(), q);
    result = publickey.Validate(prng, 3);
    if(!result)
    {
        //cout<<" in ECDSA_224_verify_message : public is invalid!!!"<<endl;
	return -1;
    }

    result = false;
    StringSource(signed_message + message, true,
		new SignatureVerificationFilter(
		ECDSA<ECP, SHA224>::Verifier(publickey),
		new ArraySink((byte*)&result, sizeof(result))
		) // SignatureVerificationFilter
		);

    if( result == false )
         return -1;
    if( result == true )
         return 0;
}



int ECDSA_224_FAST_sign_message(char* private_key_buf, int prilen,
                                char* mess_buf, int mess_len,

                                char* signed_R_x, int* signed_R_x_len,
                                char* signed_R_y, int* signed_R_y_len,
                                char* signed_S, int* signed_S_len)
{
    if( prilen < 28 )
    {
         cout<<" in ECDSA_224_FAST_sign_message : the input private_key is too short, the private_key is invalid!!!"<<endl;
         return -1;
    }
    if( (signed_R_x_len[0] < 28) || (signed_R_y_len[0] < 28) )
    {
         cout<<" in ECDSA_224_FAST_sign_message : the output signed_R's length is too short!!!"<<endl;
         return -2;
    }
    if(signed_S_len[0] < 28)
    {
         cout<<" in ECDSA_224_FAST_sign_message : the output signed_S's length is too short!!!"<<endl;
         return -2;
    }

    AutoSeededRandomPool prng;

    bool result = false;
    string message;
    CharToString(message, mess_buf, mess_len);

    string privatekey_;
    CharToString(privatekey_, private_key_buf, prilen);

    string private_key;
    StringSource ss1(privatekey_, true, new HexEncoder(new StringSink(private_key)));
    private_key.push_back('h');

    Integer integer_privatekey;
    stringstream streampk;
    streampk << private_key;
    streampk >> integer_privatekey;

    ECDSA<ECP, SHA224>::PrivateKey privatekey;

    result = false;
    privatekey.Initialize(prng, CryptoPP::ASN1::secp224r1());
    result = privatekey.Validate(prng, 3);
    if(!result)
        return -1;


    privatekey.SetPrivateExponent(integer_privatekey);

    result = false;
    //前面代码没有问题，是照搬过来的，只是转换message和private而已


    ECDSA<ECP, SHA224>::PrivateKey ephemeral_privatekey;
    ECDSA<ECP, SHA224>::PublicKey ephemeral_publickey;

    string nn("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    nn.push_back('h');

    CryptoPP::SHA224 hash;
    string digest;
    Integer k, xr, yr, r, n, e, kInv, s;

    stringstream streamn;
	streamn << nn;
	streamn >> n;

	stringstream stream;

    while(1)
    {
        while(1)
        {
            ephemeral_privatekey.Initialize(prng,CryptoPP::ASN1::secp224r1());

            if (ephemeral_privatekey.Validate(prng,3)==false)
            {
                 //cout<<"ephemeral_PrivateKey invalid"<<endl;
                 return -1;
            }

            ephemeral_privatekey.MakePublicKey(ephemeral_publickey);

            if (ephemeral_publickey.Validate(prng,3)==false)
            {
                 //cout<<"ephemeral_PublicKey invalid"<<endl;
                 return -1;
            }

            k = ephemeral_privatekey.GetPrivateExponent();

            xr = ephemeral_publickey.GetPublicElement().x;
	        yr = ephemeral_publickey.GetPublicElement().y;

	        r = xr % n;
	        if( r == 0 )
	             continue;
            else
                 break;
        }
        StringSource hhh(message, true, new CryptoPP::HashFilter(hash, new HexEncoder(new StringSink(digest))));
        digest.push_back('h');
        stream << digest;
        stream >> e;

        kInv = k.InverseMod(n);
        s = ( kInv * ( e + r*integer_privatekey ) ) % n;
        if( s == 0 )
            continue;
        else
        {
            assert(!!r && !!s);
            break;
        }
    }

    string R_x, R_y, ss;
    stringstream streamrx;
    streamrx << std::hex << xr;
    streamrx >> R_x;

    char *signed_Rx;
    signed_Rx = (char*)malloc(57*sizeof(char));
    StringToChar(R_x, signed_Rx);
    int i = 0;
    char *tmp;
    tmp = (char *)malloc(57*sizeof(char));
    int j = 0;
    int len = (int)R_x.length();
    if( len < 57 )
    {
        for(i=0; i<57; i++)
           tmp[i] = signed_Rx[i];
        j=0;
        for(i=57-len; i<57; i++)
           signed_Rx[i] = tmp[j++];
        j=0;
        for(i=0; i<57-len; i++)
           signed_Rx[i] = '0';
    }
    j = 0;
    for(i=0; i<28; i++)
    {
        signed_R_x[i] = ( (char_2_number(signed_Rx+j))*16 ) + ( (char_2_number(signed_Rx+j+1)) );
        j = j + 2;
    }
    signed_R_x_len[0] = 28;

//cout << "xr = "<<xr<<endl;
//cout << "R_x's length is "<<R_x.length()<<endl;
//cout << "R_x is "<<R_x<<endl;

    stringstream streamry;
    streamry << std::hex << yr;
    streamry >> R_y;

    char *signed_Ry;
    signed_Ry = (char*)malloc(57*sizeof(char));
    StringToChar(R_y, signed_Ry);
    i = 0;
    j = 0;
    len = (int)R_y.length();
    if( len < 57 )
    {
        for(i=0; i<57; i++)
           tmp[i] = signed_Ry[i];
        j=0;
        for(i=57-len; i<57; i++)
           signed_Ry[i] = tmp[j++];
        j=0;
        for(i=0; i<57-len; i++)
           signed_Ry[i] = '0';
    }
    j = 0;
    for(i=0; i<28; i++)
    {
        signed_R_y[i] = ( (char_2_number(signed_Ry+j))*16 ) + ( (char_2_number(signed_Ry+j+1)) );
        j = j + 2;
    }
    signed_R_y_len[0] = 28;


//cout << "R_y's length is "<<R_y.length()<<endl;
//cout << "R_y is "<<R_y<<endl;

    stringstream streamsss;
    streamsss << std::hex << s;
    streamsss >> ss;

    char *signed_Ss;
    signed_Ss = (char*)malloc(57*sizeof(char));
    StringToChar(ss, signed_Ss);
    i = 0;
    j = 0;
    len = (int)ss.length();
    if( len < 57 )
    {
        for(i=0; i<57; i++)
           tmp[i] = signed_Ss[i];
        j=0;
        for(i=57-len; i<57; i++)
           signed_Ss[i] = tmp[j++];
        j=0;
        for(i=0; i<57-len; i++)
           signed_Ss[i] = '0';
    }
    j = 0;
    for(i=0; i<28; i++)
    {
        signed_S[i] = ( (char_2_number(signed_Ss+j))*16 ) + ( (char_2_number(signed_Ss+j+1)) );
        j = j + 2;
    }
    signed_S_len[0] = 28;

//cout << "ss's length is "<<ss.length()<<endl;
//cout << "ss is "<<ss<<endl;

    return 0;

}



int ECDSA_224_FAST_verify_message(char* public_key_x_buf, int xlen,
                                  char* public_key_y_buf, int ylen,
                                  char* mess_buf, int mess_len,
                                  char* signed_R_x, int signed_R_x_len,
                                  char* signed_R_y, int signed_R_y_len,
                                  char* signed_S, int signed_S_len)
{
    if( (xlen<28) || (ylen<28) )
    {
        cout << "in ECDSA_224_FAST_verify_message : the input public_key is too short! it is invalid!!" << endl;
        return -1;
    }
    if( (signed_R_x_len < 28) || (signed_R_y_len < 28) )
    {
         cout<<" in ECDSA_224_FAST_verify_message : the input signed_R's length is too short!!!"<<endl;
         return -1;
    }
    if(signed_S_len < 28)
    {
         cout<<" in ECDSA_224_FAST_verify_message : the input signed_S's length is too short!!!"<<endl;
         return -1;
    }

    bool result = false;
    AutoSeededRandomPool prng;

    string nn("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    nn.push_back('h');
    stringstream streamn;
    Integer n;
	streamn << nn;
	streamn >> n;

    string message, signed_Rx, signed_Ry, signed_s;
    CharToString(message, mess_buf, mess_len);
    CharToString(signed_Rx, signed_R_x, signed_R_x_len);
    CharToString(signed_Ry, signed_R_y, signed_R_y_len);
    CharToString(signed_s, signed_S, signed_S_len);

    //恢复临时公钥，顺便将x和y点化为整数保存在Rx和Ry之中：
    string signed_Rx_, signed_Ry_, signed_s_;
    StringSource sss1(signed_Rx, true, new HexEncoder(new StringSink(signed_Rx_)));
    signed_Rx_.push_back('h');
    Integer Rx;
    stringstream streamRx;
    streamRx << signed_Rx_;
    streamRx >> Rx;

    StringSource sss2(signed_Ry, true, new HexEncoder(new StringSink(signed_Ry_)));
    signed_Ry_.push_back('h');
    Integer Ry;
    stringstream streamRy;
    streamRy << signed_Ry_;
    streamRy >> Ry;

    ECP::Point R;
    R.identity = false;
    R.x = Rx;
    R.y = Ry;

    result = false;
    ECDSA<ECP, SHA224>::PublicKey ephemeral_publickey;
    ephemeral_publickey.Initialize(CryptoPP::ASN1::secp224r1(), R);
    result = ephemeral_publickey.Validate(prng, 3);
    if(!result)
    {
        //cout<<" in ECDSA_224_FAST_verify_message : ephemeral_public is invalid!!!"<<endl;
	    return -1;
    }

    result = false;

    //将s恢复整数：
    StringSource sss3(signed_s, true, new HexEncoder(new StringSink(signed_s_)));
    signed_s_.push_back('h');
    Integer s;
    stringstream streams;
    streams << signed_s_;
    streams >> s;

    //恢复认证过程需要的发送方的公钥：
    string public_key_xs, public_key_ys;
    CharToString(public_key_xs, public_key_x_buf, xlen);
    CharToString(public_key_ys, public_key_y_buf, ylen);

    string public_x;
    StringSource ss1(public_key_xs, true, new HexEncoder(new StringSink(public_x)));
    public_x.push_back('h');

    string public_y;
    StringSource ss2(public_key_ys, true, new HexEncoder(new StringSink(public_y)));
    public_y.push_back('h');

    Integer  integer_public_x;
    Integer  integer_public_y;

    stringstream streamx, streamy;
    streamx << public_x;
    streamx >> integer_public_x;

    streamy << public_y;
    streamy >> integer_public_y;

    ECP::Point Q;
    Q.identity = false;
    Q.x = integer_public_x;
    Q.y = integer_public_y;

    ECDSA<ECP, SHA224>::PublicKey publickey;
    publickey.Initialize(CryptoPP::ASN1::secp224r1(), Q);
    result = publickey.Validate(prng, 3);
    if(!result)
    {
        //cout<<" in ECDSA_224_FAST_verify_message : public is invalid!!!"<<endl;
	    return -1;
    }

    result = false;
    //前面代码没有问题，是照搬过来的，只是转换message和private而已

    Integer e, r, sInv;
    stringstream stream;

    CryptoPP::SHA224 hash;
    string digest;
    StringSource hhh(message, true, new CryptoPP::HashFilter(hash, new HexEncoder(new StringSink(digest))));
    digest.push_back('h');
    stream << digest;
    stream >> e;

    r = Rx % n;


    //cout<<"~~~~~~~~~~~~~~~~~r = "<<std::hex<<r<<endl;

    if (r>=n || r<1 || s>=n || s<1)
    {
        //cout << "in ECDSA_224_FAST_verify_message : r or s is invalid!!!" << endl;
        return -1;
    }



    sInv = s.InverseMod(n);
    /*
    CryptoPP::RandomNumberGenerator rng;
    //Integer u(rng, 0, n-1, ANY, Zero(), One());   //用法可能不对啊
    Integer u(rng, 0, n-1);
    */

    /*
    CryptoPP::RandomNumberGenerator rng;
    Integer u;
    while(1)
    {
        Integer u0(rng, 224);
        if( u0 == 0 )
            continue;
        {
            u = u0;
            break;
        }
    }
    */


    string u_("B7FFDCBD6BB4BF121390B");
    u_.push_back('h');
    Integer u;
    stringstream streamu;
    streamu << u_;
    streamu >> u;



    //cout<<"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<endl;

    ECP::Point G;
    string G_x("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21");
    G_x.push_back('h');
    string G_y("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
    G_y.push_back('h');

    Integer  gx;
    Integer  gy;

    stringstream streamgx, streamgy;
    streamgx << G_x;
    streamgx >> gx;

    streamgy << G_y;
    streamgy >> gy;

    G.identity = false;
    G.x = gx;
    G.y = gy;

    string zero_("00000000000000000000000000000000000000000000000000000000");
    zero_.push_back('h');
    Integer zero;
    stringstream stream0;
    stream0 << zero_;
    stream0 >> zero;

    //cout<<"~~~~~~~~~~~~~~~~~zero = "<<std::hex<<zero<<endl;


    Integer p, a, b;
    string p_("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    p_.push_back('h');
    stringstream streamp;
    streamp << p_;
    streamp >> p;

    string a_("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    a_.push_back('h');
    stringstream streama;
    streama << a_;
    streama >> a;

    string b_("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    b_.push_back('h');
    stringstream streamb;
    streamb << b_;
    streamb >> b;

    ECP gfp(p, a, b);

    Integer t1 = (u*e*sInv)%n;
    Integer t2 = (u*r*sInv)%n;
    Integer t3 = u%n;
    ECP::Point tmp1 = gfp.ScalarMultiply(G, t1);     //用法可能不对哦
    ECP::Point tmp2 = gfp.ScalarMultiply(Q, t2);
    //ECP::Point tmp3 = gfp.ScalarMultiply(R, zero-u);
    ECP::Point tmp3 = gfp.ScalarMultiply(R, t3);
    ECP::Point tmp4 = gfp.Add(tmp1, tmp2);
    //ECP::Point tmp5 = gfp.Add(tmp4, tmp3);

    //Integer tmp5_x = tmp5.x;
    //Integer tmp5_y = tmp5.y;
    /*
    if( (tmp5_x == zero) || (tmp5_y == zero) )
         return 0;
    else
         return -1;
    */
    bool cmp_result = gfp.Equal(tmp3, tmp4);
    if( cmp_result == true )
        return 0;
    else
        return -1;
}




int ECDSA_256_get_key( char* privatekey_buf, int* prlen, char* public_key_x_buf, int* xlen, char* public_key_y_buf, int* ylen)
{
    if(prlen[0] < 32)
    {
         cout<<" in ECDSA_256_get_key : the output privatekey_buf's length is too short!!!"<<endl;
         return -2;
    }
    if( (xlen[0] < 32) || (ylen[0] < 32) )
    {
         cout<<" in ECDSA_256_get_key : the output publickey_buf's length is too short!!!"<<endl;
         return -2;
    }

    AutoSeededRandomPool prng;

    ECDSA<ECP, SHA256>::PrivateKey privatekey;

    privatekey.Initialize( prng, CryptoPP::ASN1::secp256r1() );

    if( !privatekey.Validate( prng, 3 ) )
        return -1;


    string p0;
    privatekey.Save(StringSink(p0).Ref());

    //cout<<"产生的私钥为："<<std::hex<<p0<<endl;
    //cout<<"大小为"<<p0.size()<<endl;

    string s1;
    StringSource ss0(p0, true, new HexEncoder(new StringSink(s1)));
    //cout << "all things' length is " << s1.length() << " bytes" << endl;
    //cout << "  " << s1 << endl;

    int i = 0;
    int len = p0.length();
    int j = len - 32;
    for(i=0; i<32; i++)
        privatekey_buf[i] = p0[j++];
    *prlen = 32;
    //cout<<"prlen = "<<prlen[0]<<endl;


    ECDSA<ECP, SHA256>::PublicKey publickey;
    privatekey.MakePublicKey(publickey);
    if( !publickey.Validate( prng, 3 ) )
        return -1;



    string p1;
    publickey.Save(StringSink(p1).Ref());

    //cout<<"产生的公钥为："<<std::hex<<p1<<endl;
    //cout<<"大小为"<<p1.size()<<endl;

    string s2;
    StringSource ss1(p1, true, new HexEncoder(new StringSink(s2)));
    //cout << "all things' length is " << s2.length() << " bytes" << endl;
    //cout << "  " << s2 << endl;


    len = p1.length();
    j = len - 64;
    for(i=0; i<32; i++)
        public_key_x_buf[i] = p1[j++];
    j = len - 32;
    for(i=0; i<32; i++)
        public_key_y_buf[i] = p1[j++];
    *xlen = 32;
    *ylen = 32;



    /*
    ECDSA<ECP, SHA256>::PublicKey compresskey;
    privatekey.MakePublicKey(compresskey);
    compresskey.AccessGroupParameters().SetPointCompression(true);

    string p2;
    compresskey.Save(StringSink(p2).Ref());
    cout<<"产生的compress key为："<<std::hex<<p2<<endl;
    cout<<"大小为"<<p2.size()<<endl;

    string s3;
    StringSource ss2(p2, true, new HexEncoder(new StringSink(s3)));
    cout << "all things' length is " << s3.length() << " bytes" << endl;
    cout << "  " << s3 << endl;
    */

    return 0;
}



int ECDSA_256_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                            char *public_key_y, int public_key_y_len,

                                            char *compress_key, int *compress_key_len,
                                            char *flag)
{

    if( (public_key_x_len< 32) || (public_key_y_len<32) )
    {
        cout << "in ECDSA_224_uncompress_key_2_compress_key : the input public_key_buf_len is too short! it is invalid!!" << endl;
        return -1;
    }
    if( (*compress_key_len)<32 )
    {
        cout << "in ECDSA_224_uncompress_key_2_compress_key : the output compress_key_buf_len is too short!!" << endl;
        return -2;
    }

    unsigned char last_char = public_key_y[31];
    unsigned char tmp = last_char % 2;
    int i = 0;
    *flag = -1;
    if( tmp == 0 )
        *flag = 2;
    if( tmp == 1 )
        *flag = 3;
    for(i=0; i<32; i++)
        compress_key[i] = public_key_x[i];
    *compress_key_len = 32;
    return 0;
}


int ECDSA_256_compress_key_2_uncompress(char *compress_key, int compress_key_len,
                                        char old_flag, 

                                        char *public_key_x_buf, int* public_key_x_len,
                                        char *public_key_y_buf, int* public_key_y_len)
{
    if( compress_key_len< 32 )
    {
        cout << "in ECDSA_256_compress_key_2_uncompress: the input compress_key_len is too short! it is invalid!!" << endl;
        return -1;
    }
    if( ((*public_key_x_len)<32) || ((*public_key_y_len)<32) )
    {
        cout << "in ECDSA_256_compress_key_2_uncompress: the output public_key_len is too short!" << endl;
        return -2;
    }

    AutoSeededRandomPool prng;
    int i = 0;
    int j = 0;

    char *c_key;
    c_key = (char *)malloc(33*sizeof(char));
    c_key[0] = old_flag;
    for(i=1; i<33; i++)
       c_key[i] = compress_key[i-1];
    i=0;
    j=0;
    string compresskey;
    CharToString(compresskey, c_key, 33);

    string parameters("3081F33081CC06072A8648CE3D02013081C0020101302C06072A8648CE3D0101022100FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF30440420FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC04205AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B0421036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296022100FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551020101032200");

    char *pmt;
    pmt = (char *)malloc(426*sizeof(char));
    StringToChar(parameters, pmt);
    char *pm;
    pm = (char *)malloc(213*sizeof(char));
    j = 0;
    for(i=0; i<213; i++)
    {
        pm[i] = ( char_2_number(pmt+j)*16 ) + char_2_number(pmt+j+1);
        j = j + 2;
    }

    string parameters_;
    CharToString(parameters_, pm, 213);

    string parameters_and_compresskey;
    parameters_and_compresskey = parameters_ + compresskey;

    ECDSA<ECP, SHA224>::PublicKey publickey;
    publickey.AccessGroupParameters().SetPointCompression(true);
    publickey.Load(StringSource(parameters_and_compresskey, true).Ref());
    publickey.Validate(prng, 3);
    if( !publickey.Validate( prng, 3 ) )
        return -1;

    ECP::Point point = publickey.GetPublicElement();
    Integer y = point.y;

    string public_y;
    char *public_key_y;
    public_key_y = (char *)malloc(65*sizeof(char));      //是57而不是56的原因是最后一个字符会输出h,以代表16进制

    stringstream streamy;
    streamy << std::hex << y;
    streamy >> public_y;

    StringToChar(public_y, public_key_y);

    *public_key_x_len = 32;
    *public_key_y_len = 32;

    for(i=0; i<32; i++)
        public_key_x_buf[i] = compress_key[i];

    char *tmp;
    tmp = (char *)malloc(65*sizeof(char));
    j = 0;
    int len = (int)public_y.length();
    if( len < 65 )
    {
       for(i=0; i<65; i++)
            tmp[i] = public_key_y[i];
       j=0;
       for(i=65-len; i<65; i++)
            public_key_y[i] = tmp[j++];
       j=0;
       for(i=0; i<65-len; i++)
            public_key_y[i] = '0';
    }

    j = 0;
    for(i=0; i<32; i++)
    {
        public_key_y_buf[i] = ( char_2_number(public_key_y+j)*16 ) + char_2_number(public_key_y+j+1);
        j = j + 2;
    }

    free(c_key);
    free(pmt);
    free(pm);
    free(public_key_y);
    free(tmp);

    return 0;
}


int ECDSA_256_sign_message(char* private_key_buf, int prilen,
                           char* mess_buf, int mess_len,

			   char* r, int* r_len,
                           char* s, int* s_len)
{
    if( prilen < 32 )
    {
         cout<<" in ECDSA_256_sign_message : the input private_key is too short, the private_key is invalid!!!"<<endl;
         return -1;
    }
    if( r_len[0] < 32 )
    {
         cout<<" in ECDSA_256_sign_message : the output r_len is too short!!!"<<endl;
         return -2;
    }
    if( s_len[0] < 32 )
    {
         cout<<" in ECDSA_256_sign_message : the output s_len is too short!!!"<<endl;
         return -2;
    }


    AutoSeededRandomPool prng;

    bool result = false;
    string message, signed_message;
    CharToString(message, mess_buf, mess_len);

    string privatekey_;
    CharToString(privatekey_, private_key_buf, prilen);

    string private_key;
    StringSource ss1(privatekey_, true, new HexEncoder(new StringSink(private_key)));
    private_key.push_back('h');

    Integer integer_privatekey;
    stringstream stream;
    stream << private_key;
    stream >> integer_privatekey;

    ECDSA<ECP, SHA256>::PrivateKey privatekey;

    result = false;
    privatekey.Initialize(prng, CryptoPP::ASN1::secp256r1());
    result = privatekey.Validate(prng, 3);
    if(!result)
        return -1;


    privatekey.SetPrivateExponent(integer_privatekey);

    result = false;
    StringSource(message, true,
		new SignerFilter(prng,
		ECDSA<ECP, SHA256>::Signer(privatekey),
		new StringSink(signed_message)
		)	//SignerFilter
		);  //StringSource
    result = !signed_message.empty();

    if(result == false)
	return -1;

    char* signed_mess_buf = (char*)malloc(64*sizeof(char));
    StringToChar(signed_message, signed_mess_buf);
    int i = 0;
    for(i=0; i<32; i++)
         r[i] = signed_mess_buf[i];
    r_len[0] = 32;
    int j = 32;
    for(i=0; i<32; i++)
         s[i] = signed_mess_buf[j++];
    s_len[0] = 32;

    return 0;
}


int ECDSA_256_verify_message(char* public_key_x_buf, int xlen,
                             char* public_key_y_buf, int ylen,
                             char* r, int r_len,
                             char* s, int s_len,
                             char* mess_buf, int mess_len)
{
    if( (xlen<32) || (ylen<32) )
    {
        cout << "in ECDSA_256_verify_message : the input public_key is too short! it is invalid!!" << endl;
        return -1;
    }
    if( r_len < 32 )
    {
        cout << "in ECDSA_256_verify_message : the input r_len is too short! it is invalid!!" << endl;
        return -1;
    }
    if( s_len < 32 )
    {
        cout << "in ECDSA_256_verify_message : the input s_len is too short! it is invalid!!" << endl;
        return -1;
    }

    bool result = false;
    AutoSeededRandomPool prng;

    char* signed_mess_buf = (char*)malloc(64*sizeof(char));
    int i = 0;
    for(i=0; i<32; i++)
        signed_mess_buf[i] = r[i];
    int j = 32;
    for(i=0; i<32; i++)
        signed_mess_buf[j++] = s[i];
    int signed_mess_len = 64;

    string message, signed_message;
    CharToString(message, mess_buf, mess_len);
    CharToString(signed_message, signed_mess_buf, signed_mess_len);

    string public_key_xs, public_key_ys;
    CharToString(public_key_xs, public_key_x_buf, xlen);
    CharToString(public_key_ys, public_key_y_buf, ylen);

    string public_x;
    StringSource ss1(public_key_xs, true, new HexEncoder(new StringSink(public_x)));
    public_x.push_back('h');

    string public_y;
    StringSource ss2(public_key_ys, true, new HexEncoder(new StringSink(public_y)));
    public_y.push_back('h');

    Integer  integer_public_x;
    Integer  integer_public_y;

    stringstream streamx, streamy;
    streamx << public_x;
    streamx >> integer_public_x;

    streamy << public_y;
    streamy >> integer_public_y;

    ECP::Point q;
    q.identity = false;
    q.x = integer_public_x;
    q.y = integer_public_y;

    result = false;
    ECDSA<ECP, SHA256>::PublicKey publickey;
    publickey.Initialize(CryptoPP::ASN1::secp256r1(), q);
    result = publickey.Validate(prng, 3);
    if(!result)
    {
        //cout<<" in ECDSA_256_verify_message : public is invalid!!!"<<endl;
	return -1;
    }

    result = false;
    StringSource(signed_message + message, true,
		new SignatureVerificationFilter(
		ECDSA<ECP, SHA256>::Verifier(publickey),
		new ArraySink((byte*)&result, sizeof(result))
		) // SignatureVerificationFilter
		);

    if( result == false )
         return -1;
    if( result == true )
         return 0;
}


int ECDSA_256_FAST_sign_message(char* private_key_buf, int prilen,
                                char* mess_buf, int mess_len,

                                char* signed_R_x, int* signed_R_x_len,
                                char* signed_R_y, int* signed_R_y_len,
                                char* signed_S, int* signed_S_len)
{
    if( prilen < 32 )
    {
         cout<<" in ECDSA_256_FAST_sign_message : the input private_key is too short, the private_key is invalid!!!"<<endl;
         return -1;
    }
    if( (signed_R_x_len[0] < 32) || (signed_R_y_len[0] < 32) )
    {
         cout<<" in ECDSA_256_FAST_sign_message : the output signed_R's length is too short!!!"<<endl;
         return -2;
    }
    if( signed_S_len[0] < 32 )
    {
         cout<<" in ECDSA_256_FAST_sign_message : the output signed_S's length is too short!!!"<<endl;
         return -2;
    }

    AutoSeededRandomPool prng;

    bool result = false;
    string message;
    CharToString(message, mess_buf, mess_len);

    string privatekey_;
    CharToString(privatekey_, private_key_buf, prilen);

    string private_key;
    StringSource ss1(privatekey_, true, new HexEncoder(new StringSink(private_key)));
    private_key.push_back('h');

    Integer integer_privatekey;
    stringstream streampk;
    streampk << private_key;
    streampk >> integer_privatekey;

    ECDSA<ECP, SHA256>::PrivateKey privatekey;

    result = false;
    privatekey.Initialize(prng, CryptoPP::ASN1::secp256r1());
    result = privatekey.Validate(prng, 3);
    if(!result)
        return -1;


    privatekey.SetPrivateExponent(integer_privatekey);

    result = false;
    //前面代码没有问题，是照搬过来的，只是转换message和private而已


    ECDSA<ECP, SHA256>::PrivateKey ephemeral_privatekey;
    ECDSA<ECP, SHA256>::PublicKey ephemeral_publickey;

    string nn("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    nn.push_back('h');

    CryptoPP::SHA256 hash;
    string digest;
    Integer k, xr, yr, r, n, e, kInv, s;

    stringstream streamn;
	streamn << nn;
	streamn >> n;

	stringstream stream;

    while(1)
    {
        while(1)
        {
            ephemeral_privatekey.Initialize(prng,CryptoPP::ASN1::secp256r1());

            if (ephemeral_privatekey.Validate(prng,3)==false)
            {
                 //cout<<"ephemeral_PrivateKey invalid"<<endl;
                 return -1;
            }

            ephemeral_privatekey.MakePublicKey(ephemeral_publickey);

            if (ephemeral_publickey.Validate(prng,3)==false)
            {
                 //cout<<"ephemeral_PublicKey invalid"<<endl;
                 return -1;
            }

            k = ephemeral_privatekey.GetPrivateExponent();

            xr = ephemeral_publickey.GetPublicElement().x;
	        yr = ephemeral_publickey.GetPublicElement().y;

	        r = xr % n;
	        if( r == 0 )
	             continue;
            else
                 break;
        }
        StringSource hhh(message, true, new CryptoPP::HashFilter(hash, new HexEncoder(new StringSink(digest))));
        digest.push_back('h');
        stream << digest;
        stream >> e;

        kInv = k.InverseMod(n);
        s = ( kInv * ( e + r*integer_privatekey ) ) % n;
        if( s == 0 )
            continue;
        else
        {
            break;
        }
    }

    string R_x, R_y, ss;
    stringstream streamrx;
    streamrx << std::hex << xr;
    streamrx >> R_x;

    char *signed_Rx;
    signed_Rx = (char*)malloc(65*sizeof(char));
    StringToChar(R_x, signed_Rx);
    int i = 0;
    char *tmp;
    tmp = (char *)malloc(65*sizeof(char));
    int j = 0;
    int len = (int)R_x.length();
    if( len < 65 )
    {
        for(i=0; i<65; i++)
           tmp[i] = signed_Rx[i];
        j=0;
        for(i=65-len; i<65; i++)
           signed_Rx[i] = tmp[j++];
        j=0;
        for(i=0; i<65-len; i++)
           signed_Rx[i] = '0';
    }
    j = 0;
    for(i=0; i<32; i++)
    {
        signed_R_x[i] = ( (char_2_number(signed_Rx+j))*16 ) + ( (char_2_number(signed_Rx+j+1)) );
        j = j + 2;
    }
    signed_R_x_len[0] = 32;

    //cout << "xr = "<<xr<<endl;
    //cout << "R_x's length is "<<R_x.length()<<endl;
    //cout << "R_x is "<<R_x<<endl;

    stringstream streamry;
    streamry << std::hex << yr;
    streamry >> R_y;

    char *signed_Ry;
    signed_Ry = (char*)malloc(65*sizeof(char));
    StringToChar(R_y, signed_Ry);
    i = 0;
    j = 0;
    len = (int)R_y.length();
    if( len < 65 )
    {
        for(i=0; i<65; i++)
           tmp[i] = signed_Ry[i];
        j=0;
        for(i=65-len; i<65; i++)
           signed_Ry[i] = tmp[j++];
        j=0;
        for(i=0; i<65-len; i++)
           signed_Ry[i] = '0';
    }
    j = 0;
    for(i=0; i<32; i++)
    {
        signed_R_y[i] = ( (char_2_number(signed_Ry+j))*16 ) + ( (char_2_number(signed_Ry+j+1)) );
        j = j + 2;
    }
    signed_R_y_len[0] = 32;


    //cout << "R_y's length is "<<R_y.length()<<endl;
    //cout << "R_y is "<<R_y<<endl;

    stringstream streamsss;
    streamsss << std::hex << s;
    streamsss >> ss;

    char *signed_Ss;
    signed_Ss = (char*)malloc(65*sizeof(char));
    StringToChar(ss, signed_Ss);
    i = 0;
    j = 0;
    len = (int)ss.length();
    if( len < 65 )
    {
        for(i=0; i<65; i++)
           tmp[i] = signed_Ss[i];
        j=0;
        for(i=65-len; i<65; i++)
           signed_Ss[i] = tmp[j++];
        j=0;
        for(i=0; i<65-len; i++)
           signed_Ss[i] = '0';
    }
    j = 0;
    for(i=0; i<32; i++)
    {
        signed_S[i] = ( (char_2_number(signed_Ss+j))*16 ) + ( (char_2_number(signed_Ss+j+1)) );
        j = j + 2;
    }
    signed_S_len[0] = 32;

    //cout << "ss's length is "<<ss.length()<<endl;
    //cout << "ss is "<<ss<<endl;

    return 0;

}


int ECDSA_256_FAST_verify_message(char* public_key_x_buf, int xlen,
                                  char* public_key_y_buf, int ylen,
                                  char* mess_buf, int mess_len,
                                  char* signed_R_x, int signed_R_x_len,
                                  char* signed_R_y, int signed_R_y_len,
                                  char* signed_S, int signed_S_len)
{
    if( (xlen<32) || (ylen<32) )
    {
        cout << "in ECDSA_256_FAST_verify_message : the input public_key is too short! it is invalid!!" << endl;
        return -1;
    }
    if( (signed_R_x_len < 32) || (signed_R_y_len < 32) )
    {
         cout<<" in ECDSA_256_FAST_verify_message : the input signed_R's length is too short!!!"<<endl;
         return -1;
    }
    if( signed_S_len < 32 )
    {
         cout<<" in ECDSA_256_FAST_verify_message : the input signed_S's length is too short!!!"<<endl;
         return -1;
    }

    bool result = false;
    AutoSeededRandomPool prng;

    string nn("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    nn.push_back('h');
    stringstream streamn;
    Integer n;
	streamn << nn;
	streamn >> n;

    string message, signed_Rx, signed_Ry, signed_s;
    CharToString(message, mess_buf, mess_len);
    CharToString(signed_Rx, signed_R_x, signed_R_x_len);
    CharToString(signed_Ry, signed_R_y, signed_R_y_len);
    CharToString(signed_s, signed_S, signed_S_len);

    //恢复临时公钥，顺便将x和y点化为整数保存在Rx和Ry之中：
    string signed_Rx_, signed_Ry_, signed_s_;
    StringSource sss1(signed_Rx, true, new HexEncoder(new StringSink(signed_Rx_)));
    signed_Rx_.push_back('h');
    Integer Rx;
    stringstream streamRx;
    streamRx << signed_Rx_;
    streamRx >> Rx;

    StringSource sss2(signed_Ry, true, new HexEncoder(new StringSink(signed_Ry_)));
    signed_Ry_.push_back('h');
    Integer Ry;
    stringstream streamRy;
    streamRy << signed_Ry_;
    streamRy >> Ry;

    ECP::Point R;
    R.identity = false;
    R.x = Rx;
    R.y = Ry;

    result = false;
    ECDSA<ECP, SHA256>::PublicKey ephemeral_publickey;
    ephemeral_publickey.Initialize(CryptoPP::ASN1::secp256r1(), R);
    result = ephemeral_publickey.Validate(prng, 3);
    if(!result)
    {
        //cout<<" in ECDSA_256_FAST_verify_message : ephemeral_public is invalid!!!"<<endl;
	    return -1;
    }

    //将s恢复整数：
    StringSource sss3(signed_s, true, new HexEncoder(new StringSink(signed_s_)));
    signed_s_.push_back('h');
    Integer s;
    stringstream streams;
    streams << signed_s_;
    streams >> s;

    //恢复认证过程需要的发送方的公钥：
    string public_key_xs, public_key_ys;
    CharToString(public_key_xs, public_key_x_buf, xlen);
    CharToString(public_key_ys, public_key_y_buf, ylen);

    string public_x;
    StringSource ss1(public_key_xs, true, new HexEncoder(new StringSink(public_x)));
    public_x.push_back('h');

    string public_y;
    StringSource ss2(public_key_ys, true, new HexEncoder(new StringSink(public_y)));
    public_y.push_back('h');

    Integer  integer_public_x;
    Integer  integer_public_y;

    stringstream streamx, streamy;
    streamx << public_x;
    streamx >> integer_public_x;

    streamy << public_y;
    streamy >> integer_public_y;

    ECP::Point Q;
    Q.identity = false;
    Q.x = integer_public_x;
    Q.y = integer_public_y;

    result = false;
    ECDSA<ECP, SHA256>::PublicKey publickey;
    publickey.Initialize(CryptoPP::ASN1::secp256r1(), Q);
    result = publickey.Validate(prng, 3);
    if(!result)
    {
        //cout<<" in ECDSA_256_FAST_verify_message : public is invalid!!!"<<endl;
	    return -1;
    }

    result = false;
    //前面代码没有问题，是照搬过来的，只是转换message和private而已

    Integer e, r, sInv;
    stringstream stream;

    CryptoPP::SHA256 hash;
    string digest;
    StringSource hhh(message, true, new CryptoPP::HashFilter(hash, new HexEncoder(new StringSink(digest))));
    digest.push_back('h');
    stream << digest;
    stream >> e;

    r = Rx % n;


    //cout<<"~~~~~~~~~~~~~~~~~r = "<<std::hex<<r<<endl;

    if (r>=n || r<1 || s>=n || s<1)
    {
        //cout << "in ECDSA_256_FAST_verify_message : r or s is invalid!!!" << endl;
        return -1;
    }



    sInv = s.InverseMod(n);

    /*
    CryptoPP::RandomNumberGenerator rng;
    //Integer u(rng, 0, n-1, ANY, Zero(), One());   //用法可能不对啊
    Integer u(rng, 0, n-1);
    */
    /*
    CryptoPP::RandomNumberGenerator rng;
    Integer u;
    while(1)
    {
        Integer u0(rng, 256);
        if( u0 == 0 )
            continue;
        else
        {
            u = u0;
            break;
        }
    }
    */


    string u_("B7FFDCBD6BB4BF121390B");
    u_.push_back('h');
    Integer u;
    stringstream streamu;
    streamu << u_;
    streamu >> u;



    //cout<<"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<endl;

    ECP::Point G;
    string G_x("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    G_x.push_back('h');
    string G_y("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    G_y.push_back('h');

    Integer  gx;
    Integer  gy;

    stringstream streamgx, streamgy;
    streamgx << G_x;
    streamgx >> gx;

    streamgy << G_y;
    streamgy >> gy;

    G.identity = false;
    G.x = gx;
    G.y = gy;

    string zero_("0000000000000000000000000000000000000000000000000000000000000000");
    zero_.push_back('h');
    Integer zero;
    stringstream stream0;
    stream0 << zero_;
    stream0 >> zero;

    //cout<<"~~~~~~~~~~~~~~~~~zero = "<<std::hex<<zero<<endl;


    Integer p, a, b;
    string p_("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    p_.push_back('h');
    stringstream streamp;
    streamp << p_;
    streamp >> p;

    string a_("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    a_.push_back('h');
    stringstream streama;
    streama << a_;
    streama >> a;

    string b_("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    b_.push_back('h');
    stringstream streamb;
    streamb << b_;
    streamb >> b;

    ECP gfp(p, a, b);

    Integer t1 = (u*e*sInv)%n;
    Integer t2 = (u*r*sInv)%n;
    Integer t3 = u%n;
    ECP::Point tmp1 = gfp.ScalarMultiply(G, t1);     //用法可能不对哦
    ECP::Point tmp2 = gfp.ScalarMultiply(Q, t2);
    //ECP::Point tmp3 = gfp.ScalarMultiply(R, zero-u);
    ECP::Point tmp3 = gfp.ScalarMultiply(R, t3);
    ECP::Point tmp4 = gfp.Add(tmp1, tmp2);
    //ECP::Point tmp5 = gfp.Add(tmp4, tmp3);

    //Integer tmp5_x = tmp5.x;
    //Integer tmp5_y = tmp5.y;
    /*
    if( (tmp5_x == zero) || (tmp5_y == zero) )
         return 0;
    else
         return -1;
    */

    bool cmp_result = gfp.Equal(tmp3, tmp4);
    if( cmp_result == true )
        return 0;
    else
        return -1;
}



/*
 *此函数用于通信的一方从另一方获得隐式证书后，提取出另一方的公钥（只有这一个功能！！）
 *
 *
 *从隐式证书中提取即恢复出（新的）公钥的函数：
 *参数e为隐式证书的散列值
 *
 *必须注意的一点是 证书计算散列值时，其中的所有公钥或者椭圆上的点都必须是以压缩形式输入散列函数的
 */
int cert_pk_extraction_SHA224(char* CA_public_key_x, int CA_public_key_x_len,
                              char* CA_public_key_y, int CA_public_key_y_len,
                              char* Pu_x, int Pu_x_len,
                              char* Pu_y, int Pu_y_len,
                              char* e, int e_len,

                              char* U_public_key_x, int* U_public_key_x_len,
                              char* U_public_key_y, int* U_public_key_y_len)
{
    if( (CA_public_key_x_len < 28 ) || (CA_public_key_y_len < 28) )
    {
        cout << "in cert_pk_extraction_SHA224 : the input CA_public_key_len is too short!!" << endl;
        return -1;
    }
    if( (Pu_x_len < 28) || (Pu_y_len < 28) )
    {
        cout << "in cert_pk_extraction_SHA224 : the input Pu_len is too short!!" << endl;
        return -1;
    }
    if( e_len < 32 )
    {
        cout << "in cert_pk_extraction_SHA224 : the input e_len is too short!!" << endl;
        return -1;
    }
    if( (U_public_key_x_len[0] < 28) || (U_public_key_y_len[0] < 28) )
    {
        cout << "in cert_pk_extraction_SHA224 : the output U_public_key_len is too short!!" << endl;
        return -2;
    }

    bool result = false;

    //cout << "the result is " << result << endl;

    AutoSeededRandomPool prng;

    string nn("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    nn.push_back('h');
    stringstream streamn;
    Integer n;
	streamn << nn;
	streamn >> n;

    //将CA的公钥转换成椭圆上的点Qca：
    Integer Qca_x;
    string stringQcax;
    CharToString(stringQcax, CA_public_key_x, CA_public_key_x_len);
    string stringqcax;
    StringSource ssqcax(stringQcax, true, new HexEncoder(new StringSink(stringqcax)));
    stringqcax.push_back('h');
    stringstream streamqcaxx;
    streamqcaxx << stringqcax;
    streamqcaxx >> Qca_x;

    Integer Qca_y;
    string stringQcay;
    CharToString(stringQcay, CA_public_key_y, CA_public_key_y_len);
    string stringqcay;
    StringSource ssqcay(stringQcay, true, new HexEncoder(new StringSink(stringqcay)));
    stringqcay.push_back('h');
    stringstream streamqcayy;
    streamqcayy << stringqcay;
    streamqcayy >> Qca_y;

    ECP::Point Qca;
    Qca.identity = false;
    Qca.x = Qca_x;
    Qca.y = Qca_y;

    //验证证书中包含的椭圆点Pu是否合法：
    Integer pu_x;
    string stringPux;
    CharToString(stringPux, Pu_x, Pu_x_len);
    string stringpux;
    StringSource sspux(stringPux, true, new HexEncoder(new StringSink(stringpux)));
    stringpux.push_back('h');
    stringstream streampuxx;

    //cout<<"~~~~~~~~stringpux is "<<stringpux<<endl;

    streampuxx << stringpux;
    streampuxx >> pu_x;

    Integer pu_y;
    string stringPuy;
    CharToString(stringPuy, Pu_y, Pu_y_len);
    string stringpuy;
    StringSource sspuy(stringPuy, true, new HexEncoder(new StringSink(stringpuy)));
    stringpuy.push_back('h');
    stringstream streampuyy;
    streampuyy << stringpuy;
    streampuyy >> pu_y;

    ECP::Point Pu;
    Pu.identity = false;
    Pu.x = pu_x;
    Pu.y = pu_y;

    result = false;
    ECDSA<ECP, SHA224>::PublicKey Pu_publickey;
    Pu_publickey.Initialize(CryptoPP::ASN1::secp224r1(), Pu);



    result = Pu_publickey.Validate(prng, 3);


    if(!result)
    {
        //cout<<" in cert_pk_extraction_SHA224 : Pu is invalid!!!"<<endl;
	    return -1;
    }


    //生成椭圆P_224的素数域:
    Integer p, a, b;
    string p_("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    p_.push_back('h');
    stringstream streamp;
    streamp << p_;
    streamp >> p;

    string a_("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    a_.push_back('h');
    stringstream streama;
    streama << a_;
    streama >> a;

    string b_("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    b_.push_back('h');
    stringstream streamb;
    streamb << b_;
    streamb >> b;

    ECP gfp(p, a, b);

    Integer E;
    string stringE;
    CharToString(stringE, e, e_len);
    string stringe;
    StringSource sse(stringE, true, new HexEncoder(new StringSink(stringe)));
    stringe.push_back('h');
    stringstream streamee;
    streamee << stringe;
    streamee >> E;




    ECP::Point tmp1 = gfp.ScalarMultiply(Pu, (E%n));   //注意!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!





    ECP::Point Qu = gfp.Add(tmp1, Qca);

    Integer qux = Qu.x;
    stringstream streamqqux;
    string tmpqux;
    streamqqux << std::hex << qux;
    streamqqux >> tmpqux;

    char* tmpqux_;
    tmpqux_ = (char*)malloc(57*sizeof(char));
    StringToChar(tmpqux, tmpqux_);
    int m = 0;
    int j = 0;
    int i = 0;
    int len = tmpqux.length();
    char* tmp_qux = (char*)malloc(57*sizeof(char));
    if( len < 57 )
    {
        for(i=0; i<57; i++)
           tmp_qux[i] = tmpqux_[i];
        j=0;
        for(i=57-len; i<57; i++)
           tmpqux_[i] = tmp_qux[j++];
        j=0;
        for(i=0; i<57-len; i++)
           tmpqux_[i] = '0';
    }
    j = 0;
    for(m=0; m<28; m++)
    {
        U_public_key_x[m] = ( (char_2_number(tmpqux_+j))*16 ) + ( (char_2_number(tmpqux_+j+1)) );
        j = j + 2;
    }
    U_public_key_x_len[0] = 28;

    Integer quy = Qu.y;
    stringstream streamqquy;
    string tmpquy;
    streamqquy << std::hex << quy;
    streamqquy >> tmpquy;
    char* tmpquy_;
    tmpquy_ = (char*)malloc(57*sizeof(char));
    StringToChar(tmpquy, tmpquy_);
    m = 0;
    j = 0;
    len = tmpquy.length();
    char* tmp_quy = (char*)malloc(57*sizeof(char));
    if( len < 57 )
    {
        for(i=0; i<57; i++)
           tmp_quy[i] = tmpquy_[i];
        j=0;
        for(i=57-len; i<57; i++)
           tmpquy_[i] = tmp_quy[j++];
        j=0;
        for(i=0; i<57-len; i++)
           tmpquy_[i] = '0';
    }
    j = 0;
    for(m=0; m<28; m++)
    {
        U_public_key_y[m] = ( (char_2_number(tmpquy_+j))*16 ) + ( (char_2_number(tmpquy_+j+1)) );
        j = j + 2;
    }
    U_public_key_y_len[0] = 28;

    free(tmpqux_);
    free(tmpquy_);

    return 0;
}



/*
 *此函数用来隐式证书申请者重建自己的私钥
 */
int cert_reception_SHA224(char* old_u_private_key, int old_u_private_key_len,
                          char* e, int e_len,
                          char* r, int r_len,

                          char* new_U_private_key, int* new_U_private_key_len)
{
    if( old_u_private_key_len < 28 )
    {
        cout << " in cert_reception_SHA224 : the input u_private_key_len is too short!!" << endl;
        return -1;
    }
    if( e_len < 32 )
    {
        cout << " in cert_reception_SHA224 : the input e_len is too short!!" << endl;
        return -1;
    }
    if( r_len < 28 )
    {
        cout << " in cert_reception_SHA224 : the input r_len is too short!!" << endl;
        return -1;
    }
    if( new_U_private_key_len[0] < 28 )
    {
        cout << " in cert_reception_SHA224 : the output new_U_private_key_len is too short!!" << endl;
        return -2;
    }

    string nn("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    nn.push_back('h');
    stringstream streamn;
    Integer n;
	streamn << nn;
	streamn >> n;


    //生成椭圆P_256的素数域:
    Integer p, a, b;
    string p_("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    p_.push_back('h');
    stringstream streamp;
    streamp << p_;
    streamp >> p;

    string a_("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    a_.push_back('h');
    stringstream streama;
    streama << a_;
    streama >> a;

    string b_("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    b_.push_back('h');
    stringstream streamb;
    streamb << b_;
    streamb >> b;

    ECP gfp(p, a, b);

    //生成椭圆P_256的基点G：
    ECP::Point G;
    string G_x("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21");
    G_x.push_back('h');
    string G_y("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
    G_y.push_back('h');

    Integer  gx;
    Integer  gy;

    stringstream streamgx, streamgy;
    streamgx << G_x;
    streamgx >> gx;

    streamgy << G_y;
    streamgy >> gy;

    G.identity = false;
    G.x = gx;
    G.y = gy;

    Integer E;
    string stringE;
    CharToString(stringE, e, e_len);
    string stringe;
    StringSource sse(stringE, true, new HexEncoder(new StringSink(stringe)));
    stringe.push_back('h');
    stringstream streamee;
    streamee << stringe;
    streamee >> E;

    Integer R;
    string stringR;
    CharToString(stringR, r, r_len);
    string stringr;
    StringSource ssr(stringR, true, new HexEncoder(new StringSink(stringr)));
    stringr.push_back('h');
    stringstream streamrr;

    streamrr << stringr;
    streamrr >> R;

    Integer ku;
    string stringKu;
    CharToString(stringKu, old_u_private_key, old_u_private_key_len);
    string stringku;
    StringSource ssku(stringKu, true, new HexEncoder(new StringSink(stringku)));
    stringku.push_back('h');
    stringstream streamku;

    streamku << stringku;
    streamku >> ku;

    Integer du = ( R + E*ku ) % n;

    char* tmp_new = (char*)malloc(57*sizeof(char));
    char* tmp_new_ = (char*)malloc(57*sizeof(char));
    int len = 0;
    int i = 0;
    int j = 0;
    int m = 0;
    stringstream new_privatekey;
    string new_private_key;
    new_privatekey << std::hex << du;
    new_privatekey >> new_private_key;
    StringToChar(new_private_key, tmp_new);
    len = new_private_key.length();
    if( len < 57 )
    {
        for(i=0; i<57; i++)
           tmp_new_[i] = tmp_new[i];
        j=0;
        for(i=57-len; i<57; i++)
           tmp_new[i] = tmp_new_[j++];
        j=0;
        for(i=0; i<57-len; i++)
           tmp_new[i] = '0';
    }
    j = 0;
    for(m=0; m<28; m++)
    {
        new_U_private_key[m] = ( (char_2_number(tmp_new+j))*16 ) + ( (char_2_number(tmp_new+j+1)) );
        j = j + 2;
    }
    new_U_private_key_len[0] = 28;

    return 0;
}




/*
 *此函数用于通信的一方从另一方获得隐式证书后，提取出另一方的公钥（只有这一个功能！！）
 *
 *
 *从隐式证书中提取即恢复出（新的）公钥的函数：
 *参数e为隐式证书的散列值
 *
 *必须注意的一点是 证书计算散列值时，其中的所有公钥或者椭圆上的点都必须是以压缩形式输入散列函数的
 */
int cert_pk_extraction_SHA256(char* CA_public_key_x, int CA_public_key_x_len,
                              char* CA_public_key_y, int CA_public_key_y_len,
                              char* Pu_x, int Pu_x_len,
                              char* Pu_y, int Pu_y_len,
                              char* e, int e_len,

                              char* U_public_key_x, int* U_public_key_x_len,
                              char* U_public_key_y, int* U_public_key_y_len)
{
    if( (CA_public_key_x_len < 32 ) || (CA_public_key_y_len < 32) )
    {
        cout << "in cert_pk_extraction_SHA256 : the input CA_public_key_len is too short!!" << endl;
        return -1;
    }
    if( (Pu_x_len < 32) || (Pu_y_len < 32) )
    {
        cout << "in cert_pk_extraction_SHA256 : the input Pu_len is too short!!" << endl;
        return -1;
    }
    if( e_len < 32 )
    {
        cout << "in cert_pk_extraction_SHA256 : the input e_len is too short!!" << endl;
        return -1;
    }
    if( (U_public_key_x_len[0] < 32) || (U_public_key_y_len[0] < 32) )
    {
        cout << "in cert_pk_extraction_SHA256 : the output U_public_key_len is too short!!" << endl;
        return -2;
    }

    bool result = false;

    AutoSeededRandomPool prng;

    string nn("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    nn.push_back('h');
    stringstream streamn;
    Integer n;
	streamn << nn;
	streamn >> n;

    //将CA的公钥转换成椭圆上的点Qca：
    Integer Qca_x;
    string stringQcax;
    CharToString(stringQcax, CA_public_key_x, CA_public_key_x_len);
    string stringqcax;
    StringSource ssqcax(stringQcax, true, new HexEncoder(new StringSink(stringqcax)));
    stringqcax.push_back('h');
    stringstream streamqcaxx;
    streamqcaxx << stringqcax;
    streamqcaxx >> Qca_x;

    Integer Qca_y;
    string stringQcay;
    CharToString(stringQcay, CA_public_key_y, CA_public_key_y_len);
    string stringqcay;
    StringSource ssqcay(stringQcay, true, new HexEncoder(new StringSink(stringqcay)));
    stringqcay.push_back('h');
    stringstream streamqcayy;
    streamqcayy << stringqcay;
    streamqcayy >> Qca_y;

    ECP::Point Qca;
    Qca.identity = false;
    Qca.x = Qca_x;
    Qca.y = Qca_y;

    //验证证书中包含的椭圆点Pu是否合法：
    Integer pu_x;
    string stringPux;
    CharToString(stringPux, Pu_x, Pu_x_len);
    string stringpux;
    StringSource sspux(stringPux, true, new HexEncoder(new StringSink(stringpux)));
    stringpux.push_back('h');
    stringstream streampuxx;
    streampuxx << stringpux;
    streampuxx >> pu_x;

    Integer pu_y;
    string stringPuy;
    CharToString(stringPuy, Pu_y, Pu_y_len);
    string stringpuy;
    StringSource sspuy(stringPuy, true, new HexEncoder(new StringSink(stringpuy)));
    stringpuy.push_back('h');
    stringstream streampuyy;
    streampuyy << stringpuy;
    streampuyy >> pu_y;

    ECP::Point Pu;
    Pu.identity = false;
    Pu.x = pu_x;
    Pu.y = pu_y;

    result = false;
    ECDSA<ECP, SHA256>::PublicKey Pu_publickey;
    Pu_publickey.Initialize(CryptoPP::ASN1::secp256r1(), Pu);



    result = Pu_publickey.Validate(prng, 3);


    if(!result)
    {
        //cout<<" in cert_pk_extraction_SHA256 : Pu is invalid!!!"<<endl;
	    return -1;
    }


    //生成椭圆P_256的素数域:
    Integer p, a, b;
    string p_("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    p_.push_back('h');
    stringstream streamp;
    streamp << p_;
    streamp >> p;

    string a_("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    a_.push_back('h');
    stringstream streama;
    streama << a_;
    streama >> a;

    string b_("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    b_.push_back('h');
    stringstream streamb;
    streamb << b_;
    streamb >> b;

    ECP gfp(p, a, b);

    Integer E;
    string stringE;
    CharToString(stringE, e, e_len);
    string stringe;
    StringSource sse(stringE, true, new HexEncoder(new StringSink(stringe)));
    stringe.push_back('h');
    stringstream streamee;
    streamee << stringe;
    streamee >> E;




    ECP::Point tmp1 = gfp.ScalarMultiply(Pu, (E%n));   //注意!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!





    ECP::Point Qu = gfp.Add(tmp1, Qca);

    Integer qux = Qu.x;
    stringstream streamqqux;
    string tmpqux;
    streamqqux << std::hex << qux;
    streamqqux >> tmpqux;

    char* tmpqux_;
    tmpqux_ = (char*)malloc(65*sizeof(char));
    StringToChar(tmpqux, tmpqux_);
    int m = 0;
    int j = 0;
    int i = 0;
    int len = tmpqux.length();
    char* tmp_qux = (char*)malloc(65*sizeof(char));
    if( len < 65 )
    {
        for(i=0; i<65; i++)
           tmp_qux[i] = tmpqux_[i];
        j=0;
        for(i=65-len; i<65; i++)
           tmpqux_[i] = tmp_qux[j++];
        j=0;
        for(i=0; i<65-len; i++)
           tmpqux_[i] = '0';
    }
    j = 0;
    for(m=0; m<32; m++)
    {
        U_public_key_x[m] = ( (char_2_number(tmpqux_+j))*16 ) + ( (char_2_number(tmpqux_+j+1)) );
        j = j + 2;
    }
    U_public_key_x_len[0] = 32;

    Integer quy = Qu.y;
    stringstream streamqquy;
    string tmpquy;
    streamqquy << std::hex << quy;
    streamqquy >> tmpquy;
    char* tmpquy_;
    tmpquy_ = (char*)malloc(65*sizeof(char));
    StringToChar(tmpquy, tmpquy_);
    m = 0;
    j = 0;
    len = tmpquy.length();
    char* tmp_quy = (char*)malloc(65*sizeof(char));
    if( len < 65 )
    {
        for(i=0; i<65; i++)
           tmp_quy[i] = tmpquy_[i];
        j=0;
        for(i=65-len; i<65; i++)
           tmpquy_[i] = tmp_quy[j++];
        j=0;
        for(i=0; i<65-len; i++)
           tmpquy_[i] = '0';
    }
    j = 0;
    for(m=0; m<32; m++)
    {
        U_public_key_y[m] = ( (char_2_number(tmpquy_+j))*16 ) + ( (char_2_number(tmpquy_+j+1)) );
        j = j + 2;
    }
    U_public_key_y_len[0] = 32;

    free(tmpqux_);
    free(tmp_qux);
    free(tmpquy_);
    free(tmp_qux);

    return 0;
}


/*
 *此函数用来隐式证书申请者重建自己的私钥
 */
int cert_reception_SHA256(char* old_u_private_key, int old_u_private_key_len,
                          char* e, int e_len,
                          char* r, int r_len,

                          char* new_U_private_key, int* new_U_private_key_len)
{
    if( old_u_private_key_len < 32 )
    {
        cout << " in cert_reception_SHA256 : the input u_private_key_len is too short!!" << endl;
        return -1;
    }
    if( e_len < 32 )
    {
        cout << " in cert_reception_SHA256 : the input e_len is too short!!" << endl;
        return -1;
    }
    if( r_len < 32 )
    {
        cout << " in cert_reception_SHA256 : the input r_len is too short!!" << endl;
        return -1;
    }
    if( new_U_private_key_len[0] < 32 )
    {
        cout << " in cert_reception_SHA256 : the output new_U_private_key_len is too short!! " << endl;
        return -2;
    }

    string nn("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    nn.push_back('h');
    stringstream streamn;
    Integer n;
	streamn << nn;
	streamn >> n;


    //生成椭圆P_256的素数域:
    Integer p, a, b;
    string p_("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    p_.push_back('h');
    stringstream streamp;
    streamp << p_;
    streamp >> p;

    string a_("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    a_.push_back('h');
    stringstream streama;
    streama << a_;
    streama >> a;

    string b_("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    b_.push_back('h');
    stringstream streamb;
    streamb << b_;
    streamb >> b;

    ECP gfp(p, a, b);

    //生成椭圆P_256的基点G：
    ECP::Point G;
    string G_x("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    G_x.push_back('h');
    string G_y("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    G_y.push_back('h');

    Integer  gx;
    Integer  gy;

    stringstream streamgx, streamgy;
    streamgx << G_x;
    streamgx >> gx;

    streamgy << G_y;
    streamgy >> gy;

    G.identity = false;
    G.x = gx;
    G.y = gy;

    Integer E;
    string stringE;
    CharToString(stringE, e, e_len);
    string stringe;
    StringSource sse(stringE, true, new HexEncoder(new StringSink(stringe)));
    stringe.push_back('h');
    stringstream streamee;
    streamee << stringe;
    streamee >> E;

    Integer R;
    string stringR;
    CharToString(stringR, r, r_len);
    string stringr;
    StringSource ssr(stringR, true, new HexEncoder(new StringSink(stringr)));
    stringr.push_back('h');
    stringstream streamrr;
    streamrr << stringr;
    streamrr >> R;

    Integer ku;
    string stringKu;
    CharToString(stringKu, old_u_private_key, old_u_private_key_len);
    string stringku;
    StringSource ssku(stringKu, true, new HexEncoder(new StringSink(stringku)));
    stringku.push_back('h');
    stringstream streamku;
    streamku << stringku;
    streamku >> ku;

    Integer du = ( R + E*ku ) % n;

    char* tmp_new = (char*)malloc(65*sizeof(char));
    char* tmp_new_ = (char*)malloc(65*sizeof(char));
    int len = 0;
    int i = 0;
    int j = 0;
    int m = 0;
    stringstream new_privatekey;
    string new_private_key;
    new_privatekey << std::hex << du;
    new_privatekey >> new_private_key;
    StringToChar(new_private_key, tmp_new);
    len = new_private_key.length();
    if( len < 65 )
    {
         for(i=0; i<65; i++)
            tmp_new_[i] = tmp_new[i];
         j=0;
         for(i=65-len; i<65; i++)
            tmp_new[i] = tmp_new_[j++];
         j=0;
         for(i=0; i<65-len; i++)
            tmp_new[i] = '0';
    }
    j = 0;
    for(m=0; m<32; m++)
    {
        new_U_private_key[m] = ( (char_2_number(tmp_new+j))*16 ) + ( (char_2_number(tmp_new+j+1)) );
        j = j + 2;
    }
    new_U_private_key_len[0] = 32;

    return 0;
}



//flag用来表明公钥的格式.未压缩是4,压缩且y是奇数,flag为3,压缩且y为偶数,flag为2.
int ECIES_get_key(char* private_key_buf, int* private_klen,
                  char *public_key_x_buf, int* public_key_x_len,
                  char *public_key_y_buf, int* public_key_y_len)
{
    if( (private_klen[0]<32) )
    {
        cout << "in ECIES_get_key: the output private_key_buf_len is too short!" << endl;
        return -2;
    }
    if( (public_key_x_len[0]<32) || (public_key_y_len[0]<32) )
    {
        cout << "in ECIES_get_key: the output public_key_buf_len is too short!" << endl;
        return -2;
    }

    AutoSeededRandomPool prng;

    ECIES<ECP>::PrivateKey privatekey;
    ECIES<ECP>::PublicKey publickey;

    privatekey.Initialize(prng,CryptoPP::ASN1::secp256r1());

    if (privatekey.Validate(prng,3)==false)
    {
         //cout<<"PrivateKey invalid"<<endl;
         return -1;
    }

    privatekey.MakePublicKey(publickey);

    if (publickey.Validate(prng,3)==false)
    {
         //cout<<"PublicKey invalid"<<endl;
         return -1;
    }

    string p0;
    privatekey.Save(StringSink(p0).Ref());

    //cout<<"产生的私钥为："<<std::hex<<p0<<endl;
    //cout<<"大小为"<<p0.size()<<endl;

    *private_klen = 32;

    string s1;
    StringSource ss0(p0, true, new HexEncoder(new StringSink(s1)));


    char *tmp;
    tmp = (char *)malloc(64*sizeof(char));
    int i = 0;
    int j = s1.length()-64;
    //cout<<"j="<<j<<endl;
    for(i =0; i<64; i++)
        tmp[i] = s1[j++];

    j = 0;
    for(i=0; i<32; i++)
    {
        private_key_buf[i] = ( (char_2_number(tmp+j))*16 ) + ( (char_2_number(tmp+j+1)) );
        j = j + 2;
    }


    string p1;
    publickey.Save(StringSink(p1).Ref());
    *public_key_x_len = 32;
    *public_key_y_len = 32;


    string s2;
    StringSource ss1(p1, true, new HexEncoder(new StringSink(s2)));
    //cout << "private key's length is " << s2.length() << " bytes" << endl;
    //cout << "  " << s2 << endl;

    char *tmp1;
    tmp1 = (char *)malloc(130*sizeof(char));
    i = 0;
    j = s2.length()-130;
    //cout<<"j="<<j<<endl;
    for(i =0; i<130; i++)
        tmp1[i] = s2[j++];


    for(i=0; i<32; i++)
        public_key_x_buf[i] = p1[p1.size()-64+i];

    j = 66;
    for(i=0; i<32; i++)
    {
        public_key_y_buf[i] = ( (char_2_number(tmp1+j))*16 ) + ( (char_2_number(tmp1+j+1)) );
        j = j + 2;
    }


    free(tmp);
    free(tmp1);

    return 0;
}




int ECIES_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                        char *public_key_y, int public_key_y_len,

                                        char *compress_key, int *compress_key_len,
                                        char *flag)
{

    if( (public_key_x_len< 32) || (public_key_y_len<32) )
    {
        cout << "in ECIES_uncompress_key_2_compress_key : the input public_key_buf_len is too short!" << endl;
        return -1;
    }
    if( (*compress_key_len) < 32 )
    {
        cout << "in ECIES_uncompress_key_2_compress_key : the output compress_key_buf_len is too short!" << endl;
        return -2;
    }

    unsigned char last_char = public_key_y[31];
    unsigned char tmp = last_char % 2;
    int i = 0;
    *flag = -1;
    if( tmp == 0 )
        *flag = 2;
    if( tmp == 1 )
        *flag = 3;
    for(i=0; i<32; i++)
        compress_key[i] = public_key_x[i];
    *compress_key_len = 32;
    return 0;
}





int ECIES_compress_key_2_uncompress(char *compress_key, int compress_key_len,
                                    char old_flag, 

                                    char *public_key_x_buf, int* public_key_x_len,
                                    char *public_key_y_buf, int* public_key_y_len)
{
    if( compress_key_len< 32 )
    {
        cout << "in ECIES_compress_key_2_uncompress: the input compress_key_len is too short!" << endl;
        return -1;
    }
    if( ((*public_key_x_len)<32) || ((*public_key_y_len)<32) )
    {
        cout << "in ECIES_compress_key_2_uncompress: the output public_key_len is too short!" << endl;
        return -2;
    }


    AutoSeededRandomPool prng;

    int i = 0;
    int j = 0;

    char *c_key;
    c_key = (char *)malloc(33*sizeof(char));
    c_key[0] = old_flag;
    for(i=1; i<33; i++)
        c_key[i] = compress_key[i-1];
    i=0;
    j=0;
    string compresskey;
    CharToString(compresskey, c_key, 33);


    string parameters("3081F33081CC06072A8648CE3D02013081C0020101302C06072A8648CE3D0101022100FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF30440420FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC04205AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B0421036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296022100FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551020101032200");

    char* pmt;
    pmt = (char *)malloc(426*sizeof(char));
    StringToChar(parameters, pmt);
    char* pm;
    pm = (char *)malloc(213*sizeof(char));
    j = 0;
    for(i=0; i<213; i++)
    {
        pm[i] = ( char_2_number(pmt+j)*16 ) + char_2_number(pmt+j+1);
        j = j + 2;
    }

    string parameters_;
    CharToString(parameters_, pm, 213);

    string parameters_and_compresskey;
    parameters_and_compresskey = parameters_ + compresskey;


    //string compresskey;
    //CharToString(compresskey, compress_key, 33);

    ECIES<ECP>::PublicKey publickey;
    //publickey.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256r1());
    publickey.AccessGroupParameters().SetPointCompression(true);
    publickey.Load(StringSource(parameters_and_compresskey, true).Ref());
    publickey.Validate(prng, 3);
    if (publickey.Validate(prng,3)==false)
    {
         //cout<<"PublicKey invalid"<<endl;
         return -1;
    }

    //string uncompresskey;


    ECP::Point point = publickey.GetPublicElement();
    Integer y = point.y;

    string public_y;
    char *public_key_y;
    public_key_y = (char *)malloc(65*sizeof(char));

    stringstream streamy;
    streamy << std::hex << y;
    streamy >> public_y;

    StringToChar(public_y, public_key_y);

    *public_key_x_len = 32;
    *public_key_y_len = 32;


    for(i=0; i<32; i++)
        public_key_x_buf[i] = compress_key[i];

    char *tmp;
    tmp = (char *)malloc(65*sizeof(char));
    j = 0;
    int len = (int)public_y.length();
    if( len < 65 )
    {
        for(i=0; i<65; i++)
           tmp[i] = public_key_y[i];
        j=0;
        for(i=65-len; i<65; i++)
           public_key_y[i] = tmp[j++];
        j=0;
        for(i=0; i<65-len; i++)
           public_key_y[i] = '0';
    }

    j = 0;
    for(i=0; i<32; i++)
    {
        public_key_y_buf[i] = ( char_2_number(public_key_y+j)*16 ) + char_2_number(public_key_y+j+1);
        j = j + 2;
    }


    free(c_key);
    free(pmt);
    free(pm);
    free(public_key_y);
    free(tmp);

    return 0;
}


//公钥加密，私钥解密
int ECIES_encrypto_message(char* mess_buf, int mess_len,
                           char* public_key_x_buf, int xlen,
                           char* public_key_y_buf, int ylen,

                           char* ephe_public_key_x, int* ephe_public_key_x_len,
                           char* ephe_public_key_y, int* ephe_public_key_y_len,
		           char* encrypto_mess_buf, int* encrypto_mess_len,
                           char* tag, int* tag_len)
{
        if( (xlen < 32) || (ylen <32) )
        {
             cout<<"in ECIES_encrypto_message : the input public_key_len is too short!!"<<endl;
             return -1;
        }
        if( (ephe_public_key_x_len[0] < 32) || (ephe_public_key_y_len[0] < 32) )
        {
             cout<<"in ECIES_encrypto_message : the output ephe_public_key_len is too short!!"<<endl;
             return -2;
        }
        if( encrypto_mess_len[0] < mess_len )
        {
             cout<<"in ECIES_encrypto_message : the output encrypto_mess_len is too short!!"<<endl;
             return -2;
        }
        if( tag_len[0] < 20 )
        {
             cout<<"in ECIES_encrypto_message : the output tag_len is too short!!"<<endl;
             return -2;
        }

	AutoSeededRandomPool prng;
	string message, encrypto_message;
	CharToString(message, mess_buf, mess_len);
	string public_key_x, public_key_y;
	CharToString(public_key_x, public_key_x_buf, xlen);
	CharToString(public_key_y, public_key_y_buf, ylen);

       string public_x;
       StringSource ss1(public_key_x, true, new HexEncoder(new StringSink(public_x)));
       public_x.push_back('h');
       //cout<<"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~public_x.length() is "<<public_x.length()<<endl;
       //cout<<"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~public_x is : "<<std::hex<<public_x<<endl;
       string public_y;
       StringSource ss2(public_key_y, true, new HexEncoder(new StringSink(public_y)));
       public_y.push_back('h');


       stringstream streamx, streamy;
       streamx << public_x;
       streamy << public_y;

       Integer pubx, puby;
       streamx >>pubx;
       streamy >>puby;

       ECP::Point q;
       q.identity = false;
       q.x = pubx;
       q.y = puby;


       try
       {
           ECIES<ECP>::Encryptor e0;
           e0.AccessKey().AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256r1());
           e0.AccessKey().SetPublicElement(q);

           e0.GetPublicKey().ThrowIfInvalid(prng, 3);
           string em0;
           StringSource ss3(message, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0)));

    
           //cout<<"加密数据为"<<std::hex<<em0<<endl;
        

           //cout<<"the length of em0 is "<<(int)(em0.length())<<endl;
           //printf("the length of em0 is %d\n",(int)em0.length() );
    

           int e_mess_len = em0.length();
           char* encrypto_mess = (char*)malloc(e_mess_len*sizeof(char));
           StringToChar(em0, encrypto_mess);


           //flag[0] = encrypto_mess[0];   现在不需要传参flag了
           int i = 0;
           int j = 1;
           for(i=0; i<32; i++)
           {
               ephe_public_key_x[i] = encrypto_mess[j];
               j++;
           }
           ephe_public_key_x_len[0] = 32;
           j = 33;
           for(i=0; i<32; i++)
           {
                ephe_public_key_y[i] = encrypto_mess[j];
                j++;
           }
           ephe_public_key_y_len[0] = 32;
           j = 65;
           for(i=0; i<mess_len; i++)
           {
                encrypto_mess_buf[i] = encrypto_mess[j];
                j++;
           }
           encrypto_mess_len[0] = mess_len;
           j = e_mess_len - 32;
           for(i=0; i<20; i++)
           {
                tag[i] = encrypto_mess[j];
                j++;
           }
           tag_len[0] = 20;
       }   
       catch( CryptoPP::InvalidArgument& e )
       {
           /*
           cerr << "Caught InvalidArgument..." << endl;
           cerr << e.what() << endl;
           cerr << endl;
           */
           return -1;
       }
       catch( CryptoPP::Exception& e )
       {
           /*
           cerr << "Caught Exception..." << endl;
           cerr << e.what() << endl;
           cerr << endl;
           */
           return -1;
       }

       return 0;

}


int ECIES_decrypto_message(char* encrypto_mess_buf, int encrypto_mess_len,
                           char* ephe_public_key_x, int ephe_public_key_x_len,
                           char* ephe_public_key_y, int ephe_public_key_y_len,
                           char* tag, int tag_len,
                           char* private_key_buf, int prilen,

		           char* decrypto_mess_buf, int* decrypto_mess_len)
{
        if( (ephe_public_key_x_len < 32) || (ephe_public_key_y_len < 32) )
        {
             cout<<"in ECIES_decrypto_message : the input ephe_public_key is too short!!"<<endl;
             return -1;
        }
        if( tag_len < 20 )
        {
             cout<<"in ECIES_decrypto_message : the input tag_key is too short!!"<<endl;
             return -1;
        }
        if( prilen < 32 )
        {
             cout<<"in ECIES_decrypto_message : the input private key is too short!!"<<endl;
             return -1;
        }
        if( decrypto_mess_len[0] < encrypto_mess_len )
        {
             cout<<"in ECIES_decrypto_message : the output decrypto_mess_len is too short!!"<<endl;
             return -2;
        }

	AutoSeededRandomPool prng;
	string s_private;

	CharToString(s_private, private_key_buf, prilen);


        string privatekey;
        StringSource ss1(s_private, true, new HexEncoder(new StringSink(privatekey)));
        privatekey.push_back('h');


	stringstream stream;
	Integer integer_private;
	stream << privatekey;
	stream >> integer_private;

	ECIES<ECP>::Decryptor d0;
	d0.AccessKey().AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256r1());
	d0.AccessKey().SetPrivateExponent(integer_private);

        int cipher_len = 1 + 32 + 32 + encrypto_mess_len + 32;         //特别注意的是最后加tag的长度是32,并不是真实的长度20
                                                                          //这是因为使用了库的接口所致,必须这么长,
                                                                          //但是库中也修改了,会只对比tag的前20字节,这点不用担心,指示这里必须32

        char* cipher = (char*)malloc( cipher_len *sizeof(char));
        int i = 0;
        int j = 1;
        cipher[0] = 4;       //不用flag似乎更好,因为这样保证至少在这一位是不出错的
        for(i=0; i<32; i++)
        {
             cipher[j] = ephe_public_key_x[i];
             j++;
        }
        j = 33;
        for(i=0; i<32; i++)
        {
             cipher[j] = ephe_public_key_y[i];
             j++;
        }
        j = 65;
        for(i=0; i<encrypto_mess_len; i++)
        {
            cipher[j] = encrypto_mess_buf[i];
            j++;
        }
        j = 65 + encrypto_mess_len;
        for(i=0; i<20; i++)
        {
            cipher[j] = tag[i];
            j++;
        }
        j = 65 + encrypto_mess_len + 20;
        for(i=0; i<12; i++)
        {
            cipher[j] = '0';
            j++;
        }



        //cout<<"the cipher is "<<cipher<<endl;
        //printf("the cipher is %s\n",cipher);
 

	string encrypto_mess;
	//CharToString(encrypto_mess, encrypto_mess_buf, encrypto_mess_len);
        CharToString(encrypto_mess, cipher, cipher_len);

        //cout<<"the encrypto_mess is "<<encrypto_mess<<endl;


	string dm;

        try
        {
	    d0.GetPrivateKey().ThrowIfInvalid(prng, 3);

	    StringSource ss2(encrypto_mess, true, new PK_DecryptorFilter(prng,
							d0, new StringSink(dm)));


	    if( ((int)dm.length() > decrypto_mess_len[0]) || ( (int)dm.length()!= encrypto_mess_len ) )
		return -1;

	    StringToChar(dm, decrypto_mess_buf);

	    decrypto_mess_len[0] = (int)dm.length();
        }
        catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
        {
            /*
            cerr << "Caught HashVerificationFailed..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            */
            return -1;
        }
        catch( CryptoPP::InvalidArgument& e )
        {
            /*
            cerr << "Caught InvalidArgument..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            */
            return -1;
        }
        catch( CryptoPP::Exception& e )
        {
            /*
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            */
            return -1;
        }

        free(cipher);

        return 0;
}



int sha_224(char* message, int message_len, char* digest, int* digest_len)
{
    if( digest_len[0] < 28 )
    {
        cout << "in Sha_256 : the input digest_len is too short !!" << endl;
        return -1;
    }

    CryptoPP::SHA224 hash;
    string s_message;
    CharToString(s_message, message, message_len);
    string s_digest;

    StringSource hhh(s_message, true, new CryptoPP::HashFilter(hash, new HexEncoder(new StringSink(s_digest))));


    //cout << "the length of digest is "<<s_digest.length()<<endl;
    //cout << "the digest is "<<s_digest<<endl;


    int len = (int)s_digest.length();

    char *digest_;
    digest_ = (char*)malloc(57*sizeof(char));
    StringToChar(s_digest, digest_);
    int i = 0;
    char *tmp;
    tmp = (char *)malloc(57*sizeof(char));
    int j = 0;
    if( len < 57 )
    {
        for(i=0; i<57; i++)
           tmp[i] = digest_[i];
        j=0;
        for(i=57-len; i<57; i++)
           digest_[i] = tmp[j++];
        j=0;
        for(i=0; i<57-len; i++)
           digest_[i] = '0';
    }
    j = 0;
    for(i=0; i<28; i++)
    {
        digest[i] = ( (char_2_number(digest_+j))*16 ) + ( (char_2_number(digest_+j+1)) );
        j = j + 2;
    }

    digest_len[0] = 28;

    return 0;
}



int sha_256(char* message, int message_len, char* digest, int* digest_len)
{
    if( digest_len[0] < 32 )
    {
        cout << "in Sha_256 : the input digest_len is too short !!" << endl;
        return -1;
    }

    CryptoPP::SHA256 hash;
    string s_message;
    CharToString(s_message, message, message_len);
    string s_digest;

    StringSource hhh(s_message, true, new CryptoPP::HashFilter(hash, new HexEncoder(new StringSink(s_digest))));


    //cout << "the length of digest is "<<s_digest.length()<<endl;
    //cout << "the digest is "<<s_digest<<endl;


    int len = (int)s_digest.length();

    char *digest_;
    digest_ = (char*)malloc(64*sizeof(char));
    StringToChar(s_digest, digest_);
    int i = 0;
    char *tmp;
    tmp = (char *)malloc(64*sizeof(char));
    int j = 0;
    if( len < 64 )
    {
        for(i=0; i<64; i++)
           tmp[i] = digest_[i];
        j=0;
        for(i=64-len; i<64; i++)
           digest_[i] = tmp[j++];
        j=0;
        for(i=0; i<64-len; i++)
           digest_[i] = '0';
    }
    j = 0;
    for(i=0; i<32; i++)
    {
        digest[i] = ( (char_2_number(digest_+j))*16 ) + ( (char_2_number(digest_+j+1)) );
        j = j + 2;
    }

    digest_len[0] = 32;

    return 0;
}



int AES_128_CCM_Get_Key_and_Nonce(char* sym_key, int* sym_key_len, char* nonce, int* nonce_len)
{
    if( (sym_key_len[0] < 16) || (nonce_len[0] < 12) )
    {
         cout<<"in AES_128_CCM_Get_Key_and_Nonce : the output sym_key_len or nonce_len is too short !!!"<<endl;
         return -2;
    }

    AutoSeededRandomPool prng;

    unsigned char key[ 16 ];
    prng.GenerateBlock( key, 16 );

    int i;
    for(i=0; i<16; i++)
         sym_key[i] = (char)key[i];

    //cout<<"the sym_key is "<<sym_key<<endl;

    byte iv[ 12 ];           //iv就是nonce，要求12字节
    prng.GenerateBlock( iv, 12 );
    for(i=0; i<12; i++)
        nonce[i] = iv[i];

    //cout<<"the iv in aes encrypt is "<<iv_output<<endl;

    *sym_key_len = 16;
    *nonce_len = 12;

    return 0;
}


int AES_128_CCM_encrypto_message(char* plaintext, int length_of_plaintext,
                                 char* sym_key, int sym_key_len,
                                 char* nonce, int nonce_len,

                                 char *ciphertext, int *length_of_ciphertext)
{
    if( (sym_key_len < 16) || (nonce_len < 12) )
    {
         cout<<"in  AES_128_CCM_encrypto_message : the input sym_key_len or nonce_len is too short !!!"<<endl;
         return -1;
    }


    AutoSeededRandomPool prng;

    const int TAG_SIZE = 16;    //tag长度设为128比特


    string cipher;        //加密后的密文ciphertext
    string pdata;        //接收的明文plaintext

    CharToString(pdata, plaintext, length_of_plaintext);

    if( length_of_ciphertext[0] < ((int)pdata.length() + 16) )
    {
         cout<<"in AES_128_CCM_encrypto_message : the output length_of_ciphertext is too short!!!"<<endl;
         return -2;
    }
    
    unsigned char symkey[16] = {0};
    unsigned char iv[12] = {0};
    int i = 0;
    for(i=0; i<16; i++)
        symkey[i] = (unsigned char)sym_key[i];
    for(i=0; i<12; i++)
        iv[i] = (unsigned char)nonce[i];

    try
    {
        CCM< AES, TAG_SIZE >::Encryption e;
        e.SetKeyWithIV( symkey, 16, iv, 12 );
        e.SpecifyDataLengths( 0, pdata.size(), 0 );

        StringSource ss1( pdata, true, new AuthenticatedEncryptionFilter( e, new StringSink( cipher )) );

        StringToChar(cipher, ciphertext);

        length_of_ciphertext[0] = cipher.length();

        //cout<<"the cipher is "<<cipher<<endl;
        //cout<<"the length of ciphertext is "<<cipher.size()<<endl;

    }
    catch( CryptoPP::InvalidArgument& e )
    {
        /*
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        */
        return -1;
    }
    catch( CryptoPP::Exception& e )
    {
        /*
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        */
        return -1;
    }
    return 0;
}


int AES_128_CCM_decrypto_message(char *ciphertext, int length_of_ciphertext,
                                 const char *sym_key, int sym_key_len,
                                 const char *nonce, int nonce_len,

                                 char *plaintext, int *length_of_plaintext)
{
    /*
    if( length_of_ciphertext[0] > length_of_plaintext[0] )
    {
         cout<<"in AES_128_CCM_decrypto_message : the length_of_ciphertext is too short!!!"<<endl;
         return -1;
    }
    */
    if( (sym_key_len < 16) || (nonce_len < 12) )
    {
         cout<<"in  AES_128_CCM_decrypto_message : the input sym_key_len or nonce_len is too short !!!"<<endl;
         return -1;
    }

    unsigned char key[ 16 ] = {0};
    int i;
    for(i=0;i<16;i++)
        key[i] = sym_key[i];

    byte iv[ 12 ];
    for(i=0;i<12;i++)
        iv[i] = nonce[i];

    const int TAG_SIZE = 16;    //tag长度设为128比特

    string cipher;
    string rpdata;     //解密后的原文

    if( length_of_plaintext[0] < ( (int)cipher.length() - 16 ) )
    {
         cout<<"in  AES_128_CCM_decrypto_message : the output length_of_plaintext is too short !!!"<<endl;
         return -2;
    }

    CharToString(cipher, ciphertext, length_of_ciphertext);

    try
    {
        CCM< AES, TAG_SIZE >::Decryption d;
        d.SetKeyWithIV( key, 16, iv, 12 );
        d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

        AuthenticatedDecryptionFilter df( d,new StringSink( rpdata ) );

        StringSource ss2( cipher, true, new Redirector( df ) );

        if( true == df.GetLastResult() )
        {
             StringToChar(rpdata, plaintext);
             *length_of_plaintext = rpdata.length();
        }
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        /*
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        */
        return -1;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        /*
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        */
        return -1;
    }
    catch( CryptoPP::Exception& e )
    {
        /*
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        */
        return -1;
    }
    return 0;
}


