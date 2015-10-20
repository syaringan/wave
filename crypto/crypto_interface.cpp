/*=============================================================================
#
# Author: 杨广华 - edesale@qq.com
#
# QQ : 374970456
#
# Last modified: 2015-10-20 09:02
#
# Filename: crypto_interface.cpp
#
# Description: 
#
=============================================================================*/
#include "crypto_interface.h"
#include <assert.h>
#include <iostream>
#include <sstream>

using std::stringstream;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cryptopp/osrng.h>

using CryptoPP::AutoSeededRandomPool;
#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/sha.h>
using CryptoPP::SHA1;

#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include <cryptopp/eccrypto.h>
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include <cryptopp/oids.h>
using CryptoPP::OID;

void StringToChar(string s, char* buf)
{
	int len = s.length();
	int i ;

	for(i = 0; i < len; i++)
		*(buf+i) = s[i];
	*(buf+len) = '\0';
}

bool ECDSA_GeneratePrivateKey (const OID& oid, 
				ECDSA<ECP, SHA1>::PrivateKey& key)
{
	AutoSeededRandomPool prng;

	key.Initialize(prng, oid);
	assert(key.Validate(prng, 3));

	return key.Validate(prng, 3);
}

bool ECDSA_GeneratePublicKey(const ECDSA<ECP, SHA1>::PrivateKey& privateKey,
				ECDSA<ECP, SHA1>::PublicKey& publicKey)
{
	AutoSeededRandomPool prng;

	//Sanity check
	assert(privateKey.Validate(prng,3));

	privateKey.MakePublicKey(publicKey);
	assert(publicKey.Validate(prng, 3));

	return publicKey.Validate(prng, 3);
}
bool SignMessage(const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, 
			string& signature)
{
	AutoSeededRandomPool prng;

	signature.erase();

	StringSource(message, true,
		new SignerFilter(prng,
		ECDSA<ECP, SHA1>::Signer(key),
		new StringSink(signature)
		)	//SignerFilter
		);  //StringSource
	return !signature.empty();
}
bool VerifyMessage(const ECDSA<ECP, SHA1>::PublicKey& key, 
				const string& message, const string& signature)
{
	bool result = false;

	StringSource(signature + message, true,
		new SignatureVerificationFilter(
		ECDSA<ECP, SHA1>::Verifier(key),
		new ArraySink((byte*)&result, sizeof(result))
		) // SignatureVerificationFilter
		);

		return result;
}




int ECDSA_get_privatekey(char* privatekey_buf, int len)
{
	bool result = false;
	ECDSA<ECP, SHA1>::PrivateKey privatekey;
	ECDSA<ECP, SHA1>::PublicKey publickey;

	result = ECDSA_GeneratePrivateKey(CryptoPP::ASN1::secp256k1(), privatekey);
	assert(true == result);
	if(!result)	{return 0;}
	
	stringstream stream;
	string s_privatekey;
	stream << privatekey.GetPrivateExponent();
	stream >> s_privatekey;
	s_privatekey.erase(--s_privatekey.end());
	if((int)s_privatekey.length() >= len)
		return -1;
	//strcpy(privatekey_buf, s_privatekey.c_str());
	StringToChar(s_privatekey, privatekey_buf);
	return 1;
}


int ECDSA_get_publickey(char* public_key_x_buf, char* public_key_y_buf,
				int pulen, char* private_key_buf, int prlen)
{
	Integer Integer_privatekey;
	string s_privatekey;
	
	s_privatekey = private_key_buf;
	stringstream stream;
	stream << s_privatekey;
	stream >> Integer_privatekey;
	bool result = false;

	ECDSA<ECP, SHA1>::PrivateKey privateKey;
	ECDSA<ECP, SHA1>::PublicKey publicKey;

	result = ECDSA_GeneratePrivateKey(CryptoPP::ASN1::secp256k1(), privateKey);
	assert(true == result);
	if(!result) {return 0;}

	privateKey.SetPrivateExponent(Integer_privatekey);
	
	result = ECDSA_GeneratePublicKey(privateKey, publicKey);
	assert(true == result);
	if(!result)	{return 0;}
	stringstream streamx, streamy;
	string publickey_x, publickey_y;
	streamx << publicKey.GetPublicElement().x;
	streamy << publicKey.GetPublicElement().y;

	streamx >> publickey_x;
	streamy >> publickey_y;

	publickey_x.erase(--publickey_x.end());
	publickey_y.erase(--publickey_y.end());

	if((int)publickey_x.length()>= pulen)
		return -1;
	StringToChar(publickey_x, public_key_x_buf);
	cout<<"publc:"<<endl<<public_key_x_buf<<endl;

	if((int)publickey_y.length()>=  pulen)
		return -1;
	StringToChar(publickey_y, public_key_y_buf);
	cout<<"public"<<endl<<public_key_y_buf<<endl;
	return 1;
}


int ECDSA_sign_message(char* private_key_buf, int prlen, char* mess_buf, int mess_len,
				char* signed_mess_buf, int signed_mess_len)
{
	bool result = false;
	string message, signed_message;
	message = mess_buf;

	string s_private_key;
	Integer privatekey;
	stringstream stream;
	stream << s_private_key;
	stream >> privatekey;
	
	cout<<"privatekey:"<<endl;
	ECDSA<ECP, SHA1>::PrivateKey privateKey;
	//ECDSA<ECP, SHA1>::PublicKey publicKey;

	//result = ECDSA_GeneratePrivateKey(CryptoPP::ASN1::secp256k1(), privateKey);
	//result = ECDSA_GeneratePrivateKey(CryptoPP::ASN1::secp256k1(), privateKey);
	privateKey.Initialize(CryptoPP::ASN1::secp256k1, privatekey);
	//assert(true == result);
	//if(!result == result) {return 0;}
	
	//privateKey.SetPrivateExponent(privatekey);
	//result = ECDSA_GeneratePublicKey(privateKey, publicKey);
	//assert(true == result);
	//if(!result ){return 0;}

	result = SignMessage(privateKey, message, signed_message);
	assert(true == result);
	if(result == false)
			cout<<"error in signMessage"<<endl;
	if((int)signed_message.length() >= signed_mess_len)
		return -1;
	StringToChar(signed_message, signed_mess_buf);
	return 0;

}
