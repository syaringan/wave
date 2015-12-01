/*=============================================================================
#
# Author: 杨广华 - edesale@qq.com
#
# QQ : 374970456
#
# Last modified: 2015-10-19 14:46
#
# Filename: crypto.c
#
# Description:测试程序，用于检测c++加密算法接口是否正常使用
#
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>

extern int ECDSA256_get_privatekey(char* privatekey_buf, int len);

extern int ECDSA256_get_publickey(char* public_key_x_buf,int xlen, char* public_key_y_buf,int ylen,
				char* private_key_buf, int prilen);
extern int ECDSA256_sign_message(char* private_key_buf,int prilen,  char* mess_buf, int mess_len,
				char* signed_mess_buf, int signed_mess_len);


extern int ECDSA256_verify_messagge(char* public_key_x_buf, int xlen,char* public_key_y_buf,int ylen,
				 char* signed_mess_buf, int signed_mess_len, char* mess_buf, int mess_len);

extern int ECDSA224_get_privatekey(char* privatekey_buf, int len);

extern int ECDSA224_get_publickey(char* public_key_x_buf, int xlen, char* public_key_y_buf,int ylen,
				char* private_key_buf, int prilen);
extern int ECDSA224_sign_message(char* private_key_buf, int prilen , char* mess_buf, int mess_len,
				char* signed_mess_buf, int signed_mess_len);


extern int ECDSA224_verify_messagge(char* public_key_x_buf, int xlen, char* public_key_y_buf, int ylen,
				 char* signed_mess_buf, int signed_mess_len, char* mess_buf, int mess_len);



extern int ECIES256_get_private_key(char* private_key_buf, int prlen);

extern int ECIES256_get_public_key(char* public_key_x_buf, int xlen, char* public_key_y_buf, int ylen, char* private_key_buf, int prilen);


extern int ECIES256_encrypto_message(char* mess_buf, int mess_len, 
			char* encrypto_mess_buf, int encrypto_mess_len, char* public_key_x_buf,int xlen, 
			char* public_key_y_buf, int ylen);


extern int ECIES256_decrypto_message(char* encrypto_mess_buf, int encrypto_mess_len,
			char* decrypto_mess_buf, int decrypto_mess_len, char* private_key_buf, int prilen);

extern int ECIES224_get_private_key(char* private_key_buf, int prlen);

extern int ECIES224_get_public_key(char* public_key_x_buf, int xlen, char* public_key_y_buf, int ylen, char* private_key_buf, int prilen);


extern int ECIES224_encrypto_message(char* mess_buf, int mess_len, 
			char* encrypto_mess_buf, int encrypto_mess_len, char* public_key_x_buf,int xlen, 
			char* public_key_y_buf, int ylen);


extern int ECIES224_decrypto_message(char* encrypto_mess_buf, int encrypto_mess_len,
			char* decrypto_mess_buf, int decrypto_mess_len, char* private_key_buf, int prilen);







extern int HASH256_message(char* message, int len , char* hash_message,
				int hash_len);

extern int HASH224_message(char* message, int len, char* hash_message,
				int hash_len);

int main()
{
		char* private_buf = malloc(sizeof(char)*100);
		char* itchar;
		if(NULL == private_buf)
		{
			printf("error in malloc\n");
			return 0;
		}
	 	int private_len = ECDSA224_get_privatekey(private_buf, 100);
		printf("main函数中，私钥为：\n");
		printf("%s",private_buf);
		printf("\n");
		
		itchar = private_buf;
		int len;
		for(len = 0; *itchar!= '\n'; len++)
			itchar++;
		
		char* public_x_buf = malloc(sizeof(char)*(len + 40));
		char* public_y_buf = malloc(sizeof(char)*(len + 40));
		
		if(public_x_buf == NULL || NULL == public_y_buf)
		{
			printf("error in malloc public \n");
			return 0;
		}


		int public_len = ECDSA224_get_publickey(public_x_buf, public_y_buf, len + 40, private_buf);
		if(public_len < 0)
		{
			printf("error occur in publicke\n");
			return 0;
		}
		printf("main函数中，公钥x为：\n");
		printf("%s", public_x_buf);
		printf("\n");
	

		printf("main函数中，私钥y为：\n");
		printf("%s", public_y_buf);
		printf("\n");	
			
		char mess[50] = "this is a test\n";
		char signed_mess[100];

		int signed_mess_len = ECDSA224_sign_message(private_buf, mess, 14,
				signed_mess, 100);

		printf("main 函数中，签名值为:\n %s\n", signed_mess);

		int result= ECDSA224_verify_message(public_x_buf, public_y_buf,  
				signed_mess, signed_mess_len, mess, 14);
		if(result == 0)
		{
			printf("认证失败\n");
		}
		else
		{
			printf("认证成功\n");
		}
		free(private_buf);
		free(public_y_buf);
		free(public_x_buf);
		private_buf = NULL;
		public_y_buf = NULL;
		public_x_buf = NULL;




		/***********ECIES******************/
		private_buf = malloc(sizeof(char)* 100);
		private_len = ECIES_get_private_key(private_buf, 100);
		printf("ECIES private key\n %s ", private_buf);

		public_y_buf = malloc(sizeof(char)* 100);
		public_x_buf = malloc(sizeof(char)* 100);

		public_len = ECIES_get_public_key(public_x_buf, public_y_buf, 100, private_buf);
		printf("public_len %d\n", public_len);	
		printf("ECIES public key x\n %s \n y\n %s", public_x_buf, public_y_buf);
	
		printf("runing here\n");

		char en_mess[200];

		int en_mess_len = 
				ECIES_encrypto_message(mess, 15,en_mess, 200, 
								public_x_buf, public_y_buf);
		printf("en mess len 大小为：%d \n", en_mess_len);

		char* de_mess  = malloc(sizeof(char)*100 );
		if(de_mess == NULL)
			printf("error in de_mess\n");
		int de_mess_len = 
				ECIES_decrypto_message(en_mess, en_mess_len, de_mess, 200, 
								private_buf);
		printf("解码数据为：%s\n", de_mess);

		char* hash_message = malloc(sizeof(char)* 200);
		int hash_256 = HASH256_message(de_mess, 15, hash_message,200);
		printf("hash value is %s", hash_message);
		
		char* hash224_message = malloc(sizeof(char)* 200);
		int hash_224 = HASH224_message(de_mess, 15, hash224_message, 200);

		printf("hash value is %s \n", hash224_message);
		return 0;
}




