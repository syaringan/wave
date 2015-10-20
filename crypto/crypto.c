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
# Description: 
#
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>

extern int ECDSA_get_privatekey(char* privatekey_buf, int len);

extern int ECDSA_get_publickey(char* public_key_x_buf, char* public_key_y_buf,int pulen,
				char* private_key_buf, int prlen);
extern int ECDSA_sign_message(char* private_key_buf, int prlen, char* mess_buf, int mess_len,
				char* signed_mess_buf, int signed_mess_len);

int main()
{
		char* private_buf = malloc(sizeof(char)*100);
		char* itchar;
		if(NULL == private_buf)
		{
			printf("error in malloc\n");
			return 0;
		}
		ECDSA_get_privatekey(private_buf, 100);
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


		int m = ECDSA_get_publickey(public_x_buf, public_y_buf, len + 40, private_buf, len);
		if(m < 0)
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
			
		char mess[100] = "this is a test\n";
		char signed_mess[200];

		ECDSA_sign_message(private_buf,100, mess, 100,
				signed_mess, 200);

		printf("main 函数中，签名值为：%s", signed_mess);
		free(private_buf);
		free(public_y_buf);
		free(public_x_buf);
		private_buf = NULL;
		public_y_buf = NULL;
		public_x_buf = NULL;

		return 0;
}




