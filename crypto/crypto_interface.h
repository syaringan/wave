/*=============================================================================
#
# Author: 杨广华 - edesale@qq.com
#
# QQ : 374970456
#
# Last modified: 2015-10-19 08:40
#
# Filename: crypto_interface.h
#
# Description 加密算法对外接口，主要完成密钥生成，加密解密，哈希值的计算
#
=============================================================================*/
#ifndef CRYPTO_INTERFACE_H
#define CRYPTO_INTERFACE_H
extern "C"{
/**
 *  函数产生私钥
 *	@key_buf 存放密钥和公钥的入口地址
 *	@len	 key_buf 的字节长度
 *	返回值： 0 私钥获取失败，-1 申请内存不够  大于零的数为私钥长度 
 */
int 	ECDSA256_get_privatekey(char* privatekey_buf, int len);
/**
 *  函数产生公钥
 *  @public_key_x 公钥x
 *  @public_key_y 公钥y
 *  @pulen 	公钥申请的内存长度
 *	@privatekey_buf: 存放有privatekey的buf
 *  返回值：0 公钥获取失败，-1，申请的内存不够公钥获取失败，other 获取成功
 *  大于零时为公钥长度（x， y长度相同）
 */
int 	ECDSA_get_publickey(char* public_key_x_buf,int xlen, char* public_key_y_buf,int ylen,
				char* private_key_buf,int prilen);		
/**
 *  利用私钥进行签名
 *	@private_key_buf 存放私钥
 *  @message_buf	 需要签名的message
 *  @mess_len		 message的字节长度
 *  @signed_message_buf 存放签名后的message
 *  @signed_mess_len	申请的内存大小
 *  返回值 0 表示签名失败 -1 申请的内存不够     other 表示签名成功
 *  大于零为签名长度，
 */
int		ECDSA_sign_message(char* private_key_buf,int prilen, char* mess_buf, int mess_len, char* signed_mess_buf, int signed_mess_len);
/**
 *	利用公钥进行认证
 *	@public_key_x_buf 公钥x
 *	@public_key_y_buf 公钥y
 *	@signed_message_buf 签名消息
 *	@message_buf 没有签名的消息
 *	返回值 0 表示认证失败，other 签名成功
 */
int		ECDSA_verify_message(char* public_key_x_buf,int xlen, char* public_key_y_buf,int ylen,
			 char* signed_mess_buf, int signed_mess_len, 
				char* mess_buf, int mess_len);	
/**
 *	获取ECIES私钥（公钥加密， 私钥解密）
 *	@private_key_buf 已申请了的存放私钥的地址
 *	@prlen 			 已申请内存的大小
 *	返回值 0 申请失败 -1 申请的内存不够用， other 获取私钥成功	
 *	大于零私钥长度
 */
int		ECIES_get_private_key(char* private_key_buf, int prlen);
/**
 *  获取ECIES 公钥
 *	@public_key_x_buf  获取公钥的x
 *	@public_key_y_buf  获取公约的y
 *	@pulen			   申请的x/y 的长度
 *	@private_key_buf   私钥
 * 	返回值	0 表示获取失败， -1 申请的内存plen不够， 
 */
int		ECIES_get_public_key(char* public_key_x_buf,int xlen, char* public_key_y_buf,int ylen, char* private_key_buf,int prilen);
/** 公钥加密，私钥解密，利用公钥加密
 *	message_buf 待加密的数据
 *	mess_len	待加密的数据长度
 *	encrypto_message_buf 加密后的数据
 *	encrypto_mess_len 长度
 *	public_key_x/y_buf 公钥
 *	pulen 	私钥
 */
int		ECIES_encrypto_message(char* mess_buf, int mess_len, char* encrypto_mess_buf, int encrypto_mess_len,char* public_key_x_buf,int xlen,
             char* public_key_y_buf,int ylen);
/**	利用私钥解密
 *	@encrypto_mess_buf 加密后的消息
 *  @encrypto_mess_len 加密后消息的长度
 *  @decrypto_mess_buf 解密后的消息
 *  @decrypto_mess_len 解密后的消息长度
 *  @private_key_buf   私钥
 *  @prlen 
 */
int 	ECIES_decrypto_message(char* encrypto_mess_buf, int encrypto_mess_len, char* decrypto_mess_buf, int decrypto_mess_len,
             char* private_key_buf,int prilen);
/**
 *	计算消息的哈希值
 *	@message 待机算的消息
 *	@len 	 消息长度
 *	@hash_message 消息的哈希值
 *	@hash_message 申请内存字节长度
 */
int	    HASH256_message(char* message, int len, char* hash_message, int hash_len);
/**
 *	hash224算法
 *	@message 待hash的值
 *	@len 待hash值的长度
 *	@hash_message  hash后的值
 *	@hash_len 申请的内存大小
 */
int	    HASH224_message(char* message, int len, char* hash_message, int hash_len);

}
#endif
