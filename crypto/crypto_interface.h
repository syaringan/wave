/*************************************************************************
    > File Name: crypto_interface.cpp
    > Author: 付鹏飞
 ************************************************************************/

/*
 *所有函数均是成功返回0,失败返回-1
 */

#ifndef CRYPTO_INTERFACE_H
#define CRYPTO_INTERFACE_H
extern "C"{


/*
 *****************************************椭圆签名相关:***************************************
 */

/*
 *用来长生椭圆签名ECDSA_224的公私钥,
 *输出的公钥以两个坐标x和y的形式输出,各自应该是长度为28字节的字符数组
 *所以传入参数均为输出
 *最后一个参数flag的输出应该会恒等于4,与1609.2一致,表明这是一个未压缩的公钥
 */
int ECDSA_224_get_key( char* privatekey_buf, int* prlen, char* public_key_x_buf, int* xlen, char* public_key_y_buf, int* ylen );

/*
 *用来将未压缩的ECDSA_224的公钥变成压缩形式:
 * @public_key_x:未压缩的公钥的x坐标
 * @public_key_y:未压缩的公钥的y坐标
 *输出有以下三个:
 *
 * @compress_key:压缩后的公钥
 * @compress_key_len:压缩后的公钥长度(应该是28字节,即未压缩公钥的x坐标 
 * @flag:用来表明y的奇偶性,与1609.2一致,y为偶数,则flag等于2,y为奇数则flag等于3
 */
int ECDSA_224_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                            char *public_key_y, int public_key_y_len,
                                            char *compress_key, int *compress_key_len,
                                            char *flag);

/*
 *用来将ECDSA_224的压缩公钥还原为未压缩的形式
 * @public_key_x:未压缩的公钥的x坐标,为输出结果
 * @public_key_y:未压缩的公钥的y坐标,为输出结果
 * @compress_key:是函数输入的压缩后的公钥
 * @old_flag:是函数的输入即表明y的奇偶性的flag,与是那个面函数一致,他的值也与1609.2一致
 * @new_flag:是函数的输出,应会恒等于4,表明恢复成了未压缩的公钥
 */
int ECDSA_224_compress_key_2_uncompress(char *compress_key, int compress_key_len,
                                        char old_flag,

                                        char *public_key_x_buf, int *public_key_x_len,
                                        char *public_key_y_buf, int *public_key_y_len);

/*
 *ECDSA_224的签名函数
 *
 *需要输入签名者的私钥,被签名的消息mess_buf,
 *输出是签名消息signed_mess_buf
 *需要注意的是:signed_mess_buf仅仅就是签名,也就是仅仅是长度为56字节的签名,该字符数组中不包含被签名的消息mess_buf的内容.
 */
int ECDSA_224_sign_message(char* private_key_buf, int prilen,
                           char* mess_buf, int mess_len,

			                char* r,int *r_len, 
                            char* s,int *s_len);

/*
 *ECDSA_224的签名验证函数
 *
 *需要验证者输入签发者的公钥,(并不是验证者的公钥,而是通信的对端的公钥)
 *且该公钥需以未压缩的形式以两坐标形式输入
 *还需输入签名信息signed_mess_buf和消息mess_buf
 *即 该函数的参数全是输入,输出仅是该函数的返回值,验证成功返回0,失败返回-1
 */
int ECDSA_224_verify_message(char* public_key_x_buf, int xlen,
                             char* public_key_y_buf, int ylen,
                             char* r,int r_len,
                             char* s,int s_len,
                             char* mess_buf, int mess_len);

/*
 *ECDSA_224的快速签名函数
 *
 *之所以签名函数也分开,而不只是将验证函数分开,是因为快速签名和普通签名的输出不一样
 *
 *该函数输入私钥,以及被签名消息mess_buf,
 *
 *输出包括:临时公钥signed_R_x和signed_R_y,
 *        以及签名产生的signed_S,也就是1609.2中快速签名结构体中的S
 */
int ECDSA_224_FAST_sign_message(char* private_key_buf, int prilen,
                                char* mess_buf, int mess_len,

                                char* signed_R_x, int* signed_R_x_len,
                                char* signed_R_y, int* signed_R_y_len,
                                char* signed_S, int* signed_S_len);

/*
 *ECDSA_224的快速签名验证函数
 *
 *输入对端公钥,被签名消息以及快速签名函数的输出
 *
 *验证成功函数返回0,验证失败函数返回-1
 */
int ECDSA_224_FAST_verify_message(char* public_key_x_buf, int xlen,
                                  char* public_key_y_buf, int ylen,
                                  char* mess_buf, int mess_len,
                                  char* signed_R_x, int signed_R_x_len,
                                  char* signed_R_y, int signed_R_y_len,
                                  char* signed_S, int signed_S_len);



/*
 *以下是ECDSA_256签名相关的函数,
 *与上面的ECDSA_224签名相关几乎完全一样,只是名字中的224都变换位256,以及输出的长度不同而已
 *下面就不会详细解释了,只解释区别:
 */

/*
 *之前ECDSA_224中输出的私钥,公钥的坐标点x和y长度都是28字节,
 *在接下来的ECDSA_256中输出长度都是32字节,
 *函数使用没有区别
 */
int ECDSA_256_get_key( char* privatekey_buf, int* prlen, char* public_key_x_buf, int* xlen, char* public_key_y_buf, int* ylen);

int ECDSA_256_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                            char *public_key_y, int public_key_y_len,
                                            char *compress_key, int *compress_key_len,
                                            char *flag);

int ECDSA_256_compress_key_2_uncompress(char *compress_key,int compress_key_len,
                                        char old_flag,

                                        char *public_key_x_buf, int* public_key_x_len,
                                        char *public_key_y_buf, int* public_key_y_len);

int ECDSA_256_sign_message(char* private_key_buf, int prilen,
                           char* mess_buf, int mess_len,

                           char* r,int *r_len,
                           char* s,int *s_len);

int ECDSA_256_verify_message(char* public_key_x_buf, int xlen,
                             char* public_key_y_buf, int ylen,
                             char* r, int r_len,
                             char* s,  int s_len,
                             char* mess_buf, int mess_len);

int ECDSA_256_FAST_sign_message(char* private_key_buf, int prilen,
                                char* mess_buf, int mess_len,
                                char* signed_R_x, int* signed_R_x_len,
                                char* signed_R_y, int* signed_R_y_len,
                                char* signed_S, int* signed_S_len);

int ECDSA_256_FAST_verify_message(char* public_key_x_buf, int xlen,
                                  char* public_key_y_buf, int ylen,
                                  char* mess_buf, int mess_len,
                                  char* signed_R_x, int signed_R_x_len,
                                  char* signed_R_y, int signed_R_y_len,
                                  char* signed_S, int signed_S_len);

/*
 *****************************************椭圆加密ECIES相关*****************************************:
 */

/*
 *椭圆加密公私钥的产生:
 *公钥产生以非压缩的两点形式输出
 * @private_klen:私钥长度的指针,应该为32字节
 * @public_key_x_len:公钥x点的长度的指针,长度应该为32字节
 * @public_key_y_len:公钥y点的长度的指针,长度应该为32字节
 * @flag:等于4,表明是未压缩的公钥
 */
int ECIES_get_key(char* private_key_buf, int* private_klen,
                  char *public_key_x_buf, int* public_key_x_len,
                  char *public_key_y_buf, int* public_key_y_len);

/*
 *将椭圆加密需要的公钥从未压缩形式转换为压缩形式:
 * @flag:若y为偶数,则等于2,若y为奇数,则等于3
 */
int ECIES_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                        char *public_key_y, int public_key_y_len,
                                        char *compress_key, int *compress_key_len,
                                        char *flag);

/*
 *将椭圆加密的压缩公钥转换成非压缩形式
 * @public_key_x_buf:转换后的非压缩形式的公钥的x点
 * @public_key_y_buf:转换后的非压缩形式的公钥的y点
 * @compress_key:输入的压缩形式的公钥
 * @flag:伴随压缩公钥的标志位,y位偶数,flag等于2,y为奇数,flag等于3
 * @new_flag:为函数输出,理应输出4,表示公钥已转变为未压缩形式
 */
int ECIES_compress_key_2_uncompress(char *compress_key,int compress_key_len,
                                    char old_flag,

                                    char *public_key_x_buf, int* public_key_x_len,
                                    char *public_key_y_buf, int* public_key_y_len);

/*
 *椭圆加密算法ECIES的加密函数:
 *
 * @mess_buf:输入的被加密的原文
 * @flag:输出的临时公钥的标志位,应为4,因为输出为非压缩形式的临时公钥
 * @ephe_public_key_x:输出的临时公钥的x点,    @ephe_public_key_x_len长度应为32字节
 * @ephe_public_key_Y:输出的临时公钥的y点,    @ephe_public_key_y_len长度应为32字节
 * @encrypto_mess_buf:输出的被加密后的密文,   @encrypto_mess_len长度与原文长度mess_len一样
 * @public_key_x_buf:输入的加密需要的对端公钥的x坐标
 * @public_key_y_buf:输入的加密需要的对端公钥的y坐标
 */
int ECIES_encrypto_message(char* mess_buf, int mess_len,
                           char* public_key_x_buf, int xlen,
                           char* public_key_y_buf, int ylen,

                           char* ephe_public_key_x, int *ephe_public_key_x_len,
                           char* ephe_public_key_y, int *ephe_public_key_y_len,
		                   char* encrypto_mess_buf, int *encrypto_mess_len,
                           char* tag, int *tag_len);

/*
 *椭圆加密算法ECIES的解密函数:
 *
 * @flag:输出的临时公钥的标志位,只能为4,因为输如的临时公钥为非压缩形式的临时公钥
 * @ephe_public_key_x:输入的临时公钥的x点,    @ephe_public_key_x_len长度应为32字节
 * @ephe_public_key_Y:输入的临时公钥的y点,    @ephe_public_key_y_len长度应为32字节
 * @encrypto_mess_buf:输入的密文,   @encrypto_mess_len为密文长度
 * @decrypto_mess_buf:解密密文获得的原文,     @decrypto_mess_len解密出的原文长度,与密文长度一致
 * @private_key_buf:输入的解密需要的本方私钥
 */
int ECIES_decrypto_message( char* encrypto_mess_buf, int encrypto_mess_len,
                           char* ephe_public_key_x, int ephe_public_key_x_len,
                           char* ephe_public_key_y, int ephe_public_key_y_len,
                           char* tag,int tag_len,
                           char* private_key_buf, int prilen,

		                    char* decrypto_mess_buf, int* decrypto_mess_len);


/*
 ************************************************AES_128_CCM对称加密相关************************************************
 */

/*
 *AES_128_CCM的密钥以及随机值nonce产生函数
 * @sym_key:函数产生的对称密钥         @sym_key_len:函数产生的对称密钥的长度,函数输出的此值理应只能是16(字节位单位)
 * @nonce:函数产生的随机值             @nonce_len:函数长生的随机值的长度,函数输出的此值理应只能是12(字节位单位)
 */
int AES_128_CCM_Get_Key_and_Nonce(char* sym_key, int *sym_key_len, char* nonce, int* nonce_len);

/*
 *AES_128_CCM对称加密函数:
 * @plaintext:输入原文
 * @sym_key:输入的对称密钥
 * @nonce:输入的随机值
 * @ciphertext:输出的密文          @length_of_plaintext:输出密文长度,理应比输出原文长度要长16字节(因为会产生16字节的tag)
 */
int AES_128_CCM_encrypto_message(char *plaintext, int length_of_plaintext,
                                 char *sym_key, int sym_key_len,
                                 char *nonce, int nonce_len,
                                 char *ciphertext, int *length_of_ciphertext);

/*
 *AES_128_CCM对称加密函数:
 * @ciphertext:输入的密文
 * @sym_key:输入的对称密钥
 * @nonce:输入的随机值
 * @plaintext:输出的解密后的原文
 */
int AES_128_CCM_decrypto_message(char *ciphertext, int length_of_ciphertext,
                                 const char *sym_key, int sym_key_len,
                                 const char *nonce, int nonce_len,
                                 char *plaintext, int *length_of_plaintext);


/*
 **************************************************SHA_256相关***********************************************
 */

/*
 * @message:输入的消息
 * @digest:输出的对该消息求到的摘要
 * @digest_len:摘要的长度,在sha_256中,摘要长度一定是32字节
 */
int sha_256(char* message, int message_len, char* digest, int* digest_len);


/*
 **************************************************SHA_224相关***********************************************
 */

/*
 *SHA_224只用在一个地方!!!
 *就是在隐式证书中,且隐式证书选择的是ECDSA_224时,对证书做哈希摘要算法时才会用到,
 *其他一切需要用哈希摘要算法时,1609.2都规定使用上面的SHA_256
 */


/*
 * @message:输入的消息
 * @digest:输出的对该消息求到的摘要
 * @digest_len:摘要的长度,在sha_256中,摘要长度一定是28字节
 */
int sha_224(char* message, int message_len, char* digest, int* digest_len);


/*
 ************************************************隐式证书相关:*********************************************
 */

/*
 *此函数用于通信的一方从另一方获得隐式证书后，提取出另一方的公钥
 *
 *
 *从隐式证书中提取出（新的）对端公钥的函数：
 *
 *参数e为隐式证书的散列值(这就是前面说的,唯一使用Sha_224函数的地方)
 *
 *还有要注意的一点是 在计算证书计算散列值时，证书中的所有公钥或者椭圆上的点都必须是以压缩形式输入散列函数的,这样算出来的摘要e才能传入下面函数
 *
 * @CA_public_key_x:CA的公钥x点,长度28字节
 * @CA_public_key_y:CA的公钥y点,长度28字节
 * @Pu_x:隐式证书中包含的临时公钥的x点,长度28字节
 * @Pu_y:隐式证书中包含的临时公钥的y点,长度28字节
 * @e:对隐式证书算出来的摘要      (!!!通过Sha_224!!!)
 * @U_public_key_x:从隐式证书中恢复出来的对端的公钥的x点,长度28字节
 * @U_public_key_y:从隐式证书中恢复出来的对端的公钥的y点,长度28字节
 */
int cert_pk_extraction_SHA224(char* CA_public_key_x, int CA_public_key_x_len,
                              char* CA_public_key_y, int CA_public_key_y_len,
                              char* Pu_x, int Pu_x_len,
                              char* Pu_y, int Pu_y_len,
                              char* e, int e_len,
                              char* U_public_key_x, int* U_public_key_x_len,
                              char* U_public_key_y, int* U_public_key_y_len);

/*
 *此函数用于隐式证书申请者验证获得的隐式证书是否合法:
 *合法函数返回0,不合法返回-1
 *
 * @CA_public_key_x:CA的公钥x点,长度28字节
 * @CA_public_key_y:CA的公钥y点,长度28字节
 * @Pu_x:隐式证书中包含的临时公钥的x点,长度28字节
 * @Pu_y:隐式证书中包含的临时公钥的y点,长度28字节
 * @old_u_private_key:申请者之前的私钥,长度28字节
 * @e:对隐式证书算出来的摘要,也即A (y = Ax + B 1609.2中提到的私钥变换规则)          (!!!通过Sha_224!!!)
 * @r:CA随证书一起返回的重建因子,也即B
 * @new_U_public_key_x:重建后的新的申请者的公钥x点,长度为28字节,长度28字节
 * @new_U_public_key_y:重建后的新的申请者的公钥y点,长度为28字节,长度28字节
 * @new_U_private_key:重建后的新的申请者的私钥,长度为28字节,长度28字节
 */
int cert_reception_SHA224(char* old_u_private_key, int old_u_private_key_len,
                          char* e, int e_len,
                          char* r, int r_len,
                          char* new_U_private_key, int* new_U_private_key_len);

/*
 *下面两个函数与上面两个几乎完全一样,只有以下不同:
 *
 *一,函数名字不同,上面是224,这里是256
 *   因此此函数中使用的都是和256相关的椭圆曲线和SHA256这些
 *
 *二,因此,对隐式证书计算摘要应该使用Sha_256函数
 *
 *三,因此,所有输入输出公私钥的长度都是32字节
 */

/*
 *此函数用于通信的一方从另一方获得隐式证书后，提取出另一方的公钥
 *
 * @CA_public_key_x:CA的公钥x点,长度32字节
 * @CA_public_key_y:CA的公钥y点,长度32字节
 * @Pu_x:隐式证书中包含的临时公钥的x点,长度32字节
 * @Pu_y:隐式证书中包含的临时公钥的y点,长度32字节
 * @e:对隐式证书算出来的摘要     (!!!通过Sha_256!!!)
 * @U_public_key_x:从隐式证书中恢复出来的对端的公钥的x点,长度32字节
 * @U_public_key_y:从隐式证书中恢复出来的对端的公钥的y点,长度32字节
 */
int cert_pk_extraction_SHA256(char* CA_public_key_x, int CA_public_key_x_len,
                              char* CA_public_key_y, int CA_public_key_y_len,
                              char* Pu_x, int Pu_x_len,
                              char* Pu_y, int Pu_y_len,
                              char* e, int e_len,
                              char* U_public_key_x, int* U_public_key_x_len,
                              char* U_public_key_y, int* U_public_key_y_len);

/*
 *此函数用于隐式证书申请者验证获得的隐式证书是否合法:
 *合法函数返回0,不合法返回-1
 *
 * @CA_public_key_x:CA的公钥x点,长度32字节
 * @CA_public_key_y:CA的公钥y点,长度32字节
 * @Pu_x:隐式证书中包含的临时公钥的x点,长度32字节
 * @Pu_y:隐式证书中包含的临时公钥的y点,长度32字节
 * @old_u_private_key:申请者之前的私钥,长度32字节
 * @e:对隐式证书算出来的摘要,也即A (y = Ax + B 1609.2中提到的私钥变换规则)        (!!!通过Sha_256!!!)
 * @r:CA随证书一起返回的重建因子,也即B
 * @new_U_public_key_x:重建后的新的申请者的公钥x点,长度为32字节
 * @new_U_public_key_y:重建后的新的申请者的公钥y点,长度为32字节
 * @new_U_private_key:重建后的新的申请者的私钥,长度为32字节
 */
int cert_reception_SHA256(char* old_u_private_key, int old_u_private_key_len,
                          char* e, int e_len,
                          char* r, int r_len,
                          char* new_U_private_key, int* new_U_private_key_len);
}
#endif
