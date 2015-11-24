
#include "data/data.h" //后面把直接需要的结构体复制过来


/**
 * 这里我没有为上层提供调试的功能，只是0代表成功，-1代表失败.
 */

/**
 *请求实体的编号，lsis为null则不会有指填写，
 *@return 0成功 -1 失败
 */
int cme_lsis_request(cme_lsis *lsis)；
int cme_cmh_request(cmh *cmh);

/**
 *请求生成一对密钥，
 *@cmh:cme_cmh_request 产生的cmh
 *@pk_algorithm:这对密钥的相关算法
 *@pub_key_x/pub_key_y/pri_key:存放结果的buf，上层得分配好空间。
 *@x_len/y_len/pri_len:在调用的时候里面存放分配的buf的空间有多大，返回的时候里面存放的是填写了多少字节
 *@return 0成功 -1失败
 */
int cme_generate_keypair(cmh cmh,int algorithm,
        
                        char* pub_key_x,int* x_len,
                        char* pub_key_y,int* y_len,
                        char* pri_key,int* pri_len);
/**在cmh存储一对密钥
 * @cmh：cme_cmh_request 产生的cmh
 *@pk_algorithm:这对密钥的相关算法
 *@pub_key_x/pub_key_y/pri_key:存放的buf。
 *@x_len/y_len/pri_len:对应buf里面有多少字节。
 *@return 0成功 -1失败
 */
int cme_store_keypair(cmh cmh,int algorithm,
                        char* pub_key_x,int x_len,
                        char* pub_key_y,int y_len,
                        char* pri_key,int pri_len);

int cme_store_cert(cmh cmh,certificate* cert,
                        char* transfor,int transfor_len);

int cme_store_cert_key(cmh cmh,certificate* cert,
                        char* pri_key,int* pri_len);  // int 为什么要传指针？？

/**
 *@set_geneartion_time/set_generation_location/set_expiry_time,:只能为0或1
 *@elevation:这个我们默认只有两字节，我们自动往后读两字节，
 *@*type:各种type的画，请核实下相关结构题里面的值，只能取这些值。
 */
int sec_signed_data(cmh cmh,int type,char* data,int data_len,char* exter_data,int exter_len,psid psid,
                        char* ssp,int ssp_len,int set_generation_time,
                        time64 generation_time,unsigned char generation_long_std_dev,
                        int set_generation_location,int latitude,int longtitude,unsigned char *elevation,
                        int set_expiry_time,time64 expiry_time,int signer_type,int cert_chain_len,
                        unsigned int cert_chain_max_len,int fs_type,int compressed,
                        
                        char* signed_data,int* signed_data_len,int *len_of_cert_chain);
/**
 * @compressed:这能为0或者1
 */
int sec_encrypted_data(int type,char* data,int data_len,certificate *certs,int certs_len,int compressed,time64 time,
        
                        char* encrypted_data,int *encrypted_len,certificate *failed_certs,int *failed_certs_len);

/**
 *@set_geneartion_time/set_generation_location:只能为0或者1
 *@elevation:默认是两字节，只能为两字节
 */
int sec_secure_data_content_extration(char* recieve_data,int recieve_len,cmh cmh,
        
                int *type,int *inner_type,char* data,int* data_len,char* signed_data,int* signed_len,
                psid* psid,char* ssp,int *ssp_len,int *set_generation_time,time64* generation_time,
                unsigned char *generation_long_std_dev,int *set_generation_location,int* latitude,int* longtitude,
                unsigned char *elevation,certificate* send_cert);
/**
 *@detect_reply/check_generation_time/check_expiry_time/check_generation_location:只能为0或这1
 *@elevation:默认为2字节。
 */
int sec_signed_data_verification(cme_lsis lsis,psid psid,int  type,
                char* signed_data,int signed_len,
                char* external_data,int external_len
                int  max_cert_chain_len,
                int detect_reply,
                int check_generation_time,
                time64 validity_period,
                time64 generation_time,
                unsigned char long_std_dev,
                float generation_threshold,
                time64 accepte_time,
                float accepte_threshold,
                int check_expiry_time,
                time64 exprity_time,
                float exprity_threshold,
                int check_generation_location,
                int latitude,int longtitude,
                unsigned int  validity_distance,
                int generation_latitude, 
                int generation_longtitude,
                unsigned char* elevation,
                time64 overdue_crl_tolerance,
                
                time32 *last_recieve_crl_times,int *last_len,
                time32 *next_expected_crl_times,int *next_len,
                certificate* send_cert);


