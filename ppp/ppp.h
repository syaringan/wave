/*************************************************************************
    > File Name: ppp.h
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2016年01月08日 星期五 10时23分22秒
 ************************************************************************/
#include "./enum.h"
#include "./data.h"

//本机的身份标识id
vehicular_id id;

//本机的节点类型
node_type node_type;

//本就的车辆类型
vehicular_type vehicular_type;

//向CA申请本机的身份标识id
ppp_result ppp_vehicular_id_request();

//验证CA发送过来的id
ppp_result ppp_vehicular_id_reqeust_verification(ppp_recv_data *data);

//保存CA发送过来的共享密钥集
ppp_result ppp_share_keypair_store();

//向CA申请共享密钥集
ppp_result ppp_share_keypair_request();

ppp_result ppp_share_keypair_request_verification();

ppp_result ppp_sign_data();

ppp_result ppp_sign_data_verification();

ppp_result ppp_idrl_verification();

ppp_result ppp_update_idrl();

ppp_result ppp_erase_idrl();
