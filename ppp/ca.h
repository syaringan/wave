/*************************************************************************
    > File Name: ca.h
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2016年01月08日 星期五 10时44分13秒
 ************************************************************************/
#include "./enum.h"
typedef long long current_id_assigned;

ppp_result ca_generate_vehicular_id(vehicular_id *id);

ppp_result ca_send_vehicular_id();

ppp_result ca_share_keypair_request_verification();

ppp_reuslt ca_generate_share_keypair();

ppp_result ca_send_share_keypair();

ppp_result ca_trace_vehicular_id();

ppp_result ca_generate_idrl();

ppp_result ca_send_idrl();


