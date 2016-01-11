/*************************************************************************
    > File Name: ppp.c
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2016年01月08日 星期五 14时58分49秒
 ************************************************************************/

#include "./ppp.h"
#include "../utils/debug.h"

ppp_result ppp_vehicular_id_request(){
    ppp_result ret = FAILURE;
    if(id != 0){
        wave_error_printf("id初始化的时候没有置0");
        return ret;
    }
    ppp_snd_data data;
    data.unsigned_data.type = ID_REQUEST;
    data.unsigned_data.id = id;
    data.unsigned_data.node_type = node_type;
    data.unsigned_data.vehicular_type = vehicular_type;
    time_t now;
    time(&now);

    //通过本机的证书产生签名，此证书是和.2中的证书一样，能通过CA验证

    //此处通过和ca通信获取id，本机实验可以通过socket

    ret = SUCCESS;
    return ret;
}

ppp_result ppp_share_keypair_request(){
    ppp_result ret = FAILURE;
    ppp_snd_data data;
    data.unsigned_data.type = SHARE_KEYPAIR_REQUEST;
    data.unsigned_data.id = id;
    data.unsigned_data.node_type = node_type;
    data.unsigned_data.vehicular_type = vehicular_type;
    time_t now;
    time(&now);

    //通过本机的证书产生签名，此证书是和.2中的证书一样，能通过CA验证
    
    //此处通过和ca通信获取id，本机实验可以通过socket

    ret = SUCCESS;
    return ret;
}
