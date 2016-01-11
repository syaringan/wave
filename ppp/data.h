/*************************************************************************
    > File Name: data.h
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2016年01月08日 星期五 10时09分40秒
 ************************************************************************/
#include "./enum.h"
#include "../utils/common.h"

typedef long long vehicular_id;//id为0为无效id

typedef struct ppp_certificate{

}ppp_certificate;

typedef struct ppp_share_keypair{
}ppp_share_kerpair;

typedef struct ppp_share_keypair_array{
    u8 len;
    ppp_share_keypair *keypair;
}ppp_share_keypair_array;

typedef struct ppp_idrl{
}ppp_idrl;

typedef struct ppp_signed_data{
}ppp_signed_data;

typedef struct ppp_signature{
}ppp_signature;

typedef struct ppp_unsigned_snd_data{
    snd_data_type type;
    vehicular_id id;
    node_type node_type;
    vehicular_type vehicular_type;
}ppp_unsigned_snd_data;

typedef struct ppp_snd_data{
    ppp_unsigned_snd_data unsigned_data;
    ppp_signature signature;
}ppp_snd_data;

typedef struct ppp_recv_data{

}ppp_recv_data;
