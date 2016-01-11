/*************************************************************************
    > File Name: enum.h
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2016年01月08日 星期五 10时11分31秒
 ************************************************************************/
typedef enum node_type{
    RSU = 1,
    OBU = 2,
}node_type;

typedef enum vehicular_type{
    EMERGENCY = 1,
    LARGE_TRUCK = 2,
    COMMERCIAL = 3,
    PRIVATE = 4，
}vehicular_type;

typedef enum ppp_result{
    SUCCESS = 1,
    FAILURE = 2,
}ppp_result;

typedef enum snd_data_type{
    ID_REQUEST = 1,
    SHARE_KEYPAIR_REQUEST = 2,
}
