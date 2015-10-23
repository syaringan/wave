#ifndef PSSME_H
#define PSSME_H

#include"pssme_db.h"
#include"../utils/common.h"
#include"../data/data.h"
#include"../cme/cme_db.h"

struct sec_db;
typedef enum action{
    ADD = 1,
    DELETE = 2,
}action;


typedef struct serviceinfo{
    pssme_lsis lsis;
    psid psid;
    priority max_priority;
    string ssp;
}serviceinfo;

typedef struct serviceinfo_array{
    serviceinfo* serviceinfos;
    u32 len;
}serviceinfo_array;


/**
 * 释放一个pssme_local_cert链表
 */
void pssme_local_cert_list_free(struct pssme_local_cert *head);
/*
 * 释放一个pssme_local_cert节点
 * */
void pssme_local_cert_free(struct pssme_local_cert *node);
/**
 * 释放serviceinfo_array内部的指针
 */
void serviceinfo_array_free(serviceinfo_array* point);
void pssme_lsis_array_free(struct pssme_lsis_array* lsises);
/**
 * 申请一个pssme lsis;
 */
result pssme_lsis_request(struct sec_db* sdb,pssme_lsis* lsis);
/**
 * 向pssme注册或者撤销一个服务相关的东西;
 * @lsis：该实体标示。
 * @action：是删除还是添加
 * @psid：该实体的psid
 * @priority：该实体的priority
 * @ssp：该实体的ssp；
 * return 成功或者失败
 */
result pssme_secure_provider_serviceinfo(struct sec_db* sdb,pssme_lsis lsis,action action,
                   psid psid,priority priority,string* ssp);
/**
 *获取该lsis实体的服务信息
 *@lsis：该实体的表示，如果为0 表示获取所有实体的。
 *@se_array:如果成功，把相关的信息填写进去;
 */
result pssme_get_serviceinfo(struct sec_db* sdb,
                    pssme_lsis lsis,serviceinfo_array* se_array);

/**
 * 将证书和lsis绑定起来
 * @cmh：证书索引。
 * @liss_array:实体标示集合。
 **/
result pssme_cryptomaterial_handle_storage(struct sec_db* sdb,
                cmh cmh,struct pssme_lsis_array* lsises);
/**
 *
 * 这个暂时不实现，协议里面没有这个
 */
result pssme_cryptimaterial_handle_delete(struct sec_db* sdb,
                cmh cmh);

/**
 * 检测这个证书，受到的time是否是最新。
 * @generation_time:wsa受到的时间。
 * @cert：对应的证书.
 */
result pssme_outoforder(struct sec_db* sdb,
                u64 generation_time,certificate* cert);


    
/**
 * 这个主要是寻找签名wsa的证书。
 * @sdb：整个数据库；
 * @serviceinfo_array:需要满足的相关的一些权限。
 * @two_d_location:位置
 *
 * @permission_ind：我们需要填充的，当给我们的时候，我们认为内存已经分配。
 * @cmh：学着的证书的索引
 * @cert_chain:证书链，这个调用者，我们可以认为是之分配好了这一个节点，我们需要自行填充，
 *          然后让上层来释放这个链表（这个设计，在商榷哈）
 */
result pssme_cryptomaterial_handle(struct sec_db* sdb,serviceinfo_array* se_array,
                    two_d_location* two_dl,

                    string* permission_ind,
                    cmh* cmh,
                    struct certificate_chain* cert_chain);

void pssme_init_pdb(struct sec_db* sdb);
#endif

