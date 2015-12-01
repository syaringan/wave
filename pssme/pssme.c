#include "pssme.h"
#include "cme/cme.h"
#include "sec/sec.h"
#include "utils/debug.h"
#include<stdlib.h>
#define INIT(m) memset(&m,0,sizeof(m))
#define max_chain_length 8
void serviceinfo_array_free(serviceinfo_array* point){
    if(point->serviceinfos == NULL)
        return;
    free(point->serviceinfos);
    point->serviceinfos = NULL;
    point->len = 0;
};

void pssme_lsis_array_free(struct pssme_lsis_array* lsises){
    if(lsises->lsis == NULL)
        return ;
    free(lsises->lsis);
    lsises->len = 0;
    lsises->lsis = NULL;
}

//未测
result pssme_cryptomaterial_handle(struct sec_db* sdb,serviceinfo_array* se_array,two_d_location* two_dl,
        
        string* permission_ind,cmh* cmh,struct certificate_chain* cert_chain){
    result ret = FAILURE;

    struct pssme_local_cert clist;
    struct cme_permissions current_cert_permissions;
    bool certificate_found;
    certificate c;
    geographic_region geo_permissions;
    string cert_encoded;
    int i = 0, j = 0, k = 0;

    INIT(current_cert_permissions);
    INIT(c);
    INIT(geo_permissions);
    INIT(cert_encoded);
    INIT_LIST_HEAD(&clist.list);

    struct pssme_local_cert *p;//遍历用的临时变量
    //访问pssme_db，找到符合lsis要求的cmh
    lock_rdlock(&sdb->pssme_db.lock);
    list_for_each_entry(p, &sdb->pssme_db.cert_db.local_cert.list, list){
        if(se_array->len > p->lsis_array.len)
            continue;
        for(i = 0; i < se_array->len; i++){
            for(j = 0; j < p->lsis_array.len; j++){
                if(se_array->serviceinfos[i].lsis == p->lsis_array.lsis[j])
                    break;
            }
            if(j == p->lsis_array.len)
                break;
        }
        //创建一个新的临时节点，记得释放这个链表
        if(i == se_array->len){
            struct pssme_local_cert *p_add = malloc(sizeof(struct pssme_local_cert));
            if(p_add == NULL){
                wave_error_printf("内存分配失败");
                result ret = FAILURE;
                goto fail;
            }
            p_add->cmh = p->cmh;
            p_add->lsis_array.len = p->lsis_array.len;
            p_add->lsis_array.lsis = malloc(sizeof(pssme_lsis)*p_add->lsis_array.len);
            if(p_add->lsis_array.lsis == NULL){
                wave_error_printf("内存分配失败");
                result ret = FAILURE;
                goto fail;
            }
            memcpy(p_add->lsis_array.lsis, p->lsis_array.lsis, sizeof(pssme_lsis)*p_add->lsis_array.len);
            list_add(&p_add->list, &clist.list);
        }
    }
    lock_unlock(&sdb->pssme_db.lock);

    if(list_empty(&clist.list)){
        ret = CERTIFICATE_NOT_FOUND;
        goto fail;
    }

    certificate_found = false;
    list_for_each_entry(p, &clist.list, list){
        if(find_cert_by_cmh(sdb, &p->cmh, &c))
            continue;
        if(get_cert_expired_info_by_cmh(sdb, &p->cmh))
            continue;
        //是否需要每次循环都填充为0
        if(certificate_2_string(&c,&cert_encoded)){
            wave_error_printf("证书编码失败");
            result ret = FAILURE;
            goto fail;
        }
       
        ret = cme_certificate_info_request(sdb, ID_CERTIFICATE, &cert_encoded, NULL, &current_cert_permissions, 
                &geo_permissions, NULL, NULL, NULL, NULL);
        if(!geo_permissions_contains_location(geo_permissions))
            continue;
        if(permission_ind != NULL){
            permission_ind->len = se_array->len;
            if(permission_ind->buf != NULL){
                wave_error_printf("permission_ind的buf已经被填充");
                ret = FAILURE;
                goto fail;
            }
            permission_ind->buf = malloc(sizeof(u8)*se_array->len);
            if(permission_ind->buf == NULL){
                wave_error_printf("内存分配失败");
                ret = FAILURE;
                goto fail;
            }
            memset(permission_ind->buf, 0, sizeof(u8)*se_array->len);
            for(j = 0; j < se_array->len; j++){
                if(se_array->serviceinfos[j].lsis == 0){
                    permission_ind->buf[j] == 0;
                    continue;
                }
                for(k = 0; k < p->lsis_array.len; k++){
                    if(p->lsis_array.lsis[k] != se_array->serviceinfos[j].lsis)
                        continue;
                    if(se_array->serviceinfos[j].psid != current_cert_permissions.u.psid_priority_ssp_array.buf[k].psid)
                        continue;
                    string tmp_ssp;
                    tmp_ssp.buf = current_cert_permissions.u.psid_priority_ssp_array.buf[k].service_specific_permissions.buf;
                    tmp_ssp.len = current_cert_permissions.u.psid_priority_ssp_array.buf[k].service_specific_permissions.len;
                    if(string_cmp(&se_array->serviceinfos[j].ssp, &tmp_ssp) != 0)
                        continue;
                    if(se_array->serviceinfos[j].max_priority > current_cert_permissions.u.psid_priority_ssp_array.buf[k].max_priority)
                        continue;
                    permission_ind->buf[j] = k+1;
                }
            }
            if(j == se_array->len){
                certificate_found = true;
                break;
            }
        }
    }
    if(certificate_found == false){
        ret = CERTIFICATE_NOT_FOUND;
        goto fail;
    }
    struct certificate_chain chain;
    chain.len = 1;
    chain.certs = &c;
    ret = cme_construct_certificate_chain(sdb, ID_CERTIFICATE, NULL, &chain, false, max_chain_length, cert_chain, 
            NULL, NULL, NULL, NULL, NULL);
    if(ret == SUCCESS && cmh != NULL)
        *cmh = p->cmh;
fail:
    pssme_local_cert_list_free(&clist);
    cme_permissions_free(&current_cert_permissions);
    geographic_region_free(&geo_permissions);
    string_free(&cert_encoded);
    certificate_chain_free(&chain);
    certificate_free(&c);
    return ret;
}

result pssme_lsis_request(struct sec_db* sdb,pssme_lsis* lsis){
    struct pssme_db* pdb;
    struct list_head *head;
    struct pssme_lsis_chain *node;
    struct pssme_alloc_lsis *ptr_alloc_node,*alloc_node =NULL;
    pdb = &sdb->pssme_db;
    if(lsis == NULL)
        return FAILURE;
    alloc_node =(struct pssme_alloc_lsis*)malloc(sizeof(struct pssme_alloc_lsis));
    if(alloc_node == NULL){
        wave_error_printf("分配内存失败");
        goto fail;
    }
    INIT(*alloc_node);
    INIT_LIST_HEAD(&alloc_node->permissions.list);

    lock_wrlock(&pdb->lock);
    head = &pdb->lsis_db.lsises.list;
    
    if(list_empty(head)){
        lock_unlock(&pdb->lock);
        goto fail;
    }
    node = list_entry(head->next,struct pssme_lsis_chain,list);
    alloc_node->lsis = node->lsis;
    head = &pdb->lsis_db.alloc_lsis.list;
    list_for_each_entry(ptr_alloc_node,head,list){
        if(ptr_alloc_node->lsis > alloc_node->lsis)
            break;
    }
    list_add_tail(&alloc_node->list,head);
    list_del(&node->list);
    free(node);
    *lsis = alloc_node->lsis;
    lock_unlock(&pdb->lock);
    wave_printf(MSG_INFO,"申请到lsis: %d\n",*lsis);
    return SUCCESS;
fail:
    if(alloc_node != NULL){
        free(alloc_node);
    }
    wave_error_printf("申请lsis失败");
    return FAILURE;
}

result pssme_secure_provider_serviceinfo(struct sec_db* sdb,pssme_lsis lsis,action action,
                            psid psid,priority priority,string* ssp){
    struct pssme_db  *pdb;
    struct list_head *head;
    struct pssme_alloc_lsis* node;
    struct pssme_psid_priority_ssp_chain* permissions = NULL;
    pdb = &sdb->pssme_db;
    lock_wrlock(&pdb->lock);
    head = &pdb->lsis_db.alloc_lsis.list;
    list_for_each_entry(node,head,list){
        if( node->lsis == lsis )
            break;
        if(node->lsis > lsis){
            lock_unlock(&pdb->lock);
            wave_error_printf("pssme里面没有lsis %d",lsis);
            return FAILURE;
        }
    }
    if(&node->list == head){
        lock_unlock(&pdb->lock);
        wave_error_printf("pssme里面没有lsis %d",lsis);
        return FAILURE;
    }
    switch(action){
        case ADD:
            permissions = (struct pssme_psid_priority_ssp_chain*)malloc(sizeof(struct pssme_psid_priority_ssp_chain));
            if(permissions == NULL){
                wave_error_printf("内存分配失败");
                return FAILURE;
            }
            INIT(permissions);
            permissions->permission.priority = priority;
            permissions->permission.psid = psid;
            string_cpy(&permissions->permission.ssp,ssp);
            list_add_tail(&permissions->list,&node->permissions.list);
            break;
        case DELETE:
            list_for_each_entry(permissions,&node->permissions.list,list){
                if(permissions->permission.priority == priority &&
                        permissions->permission.psid == psid &&
                        string_cmp(&permissions->permission.ssp,ssp) == 0){
                    break;
                }
            }
            if(&permissions->list != &node->permissions.list){
                list_del(&permissions->list);
                pssme_psid_priority_ssp_chain_free(permissions);
                free(permissions);
            }
            else{
                wave_error_printf("没有找到permissions");
                lock_unlock(&pdb->lock);
                return FAILURE;
            }
            break;
        default:
            wave_error_printf("aciont 出现了一个不可能的指");
            lock_unlock(&pdb->lock);
            return FAILURE;
    }
    lock_unlock(&pdb->lock);
    return SUCCESS;
}
result pssme_get_serviceinfo(struct sec_db* sdb,pssme_lsis lsis,serviceinfo_array* se_array){
    struct pssme_db  *pdb;
    struct list_head *alloc_head,*permissions_head; 
    struct pssme_alloc_lsis *alloc_node;
    struct pssme_psid_priority_ssp_chain *permissions;
    int i;
    pdb = &sdb->pssme_db;
    if(se_array == NULL || se_array->serviceinfos != NULL){
        wave_error_printf("参数不能为空,或者可能存在野指针");
        return FAILURE;
    }
    lock_rdlock(&pdb->lock);
    alloc_head = &pdb->lsis_db.alloc_lsis.list;
    if(lsis != 0){ 
        list_for_each_entry(alloc_node,alloc_head,list){
            if(alloc_node->lsis == lsis){
                wave_printf(MSG_DEBUG,"寻找到lsis %d",lsis);
                break;
            }
            if(alloc_node->lsis > lsis){
                wave_error_printf("没有找到lsis %d",lsis);
                lock_unlock(&pdb->lock);
                se_array->len = 0;
                return FAILURE;
            }
        }
        if(&alloc_node->list == alloc_head){
            wave_error_printf("没有找到lsis %d",lsis);
            lock_unlock(&pdb->lock);
            se_array->len = 0;
            return FAILURE;
        }
        se_array->len = 0;
        permissions_head = &alloc_node->permissions.list;
        list_for_each_entry(permissions,permissions_head,list){
            se_array->len++;
        }
        se_array->serviceinfos = (struct serviceinfo*)malloc(se_array->len * sizeof(struct serviceinfo));
        if(se_array->serviceinfos == NULL){
            wave_error_printf("内存空间分配失败");
            se_array->len = 0;
            lock_unlock(&pdb->lock);
            return FAILURE;
        }
        permissions = list_entry(permissions_head,struct pssme_psid_priority_ssp_chain,list);
        for(i=0;i<se_array->len;i++){
            permissions = list_entry(permissions->list.next,struct pssme_psid_priority_ssp_chain,list);
            INIT(*(se_array->serviceinfos+i));
            (se_array->serviceinfos+i)->lsis = alloc_node->lsis;
            (se_array->serviceinfos+i)->max_priority = permissions->permission.priority;
            (se_array->serviceinfos+i)->psid = permissions->permission.psid;
            string_cpy(&(se_array->serviceinfos+i)->ssp, &permissions->permission.ssp);
        }
    }
    else{
        se_array->len = 0;
        alloc_head = &pdb->lsis_db.alloc_lsis.list;
        list_for_each_entry(alloc_node,alloc_head,list){
            permissions_head = &alloc_node->list;
            list_for_each_entry(permissions,permissions_head,list){
                se_array->len++;
            }
        }
        se_array->serviceinfos = (struct serviceinfo*)malloc(se_array->len * sizeof(struct serviceinfo));
        if(se_array->serviceinfos == NULL){
            wave_error_printf("内存空间分配失败");
            se_array->len = 0;
            lock_unlock(&pdb->lock);
            return FAILURE;
        }
        i=0;
        list_for_each_entry(alloc_node,alloc_head,list){
            permissions_head = &alloc_node->list;
            list_for_each_entry(permissions,permissions_head,list){
                INIT(*(se_array->serviceinfos+i));
                (se_array->serviceinfos+i)->lsis = alloc_node->lsis;
                (se_array->serviceinfos+i)->max_priority = permissions->permission.priority;
                (se_array->serviceinfos+i)->psid = permissions->permission.psid;
                string_cpy(&(se_array->serviceinfos+i)->ssp, &permissions->permission.ssp);
                i++;
            }
        }
    }
    lock_unlock(&pdb->lock);
    return SUCCESS;
}
result pssme_outoforder(struct sec_db* sdb,u64 generation_time,certificate* cert){
    struct pssme_db *pdb;
    struct list_head *head;
    struct pssme_receive_cert *node;
    pdb = &sdb->pssme_db;
    lock_wrlock(&pdb->lock);
    head = &pdb->cert_db.receive_cert.list;
    list_for_each_entry(node,head,list){
        if( certificate_equal(&node->cert,cert) == true)
            break;
    }
    if(&node->list != head){
        if(node->recent_time < generation_time){
            lock_unlock(&pdb->lock);
            return SUCCESS;
        }
        else{
            lock_unlock(&pdb->lock);
            return NOT_MOST_RECENT_WSA; 
        }
    }
    node = (struct pssme_receive_cert*)malloc(sizeof(struct pssme_receive_cert));
    if(node ==NULL){
        wave_error_printf("内存分配失败，这个错误可能会引起逻辑的混乱");
        lock_unlock(&pdb->lock);
        return SUCCESS;//这个是一个问题哈，本来这个错误在协议里面不存在，但是代码有可能会发生
    }
    INIT(*node);
    certificate_cpy(&node->cert,cert);
    node->recent_time = generation_time;
    list_add_tail(&node->list,head);
    lock_unlock(&pdb->lock);
    return SUCCESS;
}
result pssme_cryptomaterial_handle_storage(struct sec_db* sdb,cmh cmh,struct pssme_lsis_array* lsises){
   struct list_head *head;
   psid_priority_ssp *ppsp;
   
   struct certificate *cert;
   struct cme_permissions permissions;
   struct serviceinfo_array ser_array;
   pssme_lsis lsis;
   string identity;
   int i,j,k;
   if( (cert = (struct certificate*)malloc(sizeof(struct certificate))) == NULL){
        wave_error_printf("内存分配失败");
        return FAILURE;
   }
   INIT(*cert);
   INIT(permissions);
   INIT(ser_array);
   INIT(identity);

   if(find_cert_by_cmh(sdb,&cmh, cert)){
        goto fail;
   }
   if( certificate_2_buf(cert,&identity)){
        wave_error_printf("证书编码失败 ");
        goto fail;
   }
   //if( certificate_get_permissions(sdb,cert,permissions) == FAILURE)
   if( cme_certificate_info_request(sdb,ID_CERTIFICATE,&identity, NULL, &permissions,NULL,NULL,NULL,
                                             NULL,NULL) )
       goto fail;
   if(permissions.type != PSID_PRIORITY_SSP){
        wave_error_printf("permissions的type不等于PSID_PRIORITY_SSP,不能进行比较");
        goto fail;
   }
   for(i=0;i<lsises->len;i++){
        lsis = *(lsises->lsis+i);
        serviceinfo_array_free(&ser_array);
        if( pssme_get_serviceinfo(sdb,lsis,&ser_array) == FAILURE){
            goto fail;
        }
        ppsp = (permissions.u.psid_priority_ssp_array.buf + i);
        for(j=0;j<ser_array.len;j++){
            if( (ser_array.serviceinfos+j)->psid == ppsp->psid &&
                    (ser_array.serviceinfos + j)->max_priority == ppsp->max_priority ){
                if( (ser_array.serviceinfos+j)->ssp.len == ppsp->service_specific_permissions.len ){
                     for(k=0;k<ppsp->service_specific_permissions.len;k++){
                        if( *((ser_array.serviceinfos+j)->ssp.buf+k) != *(ppsp->service_specific_permissions.buf+k))
                            break;
                     } 
                     if(k == ppsp->service_specific_permissions.len)
                         break;
                }
            }
        }
        if(j==ser_array.len){
            wave_error_printf("lsis %d 没有相关的服务",lsis);
            goto fail;
        }
        
   }
    certificate_free(cert);
    free(cert);
    cme_permissions_free(&permissions);
    serviceinfo_array_free(&ser_array);
    string_free(&identity);
    return SUCCESS;
fail:
    if(cert != NULL){
        certificate_free(cert);
        free(cert);
    }
    cme_permissions_free(&permissions);
    serviceinfo_array_free(&ser_array);
    string_free(&identity);
    return FAILURE;
}

