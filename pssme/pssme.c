#include "pssme.h"
#include "cme.h"
#include<stdlib.h>
#define INIT(m) memset(&m,0,sizeof(m))

void serviceinfo_array_free(serviceinfo_array* point){
    if(point->serviceinfos == NULL)
        return;
    free(point->serviceinfos);
    point->serviceinfos = NULL;
    point->len = 0;
};

void lsis_array_free(lsis_array* lsises){
    if(lsises->lsis == NULL)
        return ;
    free(lsises->lsis);
    lsises->len = 0;
    lsises->lsis = NULL;
}

//未测
void pssme_local_cert_node_free(struct pssme_local_cert *node){
    if(!node){
        lsis_array_free(&node->lsis_array);
        free(node);
        node = NULL;
    }
}
//未测
void pssme_local_cert_list_free(struct list_head *head){
    struct pssme_local_cert *node = NULL;
    if(head != NULL){
        while(!list_empty(head)){
            node = list_entry(head->next, struct pssme_local_cert, list);
            list_del(&node->list);
            pssme_local_cert_node_free(node);
        }
        head->next = head->prev = NULL;
    }
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
    lock_rdlock(sdb->pssme_db.lock);
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
            if(p_add == NULL)
                goto fail;
            p_add->cmh = p->cmh;
            p_add->lsis_array.len = p->lsis_array.len;
            p_add->lsis_array.lsis = malloc(sizeof(pssme_lsis)*p_add->lsis_array.len);
            memcpy(p_add->lsis_array.lsis, p->lsis_array.lsis, sizeof(pssme_lsis)*p_add->lsis_array.len);
            list_add(&p_add->list, &clist.list);
        }
    }
    lock_unlock(sdb->pssme_db.lock);

    if(list_empty(&clist.list)){
        ret = CERTIFICATE_NOT_FOUND;
        goto fail;
    }

    certificate_found = false;
    list_for_each(p, &clist.list, list){
        if(!find_cert_by_cmh(sdb, &p->cmh, &c))
            continue;
        if(!cert_not_expired(p->cmh))
            continue;
        certificate_encode(c, &cert_encoded);//这个函数需要判断能否成功吗
        ret = cme_certificate_info_request(sdb, ID_CERTIFICATE, cert_encoded, NULL, current_cert_permissions, geo_permissions, NULL, NULL, NULL, NULL);
        if(!geo_permissions_contains_location(geo_permissions))
            continue;
        if(permission_ind != NULL){
            permission_ind->len = se_array->len;
            permission_ind->buf = malloc(sizeof(u8)*se_array->len);
            if(permission_ind->buf == NULL)
                goto fail;
            memset(permission_ind->buf, 0, sizeof(u8)*se_array->len);
            for(j = 0; j < se_array->len; j++){
                if(se_array->serviceinfos[j].lsis == 0){
                    permission_ind->buf[j] == 0;
                    continue;
                }
                for(k = 0; k < p->lsis_array.len; k++){
                    if(p->lsis_array.lsis[k] != se_array->serviceinfos[j].lsis)
                        continue;
                    if(!same_psid(se_array->serviceinfos[j].psid, current_cert_permissions->u.psid_priority_ssp_array.u.permissions_list.psid))
                        continue;
                    if(!same_ssp(se_array->serviceinfos[j].ssp, current_cert_permissions->u.psid_priority_ssp_array.u.permissions_list.service_specific_permissions))
                        continue;
                    if(se_array->serviceinfos[j].priority > current_cert_permissions->u.psid_priority_ssp_array.u.permissions_list.max_priority)
                        continue;
                    permission_ind[j] = k+1;
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
    ret = cme_construct_certificate_chain(sdb, ID_CERTIFICATE, NULL, &chain, false, 6, cert_chain, NULL, NULL);
    if(ret == SUCCESS && cmh != NULL)
        *cmh = p->cmh;
fail:
    pssme_local_cert_list_free(&clist.list);
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
        goto FAILURE;
    }
    INIT(*pssme_alloc_lsis);

    lock_wrlock(&pdb->lock);
    head = pdb->lsis_db.lsises;
    
    if(list_empty(head)){
        lock_unlock(&pdb->lock);
        goto FAILURE;
    }
    node = list_entry(head->next,struct pssme_lsis_chain,list);
    alloc_node->lsis = node->list;
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
