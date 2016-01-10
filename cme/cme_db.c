#include"cme_db.h"
#include"utils/lock.h"
#include"sec/sec_db.h"
#include<stdio.h>
#include<string.h>
#include<error.h>
#define CMH_MAX_NUM 1024
#define LSIS_MAX_NUM 1024
#define CERTIFICATE_BUF_LNE 1024
#define READ_BUF_LEN 1024

#define INIT(n) memset(&n,0,sizeof(n))
void inline cme_alloced_lsis_free(struct cme_alloced_lsis* alloced_lsis){
    if(alloced_lsis == NULL)
        return;
    string_free(&alloced_lsis->data);
}
void inline cmh_keypaired_free(struct cmh_keypaired* cmh_keys){
    if(cmh_keys == NULL)
        return ;
    string_free(&cmh_keys->private_key);
    string_free(&cmh_keys->public_key_x);
    string_free(&cmh_keys->public_key_y);
}
void inline cmh_key_cert_free(struct  cmh_key_cert* key_cert){
    if(key_cert == NULL)
        return ;
    certificate_free(key_cert->cert);
    key_cert->cert = NULL;
}
void inline cert_info_free(struct cert_info* certinfo){
    if(certinfo == NULL)
        return ;
    if(certinfo->cert != NULL){
        certificate_free(certinfo->cert);
        certinfo->cert = NULL;
    }
}
/**
 * alloced_lsis链表按照递增的顺序维护
 */
void cme_lsis_insert(struct cme_db* cmdb,struct cme_alloced_lsis* lsis){
    struct list_head *head;
    struct cme_alloced_lsis *node;
    lock_wrlock(&cmdb->lock);
    head = &cmdb->cmhs.alloc_cmhs.cmh_init.list;
    list_for_each_entry(node,head,list){
        if(lsis->lsis < node->lsis){
            break;
        }     
    }
    list_add_tail(&lsis->list,&node->list);
    lock_unlock(&cmdb->lock);
}
/**
 * cmh_init链表按照递增的顺序维护
 */
void cme_cmh_init_insert(struct cme_db* cmdb,struct cmh_chain* cmh){
    struct list_head *head;
    struct cmh_chain *node;
    lock_wrlock(&cmdb->lock);
    head = &cmdb->cmhs.alloc_cmhs.cmh_init.list;
    list_for_each_entry(node,head,list){
        if(cmh->cmh < node->cmh){
            break;
        }     
    }
    list_add_tail(&cmh->list,&node->list);
    lock_unlock(&cmdb->lock);
}

/**************cert_info 红黑书函数操作开始************/

static int cert_info_compare(struct rb_head* a,struct rb_head* b){
    struct cert_info *certinfoa,*certinfob;
    certinfoa = rb_entry(a,struct cert_info,rb);
    certinfob = rb_entry(b,struct cert_info,rb);
    return certid10_cmp(&certinfoa->certid10,&certinfob->certid10);
}
static int cert_info_equal(struct rb_head* a,void* value){
    struct cert_info_cmp* ptr;
    struct cert_info *certinfoa;
    int i;
    ptr = (struct cert_info_cmp*)value;
    certinfoa = rb_entry(a,struct cert_info,rb);
    printf(HASHEDID8_FORMAT"\n",HASHEDID8_VALUE(ptr->u.hashedid8));
    if(ptr->type == ID_HASHEDID8){
        for(i=0;i<8;i++){
            //注意高地位是怎么回事>>
           if( certinfoa->certid10.certid10[i+2] < ptr->u.hashedid8.hashedid8[i]) 
               return -1;
           if( certinfoa->certid10.certid10[i+2] > ptr->u.hashedid8.hashedid8[i])
               return 1;
        }
        return 0;
    }
    if(ptr->type == ID_CERTID10){
        return certid10_cmp(&certinfoa->certid10,&ptr->u.certid10);
    }
    return -1;
}
void cert_info_init_rb(struct cert_info* certinfo){
    rb_init(&certinfo->rb,cert_info_compare,cert_info_equal);
}
struct cert_info*  cert_info_insert(struct cert_info* root,struct cert_info* node){
    struct rb_head *rb;
    if( root != NULL)
        rb = rb_insert(&root->rb,&node->rb);
    else
        rb = rb_insert(NULL,&node->rb);
    return rb_entry(rb,struct cert_info,rb);
}
struct cert_info* cert_info_find(struct cert_info* root,void* value){
    struct rb_head* rb;
    if(root == NULL){
        wave_printf(MSG_DEBUG,"cert_info root == NULL  %s %d",__FILE__,__LINE__);
        return NULL;
    }
    rb = rb_find(&root->rb,value);
    if(rb == NULL)
        return NULL;
    return rb_entry(rb,struct cert_info,rb);   
}
struct cert_info* cert_info_delete(struct cert_info* root,struct cert_info* node){
    struct rb_head* rb;
    if(root == NULL)
        return NULL;
    rb = rb_delete(&root->rb,&node->rb);
    if(rb == NULL)
        return NULL;
    return rb_entry(rb,struct cert_info,rb);
}
/**************cert_info 红黑书函数操作结束*************/


/************cmh_key_cert 红黑书函数操作开始*********/
int compare(struct rb_head *a,struct rb_head *b){
    struct cmh_key_cert *ckca,*ckcb;
    ckca = rb_entry(a,struct cmh_key_cert,rb);
    ckcb = rb_entry(b,struct cmh_key_cert,rb);
    if(ckca->cmh < ckcb->cmh)
        return -1;
    if(ckca->cmh == ckcb->cmh);
        return 0;
    return 1;
}
int equal(struct rb_head *a,void* value){
    struct cmh_key_cert *ckca;
    cmh mvalue = *(cmh*)value;
    ckca =  rb_entry(a,struct cmh_key_cert,rb);
    if(ckca->cmh < mvalue)
        return -1;
    if(ckca->cmh == mvalue)
        return 0;
    return 1;
}
void ckc_init_rb(struct cmh_key_cert* ckc){
    rb_init(&ckc->rb,compare,equal);
}
struct cmh_key_cert*  ckc_insert(struct cmh_key_cert* root,struct cmh_key_cert* node){
    struct rb_head *rb;
    if( root != NULL)
        rb = rb_insert(&root->rb,&node->rb);
    else
        rb = rb_insert(NULL,&node->rb);
    return rb_entry(rb,struct cmh_key_cert,rb);
}
struct cmh_key_cert*  ckc_find(struct cmh_key_cert* root,void* value){
    struct rb_head* rb;
    if(root == NULL)
        return NULL;
    rb = rb_find(&root->rb,value);
    if(rb == NULL)
        return NULL;
    return rb_entry(rb,struct cmh_key_cert,rb);
}
struct cmh_key_cert*  ckc_delete(struct cmh_key_cert* root,struct cmh_key_cert* node){
    struct rb_head* rb;
    if(root == NULL)
        return NULL;
    rb = rb_delete(&root->rb,&node->rb);
    if(rb == NULL)
        return NULL;
    return rb_entry(rb,struct cmh_key_cert,rb);
}
/***************cmh_key_cert 红黑树操作函数结束**************/

void cme_db_free(struct cme_db* cdb){
    struct cert_info *cinfo;
    struct list_head *series_head,*ca_head,*serial_head,*head;
    struct crl_head *series_temp;
    struct crl_ca_id *ca_temp;
    struct crl_serial_number* serial_temp;
    struct cme_lsis_chain *cme_lsis_chain_temp;
    struct cme_alloced_lsis *cme_alloced_lsis_temp;
    struct cmh_chain *cmh_chain_temp;
    struct cmh_keypaired *cmh_keys_temp;
    struct cmh_key_cert *cmh_key_cert_temp; 
    if(cdb == NULL)
        return;
    lock_wrlock(&cdb->lock);
    while(cdb->certs != NULL){
        cinfo = cdb->certs;
        cdb->certs = cert_info_delete(cdb->certs,cinfo);
        cert_info_free(cinfo);
        free(cinfo);
    }
    while(!list_empty(&cdb->crls.list)){
        series_head = &cdb->crls.list;
        series_temp = list_entry(series_head->next,struct crl_head,list);
        while(!list_empty(&series_temp->ca_id_list.list)){
            ca_head = &series_temp->ca_id_list.list;
            ca_temp = list_entry(ca_head->next,struct crl_ca_id,list);
            while(!list_empty(&ca_temp->crl_info_list.list)){
                serial_head = &ca_temp->crl_info_list.list;
                serial_temp = list_entry(serial_head->next,struct crl_serial_number,list);
                list_del(&serial_temp->list);
                free(serial_temp);
            }
            list_del(&ca_temp->list);
            free(ca_temp);
        }
        list_del(&series_temp->list);
        free(series_temp);
    }
    head = &cdb->lsises.alloced_lsis.list;
    while(!list_empty(head)){
        cme_alloced_lsis_temp = list_entry(head->next,struct cme_alloced_lsis,list);
        list_del(&cme_alloced_lsis_temp->list);
        cme_alloced_lsis_free(cme_alloced_lsis_temp);
        free(cme_alloced_lsis_temp);
    }
    head = &cdb->lsises.lsises.list;
    while(!list_empty(head)){
        cme_lsis_chain_temp = list_entry(head->next,struct cme_lsis_chain,list);
        list_del(&cme_lsis_chain_temp->list);
        free(cme_lsis_chain_temp);
    }
    
    head = &cdb->cmhs.alloc_cmhs.cmh_init.list;
    while(!list_empty(head)){
        cmh_chain_temp = list_entry(head->next,struct cmh_chain,list);
        list_del(&cmh_chain_temp->list);
        free(cmh_chain_temp);
    }

    head = &cdb->cmhs.alloc_cmhs.cmh_keys.list;
    while(!list_empty(head)){
        cmh_keys_temp = list_entry(head->next,struct cmh_keypaired,list);
        list_del(&cmh_keys_temp->list);
        cmh_keypaired_free(cmh_keys_temp);
        free(cmh_keys_temp);
    }
    
    while(cdb->cmhs.alloc_cmhs.cmh_key_cert != NULL){
        cmh_key_cert_temp = cdb->cmhs.alloc_cmhs.cmh_key_cert;
        cdb->cmhs.alloc_cmhs.cmh_key_cert = ckc_delete(cdb->cmhs.alloc_cmhs.cmh_key_cert,cmh_key_cert_temp);
        cmh_key_cert_free(cmh_key_cert_temp);
        free(cmh_key_cert_temp);
    }
    
    head = &cdb->cmhs.cmh_chain.list;
    while(!list_empty(head)){
        cmh_chain_temp = list_entry(head->next,struct cmh_chain,list);
        list_del(&cmh_chain_temp->list);
        free(cmh_chain_temp);
    }
    lock_unlock(&cdb->lock);
    lock_destroy(&cdb->lock);
}
int cme_db_init(struct cme_db *cdb){
    if(cdb == NULL){
        wave_error_printf("传入参数有问题  %s %d",__FILE__,__LINE__);
        return -1;
    }
    cdb->certs = NULL;
    INIT_LIST_HEAD(&cdb->crls.list);
    if(lock_init(&cdb->lock)){
        wave_error_printf("锁初始化失败  %s %d",__FILE__,__LINE__);
        return -1;
    }
    INIT_LIST_HEAD(&cdb->lsises.alloced_lsis.list);
    INIT_LIST_HEAD(&cdb->lsises.lsises.list);
    INIT_LIST_HEAD(&cdb->cmhs.alloc_cmhs.cmh_init.list);
    INIT_LIST_HEAD(&cdb->cmhs.alloc_cmhs.cmh_keys.list);
    cdb->cmhs.alloc_cmhs.cmh_key_cert = NULL;
    INIT_LIST_HEAD(&cdb->cmhs.cmh_chain.list); 
    return 0;
}
static int get_ca_cert(struct certificate* cert){
    FILE *fp;
    string str;

    INIT(str);
    fp = fopen("./cert/ca_cert/ca.cert","r");
    if(fp == NULL){
        wave_error_printf("没有ca证书，请查看路径有问题没有 %s %d",__FILE__,__LINE__);
        return -1;
    }
    str.len = 400;
    str.buf = (u8*)malloc(str.len);
    if(str.buf == NULL){
        wave_malloc_error();
        fclose(fp);
        return -1;
    }
    str.len = fread(str.buf,1,str.len,fp);
    if(str.len <= 0){
        wave_error_printf("读取文件出现了错误 %s %d",__FILE__,__LINE__);
        fclose(fp);
        string_free(&str);
        return -1;
    }
    if(string_2_certificate(&str,cert) <=0 ){
        wave_error_printf("证书解码有问题  %s %d",__FILE__,__LINE__);
        fclose(fp);
        string_free(&str);
        return -1;
    }
    fclose(fp);
    string_free(&str);
    return 0;
}
static int get_ca_pri(string *str){
    FILE *fp;

    fp = fopen("./cert/ca_cert/ca.veri.pri","r");
    if(fp == NULL){
        wave_error_printf("没有ca证书，请查看路径有问题没有 %s %d",__FILE__,__LINE__);
        return -1;
    }
    str->len = 400;
    str->buf = (u8*)malloc(str->len);
    if(str->buf == NULL){
        wave_malloc_error();
        fclose(fp);
        return -1;
    }
    str->len = fread(str->buf,1,str->len,fp);
    if(str->len <= 0){
        wave_error_printf("读取文件出现了错误 %s %d",__FILE__,__LINE__);
        fclose(fp);
        string_free(str);
        return -1;
    }
    fclose(fp);
    return 0;
}
int cme_db_empty_init(struct sec_db* sdb){
    struct cme_lsis_chain* lsis_node;
    struct cmh_chain* cmh_node;
    struct cmh_key_cert *key_cert;
    struct cmh_chain *ca_cmh;
    struct cme_db *cdb;
    struct certificate ca;
    string pri;
    int i;
    cdb = &sdb->cme_db;
    cdb->certs = NULL;
    INIT_LIST_HEAD(&cdb->crls.list);
    lock_init(&cdb->lock);
    
    INIT_LIST_HEAD(&cdb->lsises.alloced_lsis.list);
    INIT_LIST_HEAD(&cdb->lsises.lsises.list);

    for(i=1;i<=LSIS_MAX_NUM;i++){
        if( (lsis_node = (struct cme_lsis_chain*)malloc(sizeof(struct cme_lsis_chain))) == NULL){
            wave_malloc_error();
            cme_db_free(cdb);
            return -1;
        }
        lsis_node->lsis = i;
        list_add_tail(&lsis_node->list,&cdb->lsises.lsises.list);
    }

    INIT_LIST_HEAD(&cdb->cmhs.alloc_cmhs.cmh_init.list);
    INIT_LIST_HEAD(&cdb->cmhs.alloc_cmhs.cmh_keys.list);
    cdb->cmhs.alloc_cmhs.cmh_key_cert = NULL;
   
    INIT_LIST_HEAD(&cdb->cmhs.cmh_chain.list); 
    //1这个指 直接给ca
    for(i=2;i<=CMH_MAX_NUM;i++){
        if( (cmh_node = (struct cmh_chain*)malloc(sizeof(struct cmh_chain))) == NULL){
            wave_malloc_error();
            cme_db_free(cdb);
            return -1;
        }
        cmh_node->cmh = i;
        list_add_tail(&cmh_node->list,&cdb->cmhs.cmh_chain.list);
    }

    //这里我要为他载入默认的ca
    ca_cmh = (struct cmh_chain*)malloc(sizeof(struct cmh_chain));
    if(ca_cmh == NULL){
        wave_malloc_error();
        cme_db_free(cdb);
        return -1;
    }
    ca_cmh->cmh = 1;
    list_add_tail(&ca_cmh->list,&cdb->cmhs.alloc_cmhs.cmh_init.list);
    INIT(ca);
    INIT(pri);
    if(get_ca_cert(&ca) || get_ca_pri(&pri)){
        wave_error_printf("获取初始ca有问题 %s %d",__FILE__,__LINE__);
        cme_db_free(cdb);
        return -1;
    }
    
    if(cme_store_cert_key(sdb,1,&ca,&pri)){
        cme_db_free(cdb);
        return -1;
    }
    string_free(&pri);
    certificate_free(&ca);
    return 0;
}
static int cmh_chain_2_file(struct cmh_chain* cmh,FILE *fp){
    if(fwrite(&cmh->cmh,sizeof(cmh->cmh),1,fp) != 1){
        wave_error_printf("写入文件有问题 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int cmh_keypaired_2_file(struct cmh_keypaired* cmh_keys,FILE *fp){
    if( fwrite(&cmh_keys->cmh,sizeof(cmh_keys->cmh),1,fp) != 1 ||
            fwrite(&cmh_keys->algorithm,sizeof(cmh_keys->algorithm),1,fp) != 1||
            fwrite(&cmh_keys->public_key_x.len,sizeof(cmh_keys->public_key_x.len),1,fp) != 1||
            fwrite(cmh_keys->public_key_x.buf,1,cmh_keys->public_key_x.len,fp) != cmh_keys->public_key_x.len ||
            fwrite(&cmh_keys->public_key_y.len,sizeof(cmh_keys->public_key_y.len),1,fp) != 1||
            fwrite(cmh_keys->public_key_y.buf,1,cmh_keys->public_key_y.len,fp) != cmh_keys->public_key_y.len ||
            fwrite(&cmh_keys->private_key.len,sizeof(cmh_keys->private_key.len),1,fp) != 1||
            fwrite(cmh_keys->private_key.buf,1,cmh_keys->private_key.len,fp) != cmh_keys->private_key.len){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}   
static int cmh_key_cert_2_file(struct cmh_key_cert* key_cert,FILE *fp){
    char* buf = NULL;
    int len;
    int res = 0;
    string cert_string;
    if(fwrite(&key_cert->cmh,sizeof(key_cert->cmh),1,fp) != 1||
            fwrite(&key_cert->private_key.len,sizeof(key_cert->private_key.len),1,fp) != 1||
            fwrite(key_cert->private_key.buf,1,key_cert->private_key.len,fp) != key_cert->private_key.len){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    memset(&cert_string,0,sizeof(cert_string));
    if( certificate_2_string(key_cert->cert,&cert_string)){
        wave_error_printf("证书编码失败 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
   
    if( fwrite(cert_string.buf,1,cert_string.len,fp) != cert_string.len){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    goto end;
end:
    string_free(&cert_string);
    return res;
}
static int alloced_cmhs_2_file(struct alloced_cmhs* alloced_cmh,FILE *fp){
    struct list_head *head;
    int len =0;
    struct cmh_chain* cmh_temp;
    struct cmh_keypaired* cmh_keys_temp;
    struct cmh_key_cert* cmh_cert;
    char end = 0;
    head = &alloced_cmh->cmh_init.list;
    list_for_each_entry(cmh_temp,head,list){
        len++;
    }
    if( fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(cmh_temp,head,list){
        if(cmh_chain_2_file(cmh_temp,fp))
            return -1;
    }
    
    head = &alloced_cmh->cmh_keys.list;
    len =0;
    list_for_each_entry(cmh_keys_temp,head,list){
        len++;
    }
    if( fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(cmh_keys_temp,head,list){
        if(cmh_keypaired_2_file(cmh_keys_temp,fp))
            return -1;
    }

    while(alloced_cmh->cmh_key_cert != NULL){
        cmh_cert = alloced_cmh->cmh_key_cert;
        alloced_cmh->cmh_key_cert = ckc_delete(alloced_cmh->cmh_key_cert,cmh_cert);
        if( cmh_key_cert_2_file(cmh_cert,fp)){
            cmh_key_cert_free(cmh_cert);
            free(cmh_cert);
            return -1;
        }
        cmh_key_cert_free(cmh_cert);
        free(cmh_cert);
    }
    //结束标志，因为cmh不会为0，所以可以这样
    if( fwrite(&end,sizeof(end),1,fp) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int cmhs_2_file(struct cme_db* cdb,FILE *fp){
    int len=0;
    struct list_head *head;
    struct cmh_chain *cmh_temp;
    if( alloced_cmhs_2_file(&cdb->cmhs.alloc_cmhs,fp))
        return -1;
    head = &cdb->cmhs.cmh_chain.list;
    list_for_each_entry(cmh_temp,head,list){
        len++;
    }
    if(fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入文件有问题 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(cmh_temp,head,list){
        if(cmh_chain_2_file(cmh_temp,fp))
            return -1;
    }
    return 0;
}
static int cme_lsis_chain_2_file(struct cme_lsis_chain* lsis,FILE *fp){
    if( fwrite(&lsis->lsis,sizeof(lsis->lsis),1,fp) != 1){
        wave_error_printf("书写有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int cme_alloced_lsis_2_file(struct cme_alloced_lsis* alloced_lsis,FILE *fp){
    if( fwrite(&alloced_lsis->lsis,sizeof(alloced_lsis->lsis),1,fp) != 1){
        wave_error_printf("书写有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    if (fwrite(&alloced_lsis->data.len,sizeof(alloced_lsis->data.len),1,fp) != 1||
            fwrite(alloced_lsis->data.buf,1,alloced_lsis->data.len,fp) != alloced_lsis->data.len){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int lsises_2_file(struct cme_db* cdb,FILE *fp){
    struct list_head *head;
    struct cme_alloced_lsis* alloced_temp;
    struct cme_lsis_chain* lsis_temp;
    int len=0;
    head = &cdb->lsises.alloced_lsis.list;
    list_for_each_entry(alloced_temp,head,list){
        len++;
    }
    if( fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入文件出粗 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(alloced_temp,head,list){
        if(cme_alloced_lsis_2_file(alloced_temp,fp))
            return -1;        
    }

    len=0;
    head = &cdb->lsises.lsises.list;
    list_for_each_entry(lsis_temp,head,list){
        len++;
    }
    if( fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入文件出粗 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(lsis_temp,head,list){
        if(cme_lsis_chain_2_file(lsis_temp,fp))
            return -1;        
    }
    return 0;
}
static int revoked_cert_2_file(struct revoked_certs *revoked_cert,FILE *fp){
    if( fwrite(&revoked_cert->certid,sizeof(revoked_cert->certid),1,fp) != 1){
        wave_error_printf("写入错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int crl_serial_number_2_file(struct crl_serial_number* serial_number,FILE *fp){
    if( fwrite(&serial_number->serial_number,sizeof(serial_number->serial_number),1,fp) != 1||
            fwrite(&serial_number->start_period,sizeof(serial_number->start_period),1,fp) != 1||
            fwrite(&serial_number->issue_date,sizeof(serial_number->issue_date),1,fp) != 1||
            fwrite(&serial_number->next_crl_time,sizeof(serial_number->next_crl_time),1,fp) != 1||
            fwrite(&serial_number->type,sizeof(serial_number->type),1,fp) != 1){
        wave_error_printf("写入错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int crl_ca_id_2_file(struct crl_ca_id* ca_node,FILE *fp){
    struct list_head *head;
    struct crl_serial_number *serial_temp;
    struct revoked_certs *revoked_cert;
    int len = 0;

    if( fwrite(&ca_node->ca_id,sizeof(ca_node->ca_id),1,fp) != 1){
        wave_error_printf("写入出错 %s %d",__FILE__,__LINE__);
        return -1;
    }
    head = &ca_node->crl_info_list.list;
    list_for_each_entry(serial_temp,head,list){
        len++;
    }
    if( fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入出错 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(serial_temp,head,list){
        if( crl_serial_number_2_file(serial_temp,fp))
            return -1;
    }
    len = 0;
    head = &ca_node->revoked_certs.list;
    list_for_each_entry(revoked_cert,head,list){
        len++;
    }
    if( fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入出错 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(revoked_cert,head,list){
        if(revoked_cert_2_file(revoked_cert,fp))
            return -1;
    }
    return 0;
}
static int crl_series_2_file(struct crl_head *crl_series,FILE *fp){
    struct list_head* head;
    struct crl_ca_id *ca_temp;
    int len = 0;
    if( fwrite(&crl_series->crl_series,sizeof(crl_series->crl_series),1,fp) != 1){
        wave_error_printf("写入文件出错哦 %s %d",__FILE__,__LINE__);
        return -1;
    }

    head = &crl_series->ca_id_list.list;
    list_for_each_entry(ca_temp,head,list){
        len++;
    }
    if( fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入文件出错 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(ca_temp,head,list){
        if( crl_ca_id_2_file(ca_temp,fp) ){
            return -1;
        }    
    }
    return 0;
}
static int crls_2_file(struct cme_db* cdb,FILE *fp){
    struct list_head *series_head;
    struct crl_head *series_temp;
    int len=0;
    series_head = &cdb->crls.list;
    list_for_each_entry(series_temp,series_head,list){
        len++;
    }
    //写如从的有多少个节点
    if( fwrite(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("写入文件出错 %s %d",__FILE__,__LINE__);
        return -1; 
    }
    list_for_each_entry(series_temp,series_head,list){
        if(crl_series_2_file(series_temp,fp)){
            return -1;
        }
    }
    return 0;
}
static int cert_info_2_file(struct cert_info *cinfo,FILE *fp){
    string cert_string;
    int res = 0;
    int len;
    memset(&cert_string,0,sizeof(cert_string));
    if( certificate_2_string(cinfo->cert,&cert_string)){
        wave_error_printf("证书编码失败");
        res = -1;
        goto end;
    }
    if(  fwrite(cert_string.buf,1,cert_string.len,fp) != cert_string.len ||
            fwrite(cinfo->certid10.certid10,1,10,fp) != 10 ||
            fwrite(&cinfo->verified,sizeof(cinfo->verified),1,fp) != 1 ||
            fwrite(&cinfo->trust_anchor,sizeof(cinfo->trust_anchor),1,fp) != 1 ||
            fwrite(&cinfo->revoked,sizeof(cinfo->revoked),1,fp) != 1 ||
            fwrite(&cinfo->expriry,sizeof(cinfo->expriry),1,fp) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    goto end;
end:
    string_free(&cert_string);
    return res;
}
static int certs_2_file(struct cme_db *cdb,FILE *fp){
    struct cert_info *cinfo; 
    char buf = 0;
    cinfo = cdb->certs;
    while(cinfo != NULL){
        cdb->certs = cert_info_delete(cdb->certs,cinfo);
        if( cert_info_2_file(cinfo,fp)){
            cert_info_free(cinfo);
            free(cinfo);
            return -1;
        }
        //cert_info_free(cinfo);
        free(cinfo);
        cinfo = cdb->certs;
    }
    //书写一个0标志结束，因为证书的第一个字节不可能为0
    if( (fwrite(&buf,sizeof(char),1,fp) != 1)){
        wave_error_printf("写入出错 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
int cme_db_2_file(struct cme_db *cdb,char *name){
    FILE *fp;
    fp = fopen(name,"w");
    if(fp == NULL){
        wave_error_printf("文件打开失败 %s %d",__FILE__,__LINE__);
        return -1;
    } 
    lock_wrlock(&cdb->lock);
    if( certs_2_file(cdb,fp))
        goto fail;
    if( crls_2_file(cdb,fp))
        goto fail;
    if( lsises_2_file(cdb,fp))
        goto fail;
    if(cmhs_2_file(cdb,fp))
        goto fail;
    fclose(fp);
    lock_unlock(&cdb->lock); 
    return 0;
fail:
    fclose(fp);
    lock_unlock(&cdb->lock);
    return -1;
}
static int file_2_cmh_chain(struct cmh_chain* cmh,FILE *fp){
    if(fread(&cmh->cmh,sizeof(cmh->cmh),1,fp) != 1){
        wave_error_printf("read写入文件有问题 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int file_2_cmh_keypaired(struct cmh_keypaired* cmh_keys,FILE *fp){
    if( fread(&cmh_keys->cmh,sizeof(cmh_keys->cmh),1,fp) != 1 ||
            fread(&cmh_keys->algorithm,sizeof(cmh_keys->algorithm),1,fp) != 1||
            fread(&cmh_keys->public_key_x.len,sizeof(cmh_keys->public_key_x.len),1,fp) != 1||
            fread(cmh_keys->public_key_x.buf,1,cmh_keys->public_key_x.len,fp) != cmh_keys->public_key_x.len ||
            fread(&cmh_keys->public_key_y.len,sizeof(cmh_keys->public_key_y.len),1,fp) != 1||
            fread(cmh_keys->public_key_y.buf,1,cmh_keys->public_key_y.len,fp) != cmh_keys->public_key_y.len ||
            fread(&cmh_keys->private_key.len,sizeof(cmh_keys->private_key.len),1,fp) != 1||
            fread(cmh_keys->private_key.buf,1,cmh_keys->private_key.len,fp) != cmh_keys->private_key.len){
        wave_error_printf("read文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int file_2_cmh_key_cert(struct cme_db *cdb,struct cmh_key_cert* key_cert,FILE *fp){
    int res = 0;
    char *buf;
    certificate *cert = NULL;
    certid10 certid;
    struct cert_info* cinfo;
    struct cert_info_cmp cinfo_cmp;
    int len,cert_len;
    
    if(fread(&key_cert->cmh,sizeof(key_cert->cmh),1,fp) != 1||
            fread(&key_cert->private_key.len,sizeof(key_cert->private_key.len),1,fp) != 1){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    key_cert->private_key.buf = (u8*)malloc(key_cert->private_key.len);
    if(key_cert->private_key.buf == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    if( fread(key_cert->private_key.buf,1,key_cert->private_key.len,fp) != key_cert->private_key.len){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    if( (buf = (char*)malloc(READ_BUF_LEN)) == NULL ||
            (cert = (certificate*)malloc(sizeof(certificate))) == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    memset(cert,0,sizeof(certificate));

    if( (len = fread(buf,1,READ_BUF_LEN,fp)) <= 0){
        wave_error_printf("read文件错误 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    if( (cert_len = buf_2_certificate(buf,len,cert)) <0){
        wave_error_printf("证书解码失败 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    fseek(fp,cert_len-len,SEEK_CUR);
    if(certificate_2_certid10(cert,&certid)){
        res = -1;
        goto end;    
    }
    cinfo_cmp.type = ID_CERTID10;
    certid10_cpy(&cinfo_cmp.u.certid10,&certid);
    cinfo = cert_info_find(cdb->certs,&cinfo_cmp.type);
    if(cinfo == NULL){
        wave_error_printf("怎么可能没有  有问题哦 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    key_cert->cert = cinfo->cert;
    key_cert->cert_info = cinfo;
    cinfo->key_cert = key_cert;
    goto end;
end:
    if(buf != NULL)
        free(buf);
    if( cert != NULL){
        certificate_free(cert);
        free(cert);
    }
    return res;
}
static int file_2_alloced_cmhs(struct cme_db *cdb,struct alloced_cmhs* alloced_cmh,FILE *fp){
    int len,i;
    struct cmh_chain *cmh_temp;
    struct cmh_keypaired* cmh_keys_temp;
    struct cmh_key_cert* key_cert_temp;
    char end=0,flag;
    if( fread(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("read文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        if( (cmh_temp = (struct cmh_chain*)malloc(sizeof(struct cmh_chain))) == NULL){
            wave_malloc_error();
            return -1;
        }
        if( file_2_cmh_chain(cmh_temp,fp)){
            free(cmh_temp);
            return -1;
        }
        list_add_tail(&cmh_temp->list,&alloced_cmh->cmh_init.list);
    }
    
    if( fread(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("read文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        if( (cmh_keys_temp = (struct cmh_keypaired*)malloc(sizeof(struct cmh_keypaired))) == NULL){
            wave_malloc_error();
            return -1;
        }
        if( file_2_cmh_keypaired(cmh_keys_temp,fp)){
            free(cmh_keys_temp);
            return -1;
        }
        list_add_tail(&cmh_keys_temp->list,&alloced_cmh->cmh_keys.list);
    }
    
    if( fread(&flag,sizeof(flag),1,fp) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    while(flag != end){
        fseek(fp,-sizeof(flag),SEEK_CUR);
        key_cert_temp = (struct cmh_key_cert*)malloc(sizeof(struct cmh_key_cert));
        if( key_cert_temp == NULL){
            wave_malloc_error();
            return -1;
        }
        memset(key_cert_temp,0,sizeof(struct cmh_key_cert));
        ckc_init_rb(key_cert_temp); 
        if( file_2_cmh_key_cert(cdb,key_cert_temp,fp)){
            cmh_key_cert_free(key_cert_temp);
            free(key_cert_temp);
            return -1;
        }
        alloced_cmh->cmh_key_cert = ckc_insert(alloced_cmh->cmh_key_cert,key_cert_temp);
        
        if( fread(&flag,sizeof(flag),1,fp) != 1){
            wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
            return -1;
        }

    }
    return 0;
    
}
static int file_2_cmhs(struct cme_db* cdb,FILE *fp){
    int len,i;
    struct cmh_chain *cmh_temp;
    if( file_2_alloced_cmhs(cdb,&cdb->cmhs.alloc_cmhs,fp)){
        return -1;
    }
    if(fread(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("read文件有问题 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        if( (cmh_temp  = (struct cmh_chain*)malloc(sizeof(struct cmh_chain))) == NULL){
            wave_malloc_error();
            return-1;
        }
        if( file_2_cmh_chain(cmh_temp,fp)){
            free(cmh_temp);
            return -1;
        }
        list_add_tail(&cmh_temp->list,&cdb->cmhs.cmh_chain.list);
    }
    return 0;
}
static int file_2_cme_lsis_chain(struct cme_lsis_chain* lsis,FILE *fp){
    if( fread(&lsis->lsis,sizeof(lsis->lsis),1,fp) != 1){
        wave_error_printf("读取文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int file_2_cme_alloced_lsis(struct cme_alloced_lsis* alloced_lsis,FILE *fp){
    if( fread(&alloced_lsis->lsis,sizeof(alloced_lsis->lsis),1,fp) != 1){
        wave_error_printf("读取文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    if (fread(&alloced_lsis->data.len,sizeof(alloced_lsis->data.len),1,fp) != 1||
            fread(alloced_lsis->data.buf,1,alloced_lsis->data.len,fp) != alloced_lsis->data.len){
        wave_error_printf("读取文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int file_2_lsises(struct cme_db* cdb,FILE *fp){
    struct cme_alloced_lsis* alloced_temp;
    struct cme_lsis_chain* lsis_temp;
    int len,i;
    if(fread(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("读取文件出错了 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        if( (alloced_temp = (struct cme_alloced_lsis*)malloc(sizeof(struct cme_alloced_lsis))) == NULL){
            wave_malloc_error();
            return -1;
        }
        if( file_2_cme_alloced_lsis(alloced_temp,fp)) {
            free(alloced_temp);
            return -1;
        }
        list_add_tail(&alloced_temp->list,&cdb->lsises.alloced_lsis.list);
    }
    
    if(fread(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("读取文件出错了 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        if( (lsis_temp = (struct cme_lsis_chain*)malloc(sizeof(struct cme_lsis_chain))) == NULL){
            wave_malloc_error();
            return -1;
        }
        if( file_2_cme_lsis_chain(lsis_temp,fp)) {
            free(lsis_temp);
            return -1;
        }
        list_add_tail(&lsis_temp->list,&cdb->lsises.lsises.list);
    }
    return 0;
}

static int file_2_revoked_cert(struct revoked_certs* revoked_cert,FILE *fp){
    if(fread(&revoked_cert->certid,sizeof(revoked_cert->certid),1,fp) != 1 ){
        wave_error_printf("读取文件错误了 %s %d",__FILE__,__LINE__);
        return -1;        
    }
    return 0;
} 
static int file_2_crl_serial_number(struct crl_serial_number* serial_node,FILE *fp){
    if(fread(&serial_node->serial_number,sizeof(serial_node->serial_number),1,fp) != 1 ||
            fread(&serial_node->start_period,sizeof(serial_node->start_period),1,fp) != 1||
            fread(&serial_node->issue_date,sizeof(serial_node->issue_date),1,fp) != 1||
            fread(&serial_node->next_crl_time,sizeof(serial_node->next_crl_time),1,fp)!= 1||
            fread(&serial_node->type,sizeof(serial_node->type),1,fp) != 1){
        wave_error_printf("读取文件错误了 %s %d",__FILE__,__LINE__);
        return -1;        
    }
    return 0;
}
static int file_2_crl_ca_id(struct crl_ca_id *ca_node,FILE *fp){
    struct crl_serial_number *serial_temp;
    struct revoked_certs *revoked_cert;
    int len,i;
    if(fread(&ca_node->ca_id,sizeof(ca_node->ca_id),1,fp) != 1 ||
          fread(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("读取文件出错了 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        if( (serial_temp = (struct crl_serial_number*)malloc(sizeof(struct crl_serial_number))) == NULL){
            wave_malloc_error();
            return -1;
        }
        if( file_2_crl_serial_number(serial_temp,fp)){
            free(serial_temp);
            return -1;
        }
        list_add_tail(&serial_temp->list,&ca_node->crl_info_list.list);
    }
    if(fread(&len ,sizeof(len),1,fp) != 1){
        wave_error_printf("读取文件出粗了 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        if( (revoked_cert = (struct revoked_certs*)malloc(sizeof(struct revoked_certs))) == NULL){
            wave_malloc_error();
            return -1;
        }
        if( file_2_revoked_cert(revoked_cert,fp)){
            free(revoked_cert);
            return -1;
        }
        list_add_tail(&revoked_cert->list,&ca_node->revoked_certs.list);
    }
    return 0;
}
static int file_2_crl_series(struct crl_head* series_node,FILE *fp){
   int len,i;
   struct crl_ca_id *ca_temp = NULL;
   int res = 0;
   if( fread(&series_node->crl_series,sizeof(series_node->crl_series),1,fp) != 1 ||
           fread(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("读取文件有错误 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
   }
   for(i=0;i<len;i++){
        if((ca_temp = (struct crl_ca_id*)malloc(sizeof(struct crl_ca_id))) == NULL){
            wave_malloc_error();
            res = -1;
            goto end;
        }
        INIT_LIST_HEAD(&ca_temp->crl_info_list.list);
        INIT_LIST_HEAD(&ca_temp->revoked_certs.list);
        if(file_2_crl_ca_id(ca_temp,fp)){
            res = -1;
            goto end;
        }
        list_add_tail(&ca_temp->list,&series_node->ca_id_list.list);        
   }
   goto end;
end:
   if(res != 0 && ca_temp != NULL){
        free(ca_temp);
   }
   return res;
}
static int file_2_crls(struct cme_db* cdb,FILE* fp){
    int len,i;
    int res = 0;
    struct crl_head *series_node = NULL;
    if( fread(&len,sizeof(len),1,fp) != 1){
        wave_error_printf("读取文件错误 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    for(i=0;i<len;i++){
        if( (series_node = (struct crl_head*)malloc(sizeof(struct crl_head))) == NULL){
            wave_malloc_error();
            res = -1;
            goto end;
        }
        INIT_LIST_HEAD(&series_node->ca_id_list.list);
        if( file_2_crl_series(series_node,fp)){
            res = -1;
            goto end;
        }
        list_add_tail(&series_node->list,&cdb->crls.list);
    }
    goto end;
end:
    if(res != 0&&series_node != NULL){
        free(series_node);
    }
    return res;
}
static int file_2_cert_info(struct cert_info* cinfo,FILE *fp){
    char *buf = NULL;
    certificate* cert;
    int res = 0;
    int len = 0,cert_len=0;
    if( (buf = (char*)malloc(READ_BUF_LEN)) == NULL ||
            (cert = (certificate*)malloc(sizeof(certificate))) == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    memset(cert,0,sizeof(*cert)); 
    len = fread(buf,1,READ_BUF_LEN,fp);
    if( len <= 0){
        wave_error_printf("读取文件出错 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    cert_len = buf_2_certificate(buf,READ_BUF_LEN,cert);
    if(cert_len <=0){
        wave_error_printf("解码证书出错");
        res = -1;
        goto end;
    }
    fseek(fp,cert_len - len,SEEK_CUR);
    if( fread(cinfo->certid10.certid10,1,10,fp) != 10||
            fread(&cinfo->verified,sizeof(cinfo->verified),1,fp) != 1||
            fread(&cinfo->trust_anchor,sizeof(cinfo->trust_anchor),1,fp) != 1||
            fread(&cinfo->revoked,sizeof(cinfo->revoked),1,fp) != 1||
            fread(&cinfo->expriry,sizeof(cinfo->expriry),1,fp) != 1){
        wave_error_printf("读取文件出粗 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    cinfo->cert = cert;
    goto end;
end:
    if(buf != NULL){
        free(buf);
    }
    if(res != 0 && cert != NULL){
        certificate_free(cert);
        free(cert);
    }
    return res;
}
static void cert_info_init(struct cert_info* cinfo){
    cinfo->cert = NULL;
    cinfo->key_cert = NULL;
    cert_info_init_rb(cinfo);
}
static int file_2_certs(struct cme_db* cdb,FILE* fp){
    struct cert_info *cinfo=NULL;
    char end = 0;
    char flag;
    int res = 0;
    if( fread(&flag,sizeof(flag),1,fp) != 1){
        wave_error_printf("读文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    while(flag != end){
        fseek(fp,-sizeof(flag),SEEK_CUR);
        cinfo = (struct cert_info*)malloc(sizeof(struct cert_info));
        if(cinfo == NULL){
            wave_malloc_error();
            res = -1;
            goto end;
        }
        cert_info_init(cinfo);
        if( file_2_cert_info(cinfo,fp)){
            res = -1;
            goto end;
        }
        cdb->certs =  cert_info_insert(cdb->certs,cinfo);
        if( fread(&flag,sizeof(flag),1,fp) != 1){
            wave_error_printf("读文件失败 %s %d",__FILE__,__LINE__);
            return -1;
        }
    }
    goto end;
end:
    if(res == 0)
        return 0;
    if( cinfo != NULL){
        cert_info_free(cinfo);
        free(cinfo);
    }
    return res;
}
int file_2_cme_db(struct cme_db *cdb,char *name){
    FILE *fp;
    fp = fopen(name,"r");
    if(fp == NULL){
        wave_error_printf("%s 文件打开失败 %s %d",name,__FILE__,__LINE__);
        return -1;
    }
    lock_wrlock(&cdb->lock);
    if( file_2_certs(cdb,fp))
        goto fail;
    if( file_2_crls(cdb,fp))
        goto fail;
    if( file_2_lsises(cdb,fp))
        goto fail;
    if( file_2_cmhs(cdb,fp))
        goto fail;
    fclose(fp);
    lock_unlock(&cdb->lock);
    return 0;
fail:
    fclose(fp);
    lock_unlock(&cdb->lock);
    return -1;
}
