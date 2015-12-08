/*************************************************************************
    > File Name: pssme_encode.c
    > Author: Aaron
 ************************************************************************/

#include <unistd.h>
#include <string.h>            //为了使用memset
#include "pssme_db.h"
#include "utils/common.h"
#include "data/data_handle.h"

#define CERTICATE_BUF_LEN 1024
int plchain_2_file(struct pssme_lsis_chain *plchain, FILE *fd){
    struct list_head *head;
    struct pssme_lsis_chain* plchain_temp;
    int len = 0;

    head = &plchain->list;
    list_for_each_entry(plchain_temp,head,list){
        len ++;
    }

    if( fwrite(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }

    list_for_each_entry(plchain_temp,head,list){
        if( fwrite(&plchain_temp->lsis,sizeof(plchain_temp->lsis),1,fd) != 1){
            wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
            return -1;
        }
    }
	return 0;
}
int pssme_psid_priority_ssp_2_file(struct pssme_psid_priority_ssp* ppps,FILE *fd){
    if(fwrite( &ppps->psid,sizeof(ppps->psid),1,fd) != 1||
            fwrite( &ppps->priority,sizeof(ppps->priority),1,fd) != 1 ||
            fwrite( &ppps->ssp.len,sizeof(ppps->ssp.len),1,fd) != 1 ||
            fwrite( ppps->ssp.buf,1,ppps->ssp.len,fd) != ppps->ssp.len){
        wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
int pssme_psid_priority_ssp_chain_2_file(struct pssme_psid_priority_ssp_chain* pppsc,FILE *fd){
    struct list_head* head;
    int len = 0;
    struct pssme_psid_priority_ssp_chain* pppsc_temp;
    
    head = &pppsc->list;
    list_for_each_entry(pppsc_temp,head,list){
        len++;
    }

    if( fwrite(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }

    list_for_each_entry(pppsc_temp,head,list){
        if(pssme_psid_priority_ssp_2_file(&pppsc_temp->permission,fd))
            return -1;
    }
    return 0;

}
int pssme_alloc_lsis_2_file(struct pssme_alloc_lsis *pal,FILE *fd){
    if( fwrite(&pal->lsis,sizeof(pal->lsis),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return pssme_psid_priority_ssp_chain_2_file(&pal->permissions,fd);
}
int pal_2_file(struct pssme_alloc_lsis *pal, FILE* fd){
    struct list_head* head;
    struct pssme_alloc_lsis *al_temp;
    int len = 0;
    
    head = &pal->list;
    list_for_each_entry(al_temp,head,list)
        len++;

    if( fwrite(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    } 
    list_for_each_entry(al_temp,head,list){
        if(pssme_alloc_lsis_2_file(al_temp,fd))
            return -1;
    }
	return 0;
}

int lsis_db_2_file(struct pssme_lsis_db *pldb, FILE* fd){

	struct pssme_alloc_lsis *pal;
	pal = &(pldb->alloc_lsis);
	struct pssme_lsis_chain *plchain;    //这个不缩写成plc是为了区别之前的 pssme_local_cert 缩写的 plc，以免看起来混淆
	plchain = &(pldb->lsises);

	if( pal_2_file(pal, fd) == -1 )
	{
		printf("in lsis_db_2_file : pal_2_file Error!\n");
		return -1;
	}

	if( plchain_2_file(plchain, fd) == -1 )
	{
		printf("in lsis_db_2_file ; plchain_2_file Error!\n");
		return -1;
	}

	return 0;
}
int pssme_lsis_array_2_file(struct pssme_lsis_array* pl_array,FILE* fd){
    int i;
    if(fwrite(&pl_array->len,sizeof(pl_array->len),1,fd) != 1){
        wave_error_printf(" 写入错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    if( fwrite(pl_array->lsis,sizeof(pssme_lsis),pl_array->len,fd) != pl_array->len){
        wave_error_printf("写入错误 %s %d",__FILE__,__LINE__);
    }
    return 0;
}
int plc_2_file(struct pssme_local_cert *plc, FILE* fd){

    struct list_head *head;
    struct pssme_local_cert *plc_temp;
    int length = 0; 
    head = &plc->list;

    list_for_each_entry(plc_temp,head,list)
        length ++;
    if(fwrite(&length,sizeof(length),1,fd) != 1){
        wave_error_printf("写入错误 %s %d",__FILE__,__LINE__);
        return -1;
    }

    list_for_each_entry(plc_temp,head,list){
        if(fwrite(&plc_temp->cmh,sizeof(plc_temp->cmh),1,fd) != 1){
            wave_error_printf("写入错误 %s %d",__FILE__,__LINE__);
            return -1;
        }
        if(pssme_lsis_array_2_file(&plc_temp->lsis_array,fd))
            return -1;

    }
	return 0;
}


int prc_2_file(struct pssme_receive_cert *prc, FILE *fd)
{
    struct list_head* head;
    struct pssme_receive_cert *prc_temp;
    int len = 0,clen;
    char *buf;
    head = &prc->list;

    list_for_each_entry(prc_temp,head,list)
        len++;
    if( fwrite(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    buf =(char*)malloc(CERTICATE_BUF_LEN);
    if(buf == NULL){
        wave_malloc_error();
        return -1;
    }
    list_for_each_entry(prc_temp,head,list){
        clen = certificate_2_buf(&prc_temp->cert,buf,CERTICATE_BUF_LEN);
        if(clen <=0){
            free(buf);
            return -1;
        }
        if( fwrite(buf,1,len,fd) != len ||
                fwrite(&prc_temp->recent_time,sizeof(prc_temp->recent_time),1,fd) != 1){
            wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
            free(buf);
            return -1;
        }
    }
    free(buf);
	return 0;
}

int cert_db_2_file(struct pssme_cert_db *pcdb, FILE* fd){

    struct pssme_local_cert *plc;
	plc = &(pcdb->local_cert);

	if( plc_2_file(plc, fd) == -1 )
	{
		printf("in cert_db_2_file : plc_2_file Error!\n");
	    return -1;
	}

    struct pssme_receive_cert *prc;
	prc = &(pcdb->receive_cert);

	if( prc_2_file(prc, fd) == -1 )
	{
		printf("in cert_db_2_file ; prc_2_file Error!\n");
	    return -1;
	}

    return 0;
}

//正确0 错误-1
int pdb_2_file(struct pssme_db* pdb,char* name)
{
    FILE *fd;
    fd = fopen(name,"w");
    if(fd == NULL){
		printf("Open File Error!\n");
		return -1;
	}


	struct pssme_cert_db *pcdb;
	pcdb = &(pdb->cert_db);
	struct pssme_lsis_db *pldb;
	pldb = &(pdb->lsis_db);

	if( cert_db_2_file(pcdb, fd) == -1 )
	{
		printf("in pdb_2_file : cert_db_2_file Error!\n");
        fclose(fd);
	    return -1;
	}

    if( lsis_db_2_file(pldb, fd) == -1 )
	{
		printf("in pdb_2_file : lsis_db_2_file Error!\n");
        return -1;
	}
    fclose(fd);
    return 0;
}


int file_2_plchain(struct pssme_lsis_chain *plchain, FILE *fd){
    int i,len;
    struct pssme_lsis_chain* plchain_node;
    if( fread(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("read文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        plchain_node = (struct pssme_lsis_chain*)malloc(sizeof(struct pssme_lsis_chain));
        if(plchain_node == NULL){
            wave_malloc_error();
            return -1;
        }
        memset(plchain_node,0,sizeof(*plchain_node));
        if( fread(&plchain_node->lsis,sizeof(plchain_node->lsis),1,fd) != 1){
            wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
            free(plchain_node);
            return -1;
        }
        list_add_tail(&plchain_node->list,&plchain->list);
    }
    return 0;
}
int file_2_pssme_psid_priority_ssp(struct pssme_psid_priority_ssp* ppps,FILE *fd){
    if(fread( &ppps->psid,sizeof(ppps->psid),1,fd) != 1||
            fread( &ppps->priority,sizeof(ppps->priority),1,fd) != 1 ||
            fread( &ppps->ssp.len,sizeof(ppps->ssp.len),1,fd) != 1 ){
        wave_error_printf("read文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    ppps->ssp.buf = (u8*)malloc(ppps->ssp.len);
    if(ppps->ssp.buf == NULL){
        wave_malloc_error();
        return -1;
    }

    if( fread( ppps->ssp.buf,1,ppps->ssp.len,fd) != ppps->ssp.len){
        wave_error_printf("read 失败 %s %d",__FILE__,__LINE__);
        free(ppps->ssp.buf);
        return -1;
    }
    return 0;
}
int file_2_pssme_psid_priority_ssp_chain(struct pssme_psid_priority_ssp_chain* pppsc,FILE *fd){
    int i,len;
    struct pssme_psid_priority_ssp_chain* pppsc_node;
    if( fread(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("read文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        pppsc_node = (struct pssme_psid_priority_ssp_chain*)malloc(sizeof(struct pssme_psid_priority_ssp_chain));
        if( pppsc_node == NULL){
            wave_malloc_error();
            return -1;
        }
        memset(pppsc_node,0,sizeof(*pppsc_node));
        if( file_2_pssme_psid_priority_ssp(&pppsc_node->permission,fd)){
            free(pppsc_node);
            return -1;
        }
        list_add_tail(&pppsc_node->list,&pppsc->list);
    }
    return 0;
}
int file_2_pssme_alloc_lsis(struct pssme_alloc_lsis* pal,FILE *fd){
    if( fread(&pal->lsis,sizeof(pal->lsis),1,fd) != 1){
        wave_error_printf("read文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    INIT_LIST_HEAD(&pal->permissions.list);
    return file_2_pssme_psid_priority_ssp_chain(&pal->permissions,fd);
}

int file_2_pal(struct pssme_alloc_lsis *pal, FILE* fd){
    struct pssme_alloc_lsis *pal_node;
    int len,i;
    
    if( fread(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    } 
    for(i=0;i<len;i++){
        pal_node = (struct pssme_alloc_lsis*)malloc(sizeof(struct pssme_alloc_lsis));
        if(pal_node == NULL){
            wave_malloc_error();
            return -1;
        }
        memset(pal_node,0,sizeof(*pal_node));
        if(file_2_pssme_alloc_lsis(pal_node,fd)){
            free(pal_node);
            return -1;
        }
        list_add_tail(&pal_node->list,&pal->list);
    }
	return 0;
}

int file_2_lsis_db(struct pssme_lsis_db *pldb, FILE *fd){
	struct pssme_alloc_lsis *pal = &(pldb->alloc_lsis);
	struct pssme_lsis_chain *plchain = &(pldb->lsises);

	if( file_2_pal(pal, fd) == -1 )
	{
		printf("in file_2_lsis_db : file_2_pal Error!\n");
		return -1;
	}

	if( file_2_plchain(plchain, fd) == -1 )
	{
		printf("in file_2_lsis_db : file_2_plchain Error!\n");
		return -1;
	}

	return 0;
}
int file_2_prc(struct pssme_receive_cert *prc, FILE *fd){
    int i,len = 0,readlen,clen;
    struct pssme_receive_cert *prc_node;
    char* buf;
    buf =(char*) malloc(CERTICATE_BUF_LEN);
    if(buf == NULL){
        wave_malloc_error();
        return -1;
    }
    if( fwrite(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        prc_node = (struct pssme_receive_cert*)malloc(sizeof(struct pssme_receive_cert));
        if(prc_node == NULL){
            wave_malloc_error();
            free(buf);
            return -1;
        }
        memset(prc_node,0,sizeof(*prc_node));
        readlen = fread(buf,1,CERTICATE_BUF_LEN,fd);
        if(readlen <= 0){
            free(buf);
            free(prc_node);
            wave_error_printf("读取文件错误 %s %d",__FILE__,__LINE__);
            return -1;
        }
        clen = buf_2_certificate(buf,readlen,&prc_node->cert);
        fseek(fd,clen-readlen,SEEK_CUR);
        if( fread(&prc_node->recent_time,sizeof(prc_node->recent_time),1,fd) != 1){
            wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
            free(buf);
            free(prc_node);
            return -1;
        }
        list_add_tail(&prc_node->list,&prc->list);
    }
    free(buf);
    return 0;
}
int file_2_pssme_lsis_array(struct pssme_lsis_array* pl_array,FILE *fd){
    if(fread(&pl_array->len,sizeof(pl_array->len),1,fd) != 1){
        wave_error_printf(" 写入错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    pl_array->lsis = (pssme_lsis*)malloc(sizeof(pssme_lsis) * pl_array->len);
    if(pl_array->lsis == NULL){
        wave_malloc_error();
        return -1;
    }
    if( fwrite(pl_array->lsis,sizeof(pssme_lsis),pl_array->len,fd) != pl_array->len){
        wave_error_printf("写入错误 %s %d",__FILE__,__LINE__);
        free(pl_array->lsis);
        pl_array->lsis = NULL;
        return -1;
    }
    return 0;
}

int file_2_plc(struct pssme_local_cert *plc, FILE *fd)
{
	int len,i;
    struct pssme_local_cert* plc_node;
    if(fread(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("read错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        plc_node = (struct pssme_local_cert*)malloc(sizeof(struct pssme_local_cert));
        if(plc_node == NULL){
            wave_malloc_error();
            return -1;
        }
        memset(plc_node,0,sizeof(*plc_node));

        if(fread(&plc_node->cmh,sizeof(plc_node->cmh),1,fd) != 1){
            wave_error_printf("写入错误 %s %d",__FILE__,__LINE__);
            free(plc_node);
            return -1;
        }
        if(file_2_pssme_lsis_array(&plc_node->lsis_array,fd)){
            free(plc_node);
            return -1;
        }
        list_add_tail(&plc_node->list,&plc->list);
    }
	return 0;
}
int file_2_cert_db(struct pssme_cert_db *pcdb, FILE *fd)
{
	struct pssme_local_cert *plc = &pcdb->local_cert;
	struct pssme_receive_cert *prc = &pcdb->receive_cert;

	if( file_2_plc(plc, fd) == -1 )
	{
		printf("in file_2_cert_db : file_2_plc Error!\n");
		return -1;
	}

	if( file_2_prc(prc, fd) == -1 )
	{
		printf("in file_2_cert_db : file_2_prc Error!\n");
		return -1;
	}

	return 0;
}


/*下面是读文件操作
 * 将文件内容读入struct pssme_db 结构体
 */
int file_2_pdb(struct pssme_db *pdb, char *name)
{
	FILE* fd = fopen(name, "r");            //以只读方式打开

	if(fd == NULL){
		printf("file_2_db Open File Error!\n");
		return -1;
	}

	struct pssme_cert_db* pcdb = &pdb->cert_db;
	struct pssme_lsis_db* pldb = &pdb->lsis_db;

	if( file_2_cert_db(pcdb, fd) == -1 )
	{
		printf("in file_2_pdb : file_2_pcdb Error!\n");
        fclose(fd);
		return -1;
	}

	if( file_2_lsis_db(pldb, fd) == -1 )
	{
		printf("in file_2_db : file_2_pldb Error!\n");
        fclose(fd);
		return -1;
	}

    fclose(fd);
	return 0;
}
void pssme_local_cert_free(struct pssme_local_cert* plc){
    if(plc == NULL)
        return ;
    if(plc->lsis_array.lsis != NULL)
        free(plc->lsis_array.lsis);
    plc->lsis_array.lsis = NULL;
    plc->lsis_array.len = 0;
}
void pssme_local_cert_list_free(struct pssme_local_cert* plc){
    struct list_head *head;
    struct pssme_local_cert* plc_temp;

    if(plc == NULL)
        return ;
    head = &plc->list;
    while(!list_empty(head)){
        plc_temp = list_entry(head->next,struct pssme_local_cert,list);
        list_del(&plc_temp->list);
        pssme_local_cert_free(plc_temp);
        free(plc_temp);
    }

}
void pssme_receive_cert_free(struct pssme_receive_cert* prc){
    if(prc == NULL)
        return;
    certificate_free(&prc->cert);
}
void pssme_receive_cert_list_free(struct pssme_receive_cert* prc){
    struct list_head *head;
    struct pssme_receive_cert* prc_temp;

    if(prc == NULL)
        return ;
    head = &prc->list;
    while(!list_empty(head)){
        prc_temp = list_entry(head->next,struct pssme_receive_cert,list);
        list_del(&prc_temp->list);
        pssme_receive_cert_free(prc_temp);
        free(prc_temp);
    }
}
void pssme_cert_db_free(struct pssme_cert_db* pcdb){
    pssme_local_cert_free(&pcdb->local_cert);
    pssme_receive_cert_free(&pcdb->receive_cert);
}
void pssme_psid_priority_ssp_chain_list_free(struct pssme_psid_priority_ssp_chain* pppsc){
    struct list_head *head;
    struct pssme_psid_priority_ssp_chain* pppsc_temp;

    if(pppsc == NULL)
        return ;
    head = &pppsc->list;
    while(!list_empty(head)){
        pppsc_temp = list_entry(head->next,struct pssme_psid_priority_ssp_chain,list);
        list_del(&pppsc_temp->list);
        pssme_psid_priority_ssp_chain_free(pppsc_temp);
        free(pppsc_temp);
    }
}
void pssme_alloc_lsis_free(struct pssme_alloc_lsis* pal){
    pssme_psid_priority_ssp_chain_list_free(&pal->permissions);
}
void pssme_alloc_lsis_list_free(struct pssme_alloc_lsis* pal){
    struct list_head *head;
    struct pssme_alloc_lsis* pal_temp;
    if(pal == NULL)
        return ;
    head = &pal->list;
    while(!list_empty(head)){
        pal_temp = list_entry(head->next,struct pssme_alloc_lsis,list);
        list_del(&pal_temp->list);
        pssme_alloc_lsis_free(pal_temp);
        free(pal_temp);
    }
}
void pssme_lsis_chain_list_free(struct pssme_lsis_chain* plc){
    struct list_head *head;
    struct pssme_lsis_chain *plc_temp;
    if(plc == NULL)
        return ;
    head = &plc->list;
    while(!list_empty(head)){
        plc_temp = list_entry(head->next,struct pssme_lsis_chain,list);
        list_del(&plc_temp->list);
        free(plc_temp);
    }
}
void pssme_lsis_db_free(struct pssme_lsis_db* pldb){
    pssme_alloc_lsis_list_free(&pldb->alloc_lsis);
    pssme_lsis_chain_list_free(&pldb->lsises);
}
void pssme_db_free(struct pssme_db* pdb){
    lock_destroy(&pdb->lock);
    pssme_cert_db_free(&pdb->cert_db);
    pssme_lsis_db_free(&pdb->lsis_db);
}
void pssme_db_init(struct pssme_db* pdb){
    if(pdb == NULL)
        return;
    lock_init(&pdb->lock);
    INIT_LIST_HEAD(&pdb->cert_db.local_cert.list);
    INIT_LIST_HEAD(&pdb->cert_db.receive_cert.list);
    INIT_LIST_HEAD(&pdb->lsis_db.alloc_lsis.list);
    INIT_LIST_HEAD(&pdb->lsis_db.lsises.list);
}
