#include "pssme.h"
#include<stdlib.h>
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

result pssme_cryptomaterial_handle(struct sec_db* sdb,serviceinfo_array* se_array,two_d_location* two_dl,string* permission_ind,cmh* cmh,struct certificate_chain* cert_chain){
    result ret = SUCCESS;
    
    permission_ind->len = se_array->len;
    permission_ind->buf = malloc(sizeof(u8)*se_array->len);
    if(permission_ind->buf == NULL)
        goto fail;
    memset(permission_ind->buf, 0, sizeof(u8)*se_array->len);


    
}
