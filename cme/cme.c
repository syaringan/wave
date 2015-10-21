#include "cme.h"
#include <stdlib.h>
void cme_permissions_free(struct cme_permissions* permissions){
    switch(permissions->type){
        case PSID:
            array_free(&permissions->u.psid_array);
            break;
        case PSID_PRIORITY:
            array_free(&permissions->u.psid_priority_array);
            break;
        case PSID_SSP:
            array_free(&permissions->u.psid_ssp_array);
            break;
        case PSID_PRIORITY_SSP:
            array_free(&permissions->u.psid_priority_ssp_array);
            break;
    }
}
void cme_permissions_array_free(struct cme_permissions_array* 
                permission_array){
    int i;
    if(permission_array->cme_permissions == NULL)
        return;
    for(i=0;i<permission_array->len;i++){
        cme_permissions_free(permission_array->cme_permissions+i);
    }
    free(permission_array->cme_permissions);
    permission_array->cme_permissions == NULL;
    permission_array->len = 0;
}

void certificate_chain_free(struct certificate_chain* certs_chain){
    int i=0;
    if(certs_chain->certs == NULL)
        return;
    for(i=0;i<certs_chain->len;i++){
       certificate_free(certs_chain->certs + i);
    }
    free(certs_chain->certs);
    certs_chain->certs = NULL;
    certs_chain->len = 0;
}
result cme_construct_certificate_chain(struct sec_db* sdb, enum identifier_type type,string* identifier,struct certificate_chain* certificates,bool terminate_at_root,u32 max_chain_len,struct certificate_chain* certificate_chain,struct cme_permissions_array* permissions_array,struct geographic_region_array* regions){

}

