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

result pssme_lsis_request(struct sec_db* sdb,pssme_lsis* lsis){
    struct pssme_db* pdb;
    struct list_head *head;
    struct pssme_lsis_chain *node;
    struct pssme_alloc_lsis *alloc_node;
    pdb = &sdb->pssme_db;
    alloc_node =(struct pssm,e)

    lock_wrlock(&pdb->lock);
    head = pdb->lsis_db.lsises;
    
    if(list_empty(head)){
        lock_unlock(&pdb->lock);
        return FAILURE;
    }
    node = list_entry(head->next,struct pssme_lsis_chain,list);


}
