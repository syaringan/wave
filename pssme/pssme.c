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
