#include "cme_db.h"
#include<stdio.h>
#define FILENAME "./cme_db.txt"
int main(){
    struct cme_db *cdb;
    cdb = (struct cme_db*)malloc(sizeof(struct cme_db));
    if(cdb == 0)
        return -1;
    cme_db_init(cdb);
    cme_db_2_file(cdb,FILENAME);
    file_2_cme_db(cdb,FILENAME);
}
