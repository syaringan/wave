#ifndef SEC_DB_H
#define SEC_DB_H
#include "cme/cme_db.h"
#include "pssme/pssme_db.h"
struct sec_db{
    struct cme_db cme_db;
    struct pssme_db pssme_db;
};
#endif
