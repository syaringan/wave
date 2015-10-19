#ifndef CMP_H
#define CMP_H
#include "../utils/common.h"
void cmp_do_certificate_applycation();
void cmp_do_recieve_data();
u32 cmp_init();
void cmp_end();
void cmp_run();
void cmp_do_crl_req(crl_serial crl_serial);
#endif
