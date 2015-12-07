#include "sec/sec_db.h"
/**
 * 当读到文件结束符或者错误的时候 返回错误
 */
int do_client_request(struct sec_db* sdb,int fd);

static int do_cme_lsis_request(struct sec_db* sdb,int fd);
static int do_cme_cmh_request(struct sec_db* sdb,int fd);

static int do_cme_generate_keypair(struct sec_db* sdb,int fd);

static int do_cme_store_keypair(struct sec_db* sdb,int fd);

static int do_cme_store_cert(struct sec_db* sdb,int fd);

static int do_cme_store_cert_key(struct sec_db* sdb,int fd);

static int do_sec_signed_data(struct sec_db* sdb,int fd);

static int do_sec_encrypted_data(struct sec_db* sdb,int fd);

static int do_sec_secure_data_content_extration(struct sec_db* sdb,int fd);

static int do_sec_signed_data_verification(struct sec_db* sdb,int fd);
