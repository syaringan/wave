#ifndef CME_HELPER_H
#define CME_HELPER_H
#include"sec/sec_db.h"
#include"utils/common.h"
#include"cme.h" 
int certificate_get_start_time(certificate* cert,time32 *start_time);
int certificate_get_expired_time(struct sec_db* sdb,certificate* cert,time32 *expired_time);
/*
 * 通过cmh来找到一个证书,成功返回0，失败返回-1
 * */
int find_cert_by_cmh(struct sec_db *sdb,cmh cmh, struct certificate *cert);
int find_cert_prikey_by_cmh(struct sec_db * sdb,cmh cmh,certificate* cert,string *privatekey);
int find_keypaire_by_cmh(struct sec_db* sdb,cmh cmh,string* pubkey_x,string* pubkey_y,string* prikey,pk_algorithm* algorithm);

int certificate_2_hash8(struct certificate *cert, string *hash8);
int certificate_2_hashedid8(struct certificate* cert,hashedid8* hashedid8);
int certificate_2_certid10(certificate* cert,certid10* certid);
//int cert_not_expired(struct sec_db *sdb, void *value);
//int cert_not_revoked(struct sec_db *sdb, enum identifier_type type, string *identifier);
int certificate_get_elliptic_curve_point(certificate* cert,elliptic_curve_point* point);
//int certificate_get_start_validity(certificate* cert,time32* start);
//int get_cert_expired_info_by_cmh(struct sec_db *sdb, void *value);

int get_cert_info_by_certid(struct sec_db *sdb, enum identifier_type type, string *identifier,
                             
                            struct cert_info **cert_info);


int get_permission_from_certificate(certificate *cert,

                                    struct cme_permissions *permission,
                                    geographic_region *scope);

int get_region(geographic_region *src, geographic_region *dst, enum holder_type type);


bool geographic_region_in_geographic_region(geographic_region *a,geographic_region* b);
bool three_d_location_in_region(three_d_location* loc,geographic_region* region);
#endif
