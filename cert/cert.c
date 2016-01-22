#include "data/data_handle.h"
#include "cert.h"
#include "utils/common.h"
#include "utils/string.h"
#include "crypto/crypto.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <entry/wave.h>
#include <sec/sec.h>
#define INIT(n) memset(&n,0,sizeof(n))

#define MAIN_DIR "/home/ljh/ljh-wave-1609.2/cert/"
#define VERI_PRIKEY_POSTFIX ".veri.pri"
#define ENRY_PRIKEY_POSTFIX ".enry.pri"
#define CA_PRIVATE_NAME "ca.pri"
#define error() wave_error_printf("在这个代码地方发生了错误  %s %d",__FILE__,__LINE__)

struct region_type_array certificate_request_support_region_types;
static void privatekey_signed_cert(pk_algorithm algorithm,string* pri,certificate* issued){
    ecdsa_signature* signature;
    string encode,hashed;
    string r,s;
    INIT(encode);
    INIT(hashed);
    INIT(r);
    INIT(s); 
    if(tobesigned_certificate_2_string(&issued->unsigned_certificate,&encode,issued->version_and_type)){
        error();
        goto end;
    }
    if(algorithm == ECDSA_NISTP224_WITH_SHA224){
        if(crypto_HASH_224(&encode,&hashed)){
            error();
            goto end;
        }
        if(crypto_ECDSA_224_sign_message(pri,&hashed,&r,&s)){
            error();
            goto end;
        }
    
    }
    else if(algorithm == ECDSA_NISTP256_WITH_SHA256){
        if(crypto_HASH_256(&encode,&hashed)){
            error();
            goto end;
        }
        if(crypto_ECDSA_256_sign_message(pri,&hashed,&r,&s)){
            error();
            goto end;
        }
    }
    else{
        error();
        goto end;
    }
    signature = &issued->u.signature.u.ecdsa_signature;
    signature->s.len = s.len;
    signature->s.buf = (u8*)malloc(s.len);
    if(signature->s.buf == NULL){
        error();
        goto end;
    }
    memcpy(signature->s.buf,s.buf,s.len);

    signature->r.type = X_COORDINATE_ONLY;
    signature->r.x.len = r.len;
    signature->r.x.buf = (u8*)malloc(r.len);
    if(signature->r.x.buf == NULL){
        error();
        goto end;
    }
    memcpy(signature->r.x.buf,r.buf,r.len);

end:
    string_free(&encode);
    string_free(&hashed);
    string_free(&r);
    string_free(&s);
}
static void cert_signed_self(certificate* cert,string* pri){
    pk_algorithm algorithm;
    algorithm = cert->unsigned_certificate.version_and_type.verification_key.algorithm;
    privatekey_signed_cert(algorithm,pri,cert);
}
static void cert_signed_cert(certificate* issuing,string* pri,certificate* issued){
    hashedid8 hashed;
    pk_algorithm algorithm;

    INIT(hashed);
    
    if(certificate_2_hashedid8(issuing,&hashed)){
        return;
    } 
    //这个地方签发证书，我们选取的tobesigned_certificate  而签发者我们选取的certificate 这个整体
    algorithm = issuing->unsigned_certificate.version_and_type.verification_key.algorithm;
    issued->unsigned_certificate.u.no_root_ca.signature_alg = algorithm;
    memcpy(issued->unsigned_certificate.u.no_root_ca.signer_id.hashedid8,hashed.hashedid8,8);
    privatekey_signed_cert(algorithm,pri,issued);
}
static void get_verification_key(pk_algorithm algorithm,string* pubkey_x,string* pubkey_y,string* pri){
    if(algorithm == ECDSA_NISTP224_WITH_SHA224){
        if(crypto_ECDSA_224_get_key(pri,pubkey_x,pubkey_y)){
            error();
        }
        return;
    }
    if(algorithm == ECDSA_NISTP256_WITH_SHA256){
        if(crypto_ECDSA_256_get_key(pri,pubkey_x,pubkey_y)){
            error();
        }
        return ;
    }
    error();
    return;
}
static void get_enrypted_key(pk_algorithm algorithm,string* pubkey_x,string* pubkey_y,string* pri){
    if(algorithm == ECIES_NISTP256){
        if(crypto_ECIES_get_key(pri,pubkey_x,pubkey_y)){
            error();
        }
        return;
    }
    error();
    return;
}
static void fill_version_and_type(certificate* cert){
    cert->version_and_type = (u8)2;
}

static void fill_holder_type(certificate* cert){
    enum holder_type holder_type;
    char name[20];
    printf("输入holder_type(root_ca,wsa_ca,wsa,sde_ca,sde_id_localized):");
    scanf("%s",name);
    if(strcmp(name,"root_ca") == 0){
        holder_type = ROOT_CA;
    }
    else if(strcmp(name,"wsa_ca") == 0){
        holder_type = WSA_CA;
    }
    else if(strcmp(name,"wsa") == 0){
        holder_type = WSA;
    }
    else if(strcmp(name,"sde_ca") == 0){
        holder_type = SDE_CA;
    }
    else if(strcmp(name,"sde_id_localized") == 0){
        holder_type = SDE_IDENTIFIED_LOCALIZED;
    }
    else{
        error();
        return;
    }
    cert->unsigned_certificate.holder_type = holder_type;
}
static void fill_geographic_region(geographic_region* region){
    region->region_type = CIRCLE;
    region->u.circular_region.center.latitude = 0;
    region->u.circular_region.center.longitude = 0;
    region->u.circular_region.radius = 20;
}
static void fill_psid_array(psid_array *pa){
    pa->type = ARRAY_TYPE_SPECIFIED;

    pa->u.permissions_list.len = 2;
    pa->u.permissions_list.buf = (psid*)malloc(sizeof(psid)*2);
    if(pa->u.permissions_list.buf == NULL){
        error();
        return;
    }
    pa->u.permissions_list.buf[0] = 0x20;
    pa->u.permissions_list.buf[1] = 0x23;
}
static void fill_psid_priority_array(psid_priority_array* ppa){
    ppa->type = ARRAY_TYPE_SPECIFIED;
    ppa->u.permissions_list.len = 2;
    ppa->u.permissions_list.buf = (psid_priority*)malloc(sizeof(psid_priority) * 2);
    if(ppa->u.permissions_list.buf == NULL){
        error();
        return;
    }
    ppa->u.permissions_list.buf[0].psid = 0x20;
    ppa->u.permissions_list.buf[0].max_priority = 0x1f;

    ppa->u.permissions_list.buf[1].psid = 0x23;
    ppa->u.permissions_list.buf[1].max_priority = 0x1f;
}
static void fill_ssp(u8** buf,int len){
    *buf = (u8*)malloc(4);
    if(*buf == NULL){
        error();
    }
    (*buf)[0] = 'l';
    (*buf)[1] = 'j';
    (*buf)[2] = 'h';
	(*buf)[3] = '\0';
}
static void fill_psid_ssp_array(psid_ssp_array* psa){
    psa->type = ARRAY_TYPE_SPECIFIED;

    psa->u.permissions_list.len = 2;
    psa->u.permissions_list.buf = (psid_ssp*)malloc(sizeof(psid_ssp) * 2);
    if(psa->u.permissions_list.buf == NULL){
        error();
        return;
    }
    psa->u.permissions_list.buf[0].psid = 0x20;
    psa->u.permissions_list.buf[0].service_specific_permissions.len = 4;
    fill_ssp(&psa->u.permissions_list.buf[0].service_specific_permissions.buf,4);

    psa->u.permissions_list.buf[1].psid = 0x23;
    psa->u.permissions_list.buf[1].service_specific_permissions.len= 4;
    fill_ssp(&psa->u.permissions_list.buf[1].service_specific_permissions.buf,4);
}
static void fill_psid_priority_ssp_array(psid_priority_ssp_array* ppsa){
    ppsa->type = ARRAY_TYPE_SPECIFIED;
    ppsa->u.permissions_list.len =2 ;
    ppsa->u.permissions_list.buf = (psid_priority_ssp*)malloc(sizeof(psid_priority_ssp) * 2);
    if(ppsa->u.permissions_list.buf == NULL){
        error();
        return;
    }
    ppsa->u.permissions_list.buf[0].psid = 0x20;
    ppsa->u.permissions_list.buf[0].max_priority = 0x1f;
    ppsa->u.permissions_list.buf[0].service_specific_permissions.len = 4;
    fill_ssp(&ppsa->u.permissions_list.buf[0].service_specific_permissions.buf,4);

    ppsa->u.permissions_list.buf[1].psid = 0x23;
    ppsa->u.permissions_list.buf[1].max_priority = 0x1f;
    ppsa->u.permissions_list.buf[1].service_specific_permissions.len = 4;
    fill_ssp(&ppsa->u.permissions_list.buf[1].service_specific_permissions.buf,4);
}
static void fill_root_ca(certificate* cert){
    root_ca_scope* scope;

    scope = &cert->unsigned_certificate.scope.u.root_ca_scope;
    scope->name.len = 4;
    scope->name.buf = (u8*)malloc(scope->name.len);
    if(scope->name.buf == NULL){
        error();
        return;
    }
    strcpy(scope->name.buf,"ljh");
    
    scope->permitted_holder_types = FLAGS_SDE_CA |FLAGS_SDE_ANONYMOUS | FLAGS_SDE_ENROLMENT |
                    FLAGS_SDE_IDENTIFIED_LOCALIZED | FLAGS_SDE_IDENTIFIED_NOT_LOCALIZED|
                    FLAGS_WSA | FLAGS_WSA_CA | FLAGS_WSA_ENROLMENT;

    fill_psid_array(&scope->flags_content.secure_data_permissions);
    fill_psid_priority_array(&scope->flags_content.wsa_permissions);
    fill_geographic_region(&scope->region);
}
static void fill_sde_ca_scope(certificate *cert){
    sec_data_exch_ca_scope* scope;
    scope = &cert->unsigned_certificate.scope.u.sde_ca_scope;
    scope->name.len = 4;
    scope->name.buf = (u8*)malloc(scope->name.len);
    if(scope->name.buf == NULL){
        error();
        return;
    }
    strcpy(scope->name.buf,"ljh");
    scope->permitted_holder_types = FLAGS_SDE_CA |FLAGS_SDE_ANONYMOUS | FLAGS_SDE_ENROLMENT |
                    FLAGS_SDE_IDENTIFIED_LOCALIZED | FLAGS_SDE_IDENTIFIED_NOT_LOCALIZED|
                    FLAGS_WSA | FLAGS_WSA_CA | FLAGS_WSA_ENROLMENT;
    fill_psid_array(&scope->permissions);
    fill_geographic_region(&scope->region);
}
static void fill_wsa_ca_scope(certificate* cert){
    wsa_ca_scope* scope;
    scope = &cert->unsigned_certificate.scope.u.wsa_ca_scope;
    scope->name.len = 4;
    scope->name.buf = (u8*)malloc(scope->name.len);
    if(scope->name.buf == NULL){
        error();
        return;
    }
    strcpy(scope->name.buf,"ljh");
    fill_psid_priority_array(&scope->permissions);
    fill_geographic_region(&scope->region);
}
static void fill_wsa(certificate* cert){
    wsa_scope* scope;
    scope = &cert->unsigned_certificate.scope.u.wsa_scope;
    
    scope->name.len = 4;
    scope->name.buf = (u8*)malloc(scope->name.len);
    if(scope->name.buf == NULL){
        error();
        return;
    }
    strcpy(scope->name.buf,"ljh");
    fill_psid_priority_ssp_array(&scope->permissions);
    fill_geographic_region(&scope->region);
}
static void fill_id_scope(certificate* cert){
    identified_scope* idscope;
    idscope = &cert->unsigned_certificate.scope.u.id_scope;
    
    idscope->name.len = 4;
    idscope->name.buf = (u8*)malloc(idscope->name.len);
    if(idscope->name.buf == NULL){
        error();
        return;
    }
    strcpy(idscope->name.buf,"ljh");
    fill_psid_ssp_array(&idscope->permissions);
    fill_geographic_region(&idscope->region);
}
static void fill_certspecificdata(certificate* cert){
   switch(cert->unsigned_certificate.holder_type){
        case ROOT_CA:
            fill_root_ca(cert);
            break;
        case SDE_CA:
        case SDE_ENROLMENT:
            fill_sde_ca_scope(cert);
            break;
        case WSA_CA:
        case WSA_ENROLMENT:
            fill_wsa_ca_scope(cert);
            break;
        case WSA:
            fill_wsa(cert);
            break;
        case SDE_IDENTIFIED_LOCALIZED:
            fill_id_scope(cert);
            break;
        default:
            error();
            return;
   }
}
static void fill_expiration(certificate* cert){
    int t;
    printf("输入证书持续多久(s):");
    scanf("%d",&t);
    getchar();
    cert->unsigned_certificate.expiration = time(NULL) + t;
}
static void fill_start_validity(certificate* cert){
    enum certificate_content_flags* cf;
    certificate_duration *cd;
    char flag;
    char type;
    int t;

    cf = &cert->unsigned_certificate.cf;
    cd = &cert->unsigned_certificate.flags_content.lifetime;
    printf("是否填写start_validity(y/n):");
    scanf("%c",&flag);
    getchar();
    if(flag == 'y'){
        *cf = *cf | USE_START_VALIDITY;
        printf("是否填写 life_is_duration(y/n)");
        scanf("%c",&flag);
        getchar();
        if(flag == 'y'){
            *cf = *cf | LIFETIME_IS_DURATION; 
            printf("填写单位（s,m,h,H,y）和时间:");
            scanf("%c %d",&type,&t);
            getchar();
            *cd = 0;
            if(type == 's'){
                *cd = *cd | 0x0000;
            }
            else if(type == 'm'){
                *cd = *cd | 0x2000;
            }
            else if(type == 'h'){
                *cd = *cd | 0x4000;
            }
            else if(type == 'H'){
                *cd = *cd | 0x6000;
            }
            else if(type == 'y'){
                *cd = *cd | 0x8000;
            }
            else{
                error();
                return;
            }
            *cd = *cd | (t & 0x1fff);
        }
        else{
            printf("填写从现在开始多久有效(s):");
            scanf("%d",&t);
            cert->unsigned_certificate.flags_content.start_validity = time(NULL) + t;
        }
    }
}
static void fill_crlseries(certificate* cert){
    int series;
    printf("输入crl_series:");
    scanf("%d",&series);
    cert->unsigned_certificate.crl_series = (crl_series)series;
}
static void fill_verify_publickey(certificate* cert,string* pri){
    enum pk_algorithm algorithm;
    elliptic_curve_point* point;
    string x,y;

    INIT(x);
    INIT(y);

    int num;
    printf("输入证书认证钥匙类型(224/256):");
    scanf("%d",&num);
    getchar();
    if(num == 224)
        algorithm = ECDSA_NISTP224_WITH_SHA224;
    else
        algorithm = ECDSA_NISTP256_WITH_SHA256;
    cert->unsigned_certificate.version_and_type.verification_key.algorithm = algorithm;
    point = &cert->unsigned_certificate.version_and_type.verification_key.u.public_key;

    get_verification_key(algorithm,&x,&y,pri);

    point->type = UNCOMPRESSED;
    point->x.len = x.len;
    point->u.y.len = y.len;
    point->x.buf = (u8*)malloc(x.len);
    point->u.y.buf = (u8*)malloc(y.len);
    if(point->x.buf == NULL || point->u.y.buf == NULL){
        error();
        goto end;
    }
    memcpy(point->x.buf,x.buf,x.len);
    memcpy(point->u.y.buf,y.buf,y.len);
end:
    string_free(&x);
    string_free(&y);
}

static void test_encrypted(string* x,string* y,string *pri){
    string mess,messb,encrypted_mess,xx,yy,tag;
    INIT(mess);
    INIT(messb);
    INIT(encrypted_mess);
    INIT(xx);
    INIT(yy);
    INIT(tag);

    mess.len = 10;
    mess.buf = (u8*)malloc(10);
    mess.buf[0] = 'h';
    mess.buf[1] = 'e';
    mess.buf[2] = 'l';
    mess.buf[3] = 'l';
    mess.buf[4] = 'o';
    mess.buf[5] = 'w';
    mess.buf[6] = 'o';
    mess.buf[7] = 'r';
    mess.buf[8] = 'd';
    mess.buf[9] = '\0';
    int res;
    printf("%s %d\n",__FILE__,__LINE__);
    res = crypto_ECIES_encrypto_message(&mess,x,y,&xx,&yy,&encrypted_mess,&tag);
    string_printf("xx",&xx);
    string_printf("yy",&yy);
    string_printf("encryptd_mess",&encrypted_mess);
    string_printf("tag",&tag);

    FILE *fd;
    fd = fopen("encrypted_mess","w");
    fwrite(encrypted_mess.buf,1,encrypted_mess.len,fd);
    fd = fopen("xx","w");
    fwrite(xx.buf,1,xx.len,fd);
    fd = fopen("yy","w");
    fwrite(yy.buf,1,yy.len,fd);
    fd = fopen("tag","w");
    fwrite(tag.buf,1,tag.len,fd);


    if(res != 0){
        error();
        return;
    }
    res = crypto_ECIES_decrypto_message(&encrypted_mess,&xx,&yy,&tag,pri,&messb);
    printf("res :%d\n",res);
}
static void fill_encrypted_publickey(certificate* cert,string* pri){
    elliptic_curve_point* point;
    string x,y;
    pk_algorithm algorithm;
    INIT(x);
    INIT(y);

    int num;
    cert->unsigned_certificate.cf |= ENCRYPTION_KEY;
    algorithm = ECIES_NISTP256;

    cert->unsigned_certificate.flags_content.encryption_key.algorithm= algorithm;
    cert->unsigned_certificate.flags_content.encryption_key.u.ecies_nistp256.supported_symm_alg = AES_128_CCM;
    point = &cert->unsigned_certificate.flags_content.encryption_key.u.ecies_nistp256.public_key;

    get_enrypted_key(algorithm,&x,&y,pri); 
    point->type = UNCOMPRESSED;
    point->x.len = x.len;
    point->u.y.len = y.len;
    point->x.buf = (u8*)malloc(x.len);
    point->u.y.buf = (u8*)malloc(y.len);
    if(point->x.buf == NULL || point->u.y.buf == NULL){
        error();
        goto end;
    }
    memcpy(point->x.buf,x.buf,x.len);
    memcpy(point->u.y.buf,y.buf,y.len);
end:
    string_free(&x);
    string_free(&y);
}
static void verify_pri_2_file(char *name,string* pri){
    FILE* fp;
    char pwd[100];
    strcpy(pwd,name);
    strcat(pwd,VERI_PRIKEY_POSTFIX); 
    fp = fopen(pwd,"w");
    printf("%s\n",pwd);
    if(fp == NULL){
        perror("verify_pri_2_file");
        error();
        return;
    }
    if(fwrite(pri->buf,1,pri->len,fp) != pri->len){
        error();
        return;
    }
    fclose(fp);
}
static void file_2_verify_pri(char* name,string* pri){
    FILE *fp;
    fp = fopen(name,"r");
    if(fp == NULL){
        error();
        return;
    }
    pri->len = 40;
    pri->buf = (u8*)malloc(pri->len);
    if(pri->buf == NULL){
        error();
        return;
    }
    pri->len = fread(pri->buf,1,pri->len,fp);
    if(pri->len <=0 ){
        error();
        return;
    }
}
static void encrypted_pri_2_file(char* name,string* pri){
    FILE* fp;
    char pwd[100];
    strcpy(pwd,name);
    strcat(pwd,ENRY_PRIKEY_POSTFIX); 
    fp = fopen(pwd,"w");
    if(fp == NULL){
        error();
        return;
    }
    if(fwrite(pri->buf,1,pri->len,fp) != pri->len){
        error();
        return;
    }
    fclose(fp);
}
static void fill_tobesigned_certificate(certificate* cert,char* name,string* pri){
    string en_pri;
    char type;

    INIT(en_pri);

    fill_holder_type(cert);
    fill_certspecificdata(cert);
    fill_expiration(cert);
    fill_start_validity(cert);
    fill_crlseries(cert);

    fill_verify_publickey(cert,pri);
    verify_pri_2_file(name,pri);

    printf("是否要添加加密钥匙(y/n):");
    scanf("%c",&type);
    if(type == 'y'){
        fill_encrypted_publickey(cert,&en_pri);
        encrypted_pri_2_file(name,&en_pri);
    }

end:
    string_free(&en_pri);
}

static void cert_2_file(certificate* cert,char* name){
    string str,temp;
    FILE *fp;
    INIT(str);
    INIT(temp);
    if(certificate_2_string(cert,&str)){
        error();
        return;
    }
    printf("\nlen :%d   len %d\n\n",str.len,string_2_certificate(&str,cert));
    fp = fopen(name,"w");
    if(fp == NULL){
        error();
        return;
    }
    if(fwrite(str.buf,1,str.len,fp) != str.len){
        error();
        fclose(fp);
        return;
    }
    string_free(&str);
    fclose(fp);
}
static void file_2_cert(certificate* cert,char* name){
    string str;
    FILE *fp;

    INIT(str);
    fp = fopen(name,"r");
    if(fp == NULL){
        error();
        return;
    }
    str.len = 1024;
    str.buf = (u8*)malloc(str.len);
    if(str.buf == NULL){
        error();
        return;
    }
    str.len = fread(str.buf,1,str.len,fp);
    if(str.len <=0){
        error();
        fclose(fp);
        return;
    }
    if(string_2_certificate(&str,cert) <= 0 ){
        certificate_printf(cert);
        error();
        fclose(fp);
        return;
    }
    fclose(fp);
    string_free(&str);
}
static void generate_ca_cert(certificate *cert){
    string pri;
    char pwd[100];
    INIT(pri);
    fill_version_and_type(cert);
    strcpy(pwd,MAIN_DIR);
    strcat(pwd,"ca_cert/ca");
    fill_tobesigned_certificate(cert,pwd,&pri);
    cert_signed_self(cert,&pri);
    string_free(&pri);
}
static void generate_no_ca_cert(certificate *cert,char* name){
    char pwd[100];
    string pri;
    string ca_pri;
    certificate ca_cert;

    INIT(ca_cert);
    INIT(pri);
    INIT(ca_pri);

    strcpy(pwd,MAIN_DIR);
    strcat(pwd,"issued_cert/");
    strcat(pwd,name);
    fill_version_and_type(cert);
    fill_tobesigned_certificate(cert,pwd,&pri);
    file_2_verify_pri("/home/ljh/ljh-wave-1609.2/cert/ca_cert/ca.veri.pri",&ca_pri);
    file_2_cert(&ca_cert,"/home/ljh/ljh-wave-1609.2/cert/ca_cert/ca.cert");
    certificate_printf(&ca_cert);
    cert_signed_cert(&ca_cert,&ca_pri,cert);

    string_free(&pri);
    string_free(&ca_pri);
    certificate_free(&ca_cert);
}

void generate_cert(){
    char type;
    certificate cert;
    INIT(cert);
    char pwd[100];
    char name[100];
    printf("是否生成一个ca(y/n):");
    scanf("%c",&type);
    if(type == 'y'){
        generate_ca_cert(&cert);
        strcpy(pwd,"/home/ljh/ljh-wave-1609.2/cert/ca_cert/ca.cert");
        cert_2_file(&cert,pwd);
        certificate_printf(&cert);
    }
    else{
        printf("输入证书名字:");
        scanf("%s",name);
        generate_no_ca_cert(&cert,name);
        strcpy(pwd,"/home/ljh/ljh-wave-1609.2/cert/issued_cert/");
        strcat(pwd,name);
        strcat(pwd,".cert");
        cert_2_file(&cert,pwd);
        certificate_printf(&cert);
    }
}
static void string_malloc(string* ptr,int len){
    ptr->len = len;
    ptr->buf = (u8*)malloc(len);
    if(ptr->buf ==NULL)
        error();
}
static void test(){
    string x,y,xx,yy,tag,mess,en_mess,pri,m;
    INIT(x);
    INIT(y);
    INIT(xx);
    INIT(yy);
    INIT(tag);
    INIT(mess);
    INIT(en_mess);
    INIT(pri);
    INIT(m);

    mess.len = 10;
    mess.buf = "helloword";

    int res = crypto_ECIES_get_key(&pri,&x,&y);
    string_printf("p",&pri);
    string_printf("x",&x);
    string_printf("y",&y);
    printf("res :%d\n",res);

    FILE *fd;
    fd = fopen("./x","w");
    fwrite(x.buf,1,x.len,fd);
    fd = fopen("./y","w");
    fwrite(y.buf,1,y.len,fd);
    fd = fopen("./p","w");
    fwrite(pri.buf,1,pri.len,fd);
  
   
    
    res = crypto_ECIES_encrypto_message(&mess,&x,&y,&xx,&yy,&en_mess,&tag);
   // string_malloc(&xx,32);
   // string_malloc(&yy,32);
   // string_malloc(&tag,20);
   // string_malloc(&en_mess,20);
    //res = ECIES_encrypto_message(mess.buf,mess.len,x.buf,x.len,y.buf,y.len,xx.buf,&xx.len,yy.buf,&yy.len,en_mess.buf,&en_mess.len,tag.buf,&tag.len);
    string_printf("tag",&tag);
    string_printf("xx",&xx);
    string_printf("yy",&yy);
    string_printf("en_mess",&en_mess);
    printf("res :%d\n",res);
    
   
    fd = fopen("encrypted_mess","w");
    fwrite(en_mess.buf,1,en_mess.len,fd);
    fd = fopen("xx","w");
    fwrite(xx.buf,1,xx.len,fd);
    fd = fopen("yy","w");
    fwrite(yy.buf,1,yy.len,fd);
    fd = fopen("tag","w");
    fwrite(tag.buf,1,tag.len,fd);


    res = crypto_ECIES_decrypto_message(&en_mess,&xx,&yy,&tag,&pri,&m);
    //string_malloc(&m,11);
    //string_printf("m",&m);
    //res = ECIES_decrypto_message(en_mess.buf,en_mess.len,xx.buf,xx.len,yy.buf,yy.len,tag.buf,tag.len,pri.buf,pri.len,m.buf,&m.len);
    string_printf("m",&m);
    printf("%s\n",m.buf);
    printf("res :%d\n",res);

}
int main(){
    generate_cert();
    //test();
}
