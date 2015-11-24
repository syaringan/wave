#ifndef DATA_H
#define DATA_H
#include "../utils/common.h"
/*
 * 1  free
 */
#define ARRAY(TYPE,name) struct{\
        TYPE* buf;\
        u16 len;} name

typedef u64 time64;
typedef u32 psid;
typedef u16 certificate_duration;
typedef u32 crl_series;
typedef u32 time32;

/**
 * 下面两个字段都是协议中有，但是没有定义他里面有什么类型
 * */
typedef enum tbsdata_extension_type{
    UNUSED = 0,
} tbsdata_extension_type;
typedef enum tobe_encrypted_anonymous_cert_response{
    UNSED = 0,
}tobe_encrypted_anonymous_cert_response;


typedef enum crl_type{
    ID_ONLY = 0,
    ID_AND_EXPIRY = 1,
}crl_type;

typedef enum certificate_request_error_code{
    VERIFICATION_FAILURE = 0,
    FUTURE_REQUEST = 1,
    REQUEST_TOO_OLD = 2,
    FUTURE_ENROLMENT_CERT = 3,
    ENROLMENT_CERT_EXPIRED = 4,
    ENROLMENT_CERT_REVOKED = 5,
    ENROLMENT_CERT_UNAUTHORIZED_TYPE = 6,
    ENROLMENT_CERT_UNAUTHORIZED_REGION = 6,
    ENROLMENT_CERT_UNAUTHORIZED_PSIDS = 6,
    FUTURE_CA_CERT = 7,
    CA_CERT_EXPIERD = 8,
    CA_CEAT_REVOKED = 9,
}certificate_request_error_code;

typedef enum region_type{
    FROM_ISSUER = 0,
    CIRCLE = 1,
    RECTANGLE = 2,
    POLYGON = 3,
    NONE = 4,
}region_type;

typedef enum ecc_public_keytype{
    X_COORDINATE_ONLY = 0,
    COMPRESSED_LSB_Y_0 = 2,
    COMPRESSED_LSB_Y_1 = 3,
    UNCOMPRESSED = 4,
}ecc_public_keytype;


typedef enum array_type{
    ARRAY_TYPE_FROM_ISSUER = 0,
    ARRAY_TYPE_SPECIFIED = 1,
}array_type;

typedef enum signer_identifier_type{
    SELF = 0,
    CERTIFICATE_DIGEST_WITH_ECDSAP224 = 1,
    CERTIFICATE_DIGEST_WITH_ECDSAP256 = 2,
    CERTIFICATE = 3,
    CERTIFICATE_CHAIN = 4,
    CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM = 5,
}signer_identifier_type;

typedef enum symm_algorithm{
    AES_128_CCM = 0,
    SYMM_ALGORITHM_NOT_SET = 255,
}symm_algorithm;

typedef enum holder_type{
    SDE_ANONYMOUS = 0,
    SDE_IDENTIFIED_NOT_LOCALIZED = 1,
    SDE_IDENTIFIED_LOCALIZED = 2,
    SDE_ENROLMENT = 3,
    WSA = 4,
    WSA_ENROLMENT = 5,
    SDE_CA = 6,
    WSA_CA = 7,
    CRL_SIGNER = 8,
	ROOT_CA = 255,
}holder_type;

typedef enum holder_type_flags{
    FLAGS_SDE_ANONYMOUS = 1<<0,
    FLAGS_SDE_IDENTIFIED_NOT_LOCALIZED = 1<<1,
    FLAGS_SDE_IDENTIFIED_LOCALIZED = 1<<2,
    FLAGS_SDE_ENROLMENT = 1<<3,
    FLAGS_WSA = 1<<4,
    FLAGS_WSA_ENROLMENT = 1<<5,
    FLAGS_SDE_CA = 1<<6,
    FLAGS_WSA_CA = 1<<7,
    FLAGS_CRL_SIGNER = 1<<8,
}holder_type_flags;

typedef enum certificate_content_flags{
    USE_START_VALIDITY = 1<<0,
    LIFETIME_IS_DURATION = 1<<1,
    ENCRYPTION_KEY = 1<<2,
}certificate_content_flags;

typedef enum content_type{
    UNSECURED = 0,
    SIGNED = 1,
    ENCRYPTED = 2,
    CERTIFICATE_REQUEST = 3,
    CERTIFICATE_RESPONSE = 4,
    ANOYMOUS_CERTIFICATE_RESPONSE = 5,
    CERTIFICATE_REQUSET_ERROR = 6,
    CONTENT_TYPE_CRL_REQUEST = 7,
    CRL = 8,
    SIGNED_PARTIAL_PAYLOAD = 9,
    SIGNED_EXTERNAL_PAYLOAD = 10,
    SIGNED_WSA = 11,
    CERTIFACATE_RESPONSE_ACKNOWLEDGMENT = 12,
}content_type;

typedef enum tbsdata_flags{
    USE_GENERATION_TIME = 1<<0,
    EXPIRES = 1<<1,
    USE_LOCATION = 1<<2,
    EXTENSIONS = 1<<3
}tbsdata_flags;
/**
 * buf_to  1
 */
typedef struct time64_with_standard_deviation{
    time64 time;
    u8 long_std_dev;
}time64_with_standard_deviation;

/*
 * 2 free  buf_to  2
 */

typedef struct tbsdata_extension{
    tbsdata_extension_type type;
    ARRAY(u8,value);//这个的编码应该是先用一字节表明长度，然后编码？
}tbsdata_extension;
/**
 *  	   buf_to  3
 */
typedef struct three_d_location{
    s32 latitude;
    s32 longitude;
    u8 elevation[2];
}three_d_location;
/**
 *	buf_to 4
 */
typedef struct hashedid8{
    u8 hashedid8[8];
}hashedid8;

typedef enum pk_algorithm{
    ECDSA_NISTP224_WITH_SHA224 = 0,
    ECDSA_NISTP256_WITH_SHA256 = 1,
    ECIES_NISTP256 =2,
    PK_ALGOTITHM_NOT_SET = 255,
}pk_algorithm;
/*
 * 3 free   buf_to 5
 */
typedef struct elliptic_curve_point{
    ecc_public_keytype type;
    ARRAY(u8,x);
    union{
        ARRAY(u8,y);
    }u;
}elliptic_curve_point;
/*
 * 4 free  buf_to 6
 */
typedef struct ecdsa_signature{
    elliptic_curve_point r;
    ARRAY(u8,s);
}ecdsa_signature;

/*
 * 5 free buf_to 7
 */
typedef struct signature{
    union{
        ecdsa_signature ecdsa_signature;
        ARRAY(u8,signature);
    }u;
}signature;

/*
 * 6 free buf_to 8
 */
typedef struct public_key{
    pk_algorithm algorithm;
    union{
        elliptic_curve_point public_key;
        struct {
            symm_algorithm supported_symm_alg;
            elliptic_curve_point public_key;
        }ecies_nistp256;
     	ARRAY(u8,other_key);
    }u;
}public_key;

/*
 * buf_to 9
 */

typedef struct two_d_location{
    s32 latitude;
    s32 longitude;
}two_d_location;


/*
 * buf_to 10
 */

typedef struct rectangular_region{
    two_d_location north_west;
    two_d_location south_east;
}rectangular_region;

/*
 * buf_to 11
 */

typedef struct circular_region{
    two_d_location center;
    u16 radius;
}circular_region;
/*
 * 7 free buf_to  12
 */
typedef struct geographic_region{
    region_type region_type;
    union{
        circular_region circular_region;
        ARRAY(rectangular_region,rectangular_region);
        ARRAY(two_d_location,polygonal_region);
        ARRAY(u8,other_region);
    }u;
}geographic_region;

/*
 * 8 free buf_to  13
 */



typedef struct psid_priority{
    psid psid;
    u8 max_priority;
}psid_priority;
/*
 * 9 free buf_to  14
 */

typedef struct psid_priority_array{
    array_type type;
    union{
        ARRAY(psid_priority,permissions_list);
        ARRAY(u8,other_permissions);
    }u;
}psid_priority_array;

/*
 * 10 free buf_to  15
 */

typedef struct psid_array{
    array_type type;
    union{
        ARRAY(psid,permissions_list);
        ARRAY(u8,other_permissions);
    }u;
}psid_array;
/*
 * 11 free buf_to  16
 */

typedef struct psid_ssp{
    psid psid;
    ARRAY(u8,service_specific_permissions);
}psid_ssp;
/*
 * 12 free buf_to  17
 */

typedef struct psid_ssp_array{
    array_type type;
    union{
        ARRAY(psid_ssp,permissions_list);
        ARRAY(u8,other_permissions);
    }u;
}psid_ssp_array;
/*
 * 13 free buf_to  18
 */

typedef struct psid_priority_ssp{
    psid psid;
    u8 max_priority;
    ARRAY(u8,service_specific_permissions);
}psid_priority_ssp;
/*
 * 14 free buf_to  19
 */

typedef struct psid_priority_ssp_array{
    array_type type;
    union{
        ARRAY(psid_priority_ssp,permissions_list);
        ARRAY(u8,other_permissions);
    }u;
}psid_priority_ssp_array;
/*
 * 15 free buf_to  20
 */

typedef struct wsa_scope{
    ARRAY(u8,name);
    psid_priority_ssp_array permissions;
    geographic_region region;
}wsa_scope;
/*
 * 16 free  buf_to  21
 */

typedef struct anonymous_scope{
    ARRAY(u8,additionla_data);
    psid_ssp_array permissions;
    geographic_region region;
}anonymous_scope;
/*
 * 17 free  buf_to  22
 */

typedef struct identified_scope{
    ARRAY(u8,name);
    psid_ssp_array permissions;
    geographic_region region;
}identified_scope;
/*
 * 18 free  buf_to  23
 */

typedef struct identified_not_localized_scope{
    ARRAY(u8,name);
    psid_ssp_array permissions;
}identified_not_localized_scope;
/*
 * 19 free  buf_to  24
 */

typedef struct wsa_ca_scope{
    ARRAY(u8,name);
    psid_priority_array permissions;
    geographic_region region;
}wsa_ca_scope;
/*
 * 20 free  buf_to  25
 */

typedef struct sec_data_exch_ca_scope{
    ARRAY(u8,name);
    holder_type_flags permitted_holder_types;
    psid_array permissions;
    geographic_region region;
}sec_data_exch_ca_scope;
/*
 * 21 free  buf_to  26
 */

typedef struct root_ca_scope{
    ARRAY(u8,name);
    holder_type_flags permitted_holder_types;
    struct{
        psid_array secure_data_permissions;
        psid_priority_array wsa_permissions;
        ARRAY(u8,other_permissions);
    }flags_content;
    geographic_region region;
}root_ca_scope;
/*
 * 22 free  buf_to  27
 */

typedef struct cert_specific_data{
    union{
        root_ca_scope root_ca_scope;
        sec_data_exch_ca_scope sde_ca_scope;
        wsa_ca_scope wsa_ca_scope;
		ARRAY(crl_series,responsible_series);
        identified_not_localized_scope id_non_loc_scope;
        identified_scope id_scope;
        anonymous_scope anonymous_scope;
        wsa_scope wsa_scope;
        ARRAY(u8,other_scope);
    }u;
}cert_specific_data;
/*
 * 23 free  buf_to  28
 */

typedef struct tobesigned_certificate{
    holder_type holder_type;
    certificate_content_flags cf;
    union{
        struct{
            hashedid8 signer_id;
            pk_algorithm signature_alg;
        }no_root_ca;
    }u;
    cert_specific_data scope;
    time32 expiration;
    crl_series crl_series;
    union{
        public_key verification_key;
        ARRAY(u8,other_key_material);
    }version_and_type;
    struct{
        certificate_duration lifetime;
        time32 start_validity;
        public_key encryption_key;
        ARRAY(u8,other_cert_content);
    }flags_content;
}tobesigned_certificate;
/*
 * 24 free  buf_to  29
 */

typedef struct certificate{
    u8 version_and_type;
    tobesigned_certificate unsigned_certificate;
    union{
        signature signature;
        elliptic_curve_point reconstruction_value;
        ARRAY(u8,signature_material);
    }u;
}certificate;
/*
 * 25 free  buf_to  30
 */

typedef struct signer_identifier{
    signer_identifier_type type;
    union{
        hashedid8 digest;
        certificate certificate;
        ARRAY(certificate,certificates);
        struct{
            pk_algorithm algorithm;
            hashedid8 digest;
        }other_algorithm;
        ARRAY(u8,id);
    }u;
} signer_identifier;

/*
 * buf_to  31
 */

typedef struct crl_request{
    hashedid8 issuer;
    crl_series crl_series;
    time32 issue_date;
}crl_request;

/*
 * buf_to  32
 */

typedef struct certid10{
    u8 certid10[10];
}certid10;

/*
 * buf_to  33
 */
typedef struct id_and_date{
    certid10 id;
    time32 expiry;
}id_and_date;
/*
 * 26 free  buf_to  34
 */

typedef struct tobesigned_crl{
    crl_type type;
    crl_series crl_series;
    hashedid8 ca_id;
    u32 crl_serial;
    time32 start_period;
    time32 issue_date;
    time32 next_crl;
    union{
        ARRAY(certid10,entries);
        ARRAY(id_and_date,expiring_entries);
        ARRAY(u8,other_entries);
    }u;
}tobesigned_crl;
/*
 * 27 free  buf_to  35
 */

typedef struct crl{
    u8 version;
    signer_identifier signer;
    tobesigned_crl  unsigned_crl;
    signature  signature;
}crl;

/*
 *  buf_to  36
 */

typedef struct tobe_encrypted_certificate_response_acknowledgment{
    u8 response_hash[10];
}tobe_encrypted_certificate_response_acknowledgment;

/*
 * 28 free  buf_to  37
 */

typedef struct tobe_encrypted_certificate_request_error{
    signer_identifier signer;
    u8 request_hash[10];
    certificate_request_error_code reason;
    signature signature;
}tobe_encrypted_certificate_request_error;
/*
 * 29 free  buf_to  38
 */

typedef struct tobe_encrypted_certificate_response{
    u8 f;//这个地方在协议中是flag，可能是说一bite的意思，这个我们后面在看。
    ARRAY(certificate,certificate_chain);
    union{
        ARRAY(u8,recon_priv);
        ARRAY(u8,other_material);
    }u;    
    ARRAY(crl,crl_path);
}tobe_encrypted_certificate_response;

/*
 * 30 free  buf_to  39
 */

typedef struct tobesigned_certificate_request{
    u8 version_and_type;
    time32 request_time;
    holder_type holder_type;
    certificate_content_flags cf;
    cert_specific_data type_specific_data;
    time32 expiration;
    struct{
        certificate_duration lifetime;
        time32 start_validity;
        public_key encryption_key;
        ARRAY(u8,other_cert);
    }flags_content;
    public_key verification_key;
    public_key response_encryption_key;
}tobesigned_certificate_request;

/*
 * 31 free  buf_to  40
 */

typedef struct certificate_request{
    signer_identifier signer;
    tobesigned_certificate_request unsigned_csr;
    signature signature;
}certificate_request;

/*
 * 32 free  buf_to  41
 */ 

typedef struct tobesigned_data{
   tbsdata_flags tf;
   union{
        struct {
            psid psid;
            ARRAY(u8,data);
        }type_signed;
		struct{
			psid psid;
			ARRAY(u8,ext_data);
			ARRAY(u8,data);
		}type_signed_partical;
		struct{
			psid psid;
			ARRAY(u8,ext_data);
		}type_signed_external;
        ARRAY(u8,data);
   }u;
   struct {
        time64_with_standard_deviation generation_time;
        time64 exipir_time;
        three_d_location generation_location;
        ARRAY(tbsdata_extension,extensions);
        ARRAY(u8,other_data);
   }flags_content;
}tobesigned_data;

/*
 * 33 free  buf_to  42
 */

typedef struct signed_data{
    struct signer_identifier signer;
    struct tobesigned_data unsigned_data;
    struct signature signature;
}signed_data;
/*
 * 34 free  buf_to  43
 */

typedef struct tobe_encrypted{
    content_type type;
    union{
        ARRAY(u8,plain_text);
        signed_data signed_data;
        certificate_request request;
        tobe_encrypted_certificate_response 
                response;
        tobe_encrypted_anonymous_cert_response 
                anon_response;
        tobe_encrypted_certificate_request_error
                request_error;
        crl_request crl_request;
        crl crl;
        tobe_encrypted_certificate_response_acknowledgment
                ack;
        ARRAY(u8,data);
    }u;
}tobe_encrypted;
/*
 * 35 free  buf_to  44
 */

typedef struct aes_ccm_ciphertext{
    u8 nonce[12];
    ARRAY(u8,ccm_ciphertext);
}aes_ccm_ciphertext;

/*
 * 36 free  buf_to  45
 */

typedef struct ecies_nist_p256_encrypted_key{
    elliptic_curve_point  v;
    ARRAY(u8,c);
    u8 t[20];
}ecies_nist_p256_encrypted_key;
/*
 * 37 free  buf_to  46
 */

typedef struct recipient_info{
    hashedid8 cert_id;
    union{
        ecies_nist_p256_encrypted_key enc_key;
        ARRAY(u8,other_enc_key);
    }u;
}recipient_info;

/*
 * 38 free  buf_to  47
 */

typedef struct encrypted_data{
    symm_algorithm symm_algorithm;
    ARRAY(recipient_info,recipients);
    union{
        aes_ccm_ciphertext ciphertext;
        ARRAY(u8,other_ciphertext);
    }u;
}encrypted_data;
/*
 * 39 free  buf_to  48
 */

typedef struct tobesigned_wsa{
    ARRAY(u8,permission_indices);
    tbsdata_flags tf;
    ARRAY(u8,data);
    time64_with_standard_deviation generation_time;
    time64 expire_time;
    three_d_location generation_location;
    struct{
        ARRAY(tbsdata_extension,extension);
        ARRAY(u8,other_data);
    }flags_content;
}tobesigned_wsa;
/*
 * 40 free  buf_to  49
 */

typedef struct signed_wsa{
    signer_identifier signer;
    tobesigned_wsa unsigned_wsa;
    signature signature;
}signed_wsa;




/*
 * 41 free  buf_to  50
 */

typedef struct sec_data{
	u8 protocol_version;//1
	content_type type;  //4
	union
	{
		ARRAY(u8,data); //8
		struct signed_data signed_data;//288
		struct signed_wsa signed_wsa;
		struct encrypted_data encrypted_data;
		struct crl_request crl_request;
		struct crl crl;
        ARRAY(u8,other_data);
	}u;//292
}sec_data;//300
#endif
