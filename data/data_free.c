/*=============================================================================
#
# Author: 杨广华 - edesale@qq.com
#
# QQ : 374970456
#
# Last modified: 2015-10-11 14:45
#
# Filename: data_free.c
#
# Description: 
#
=============================================================================*/
#include "data.h"
#include <stdlib.h>
#include <stddef.h>

#define ARRAY_FREE(m) array_free((void**)(m))
/**
 * YGH 1
 */
static void array_free(void **addr){
	free(*addr);
	*addr = NULL;
}

/**	
 * YGH 2
 */
static void tbsdata_extension_free(tbsdata_extension* tbsdata_extension)	{
	if(NULL == tbsdata_extension->value.buf)
		return ;
	ARRAY_FREE(&tbsdata_extension->value);
}

/**
 * YGH 3
 * @elliptic_curve_point* 释放的目标
 * @algorithm 外部传入参数(这个数据在free中也不起作用，删除)
 * @field外部传入参数，在释放函数中好像没用，先保留，这个数据不需要，删除就好
 */
static void elliptic_curve_point_free(elliptic_curve_point* elliptic_curve_point){
	if(NULL != elliptic_curve_point->x.buf) 
		ARRAY_FREE(&elliptic_curve_point->x);
	if(elliptic_curve_point->type == UNCOMPRESSED)
		if(NULL != elliptic_curve_point->u.y.buf)
			ARRAY_FREE(&elliptic_curve_point->u.y);
}
 /*
 *YGH  4
 */
static void ecdsa_signature_free(ecdsa_signature* ecdsa_signature){	
	elliptic_curve_point_free(&ecdsa_signature->r);
	if(NULL != ecdsa_signature->s.buf)
		ARRAY_FREE(&ecdsa_signature->s);
}


/*
 * YGH  5 
 * @signature* 需要释放的结构体
 * @pk_algorithm 外部传入参数,看协议中signature的定义
 */
static void signature_free(signature* signature, pk_algorithm algorithm  ){
	switch(algorithm){
		case ECDSA_NISTP224_WITH_SHA224:
		case ECDSA_NISTP256_WITH_SHA256:
			ecdsa_signature_free(&signature->u.ecdsa_signature);
			break;
		default:
			ARRAY_FREE(&signature->u.signature);
	}			
}
/*
 * YGH 6
 */

static void public_key_free(public_key* public_key){
	switch(public_key->algorithm){
		case ECDSA_NISTP224_WITH_SHA224:
		case ECDSA_NISTP256_WITH_SHA256:
			elliptic_curve_point_free(&public_key->u.public_key);
			break;
		case ECIES_NISTP256:
			elliptic_curve_point_free(&public_key->u.ecies_nistp256.public_key);
			break;
		default:
			if(NULL != public_key->u.other_key.buf)
				ARRAY_FREE(&public_key->u.other_key);
			break;
	}
}

/**
 * YGH 7
 */
static void geographic_region_free(geographic_region* geographic_region){
	switch(geographic_region->region_type){
		case FROM_ISSUER:
			break;
		case CIRCLE:
			break;
		case RECTANGLE:
			ARRAY_FREE(&geographic_region->u.rectangular_region);
			break;
		case POLYGON:
			ARRAY_FREE(&geographic_region->u.polygonal_region);
			break;
		case NONE:
			break;
	    default:
			ARRAY_FREE(&geographic_region->u.other_region);
	}
}

/**
 * YGH 8    该结构体无指针
 */

//static void psid_priority_free(psid_priority*  psid_priority){
//}

/**
 * YGH 9
 */

static void psid_priority_array_free(psid_priority_array*  psid_priority_array){
    switch(psid_priority_array->type){
        case ARRAY_TYPE_SPECIFIED:
			if(NULL != psid_priority_array->u.permissions_list.buf)
				ARRAY_FREE(&psid_priority_array->u.permissions_list);
			break;
		case ARRAY_TYPE_FROM_ISSUER:
			break;
		default:
			if(NULL!=psid_priority_array->u.other_permissions.buf)
			ARRAY_FREE(&psid_priority_array->u.other_permissions);
	}
}


/**
 *YGH 10
 */

static void psid_array_free(psid_array* psid_array){
     switch(psid_array->type){
		 case ARRAY_TYPE_SPECIFIED:
           if(NULL!=psid_array->u.permissions_list.buf)
		   ARRAY_FREE(&psid_array->u.permissions_list);
		   break;
		 case ARRAY_TYPE_FROM_ISSUER:
		   break;
		 default:
		   if(NULL!=psid_array->u.other_permissions.buf)
		    ARRAY_FREE(&psid_array->u.other_permissions);
	 }
}

/**
 *YGH 11
 */
static void psid_ssp_free(psid_ssp* psid_ssp){
	  if(NULL!=psid_ssp->service_specific_permissions.buf)
		  ARRAY_FREE(&psid_ssp->service_specific_permissions);
}

/**
 *YGH 12
 */
static void psid_ssp_array_free(psid_ssp_array* psid_ssp_array){
	int i;
	 switch(psid_ssp_array->type){
		 case ARRAY_TYPE_SPECIFIED:
			if(NULL!=psid_ssp_array->u.permissions_list.buf){
				for(i = 0;i<psid_ssp_array->u.permissions_list.len;i++){
					psid_ssp_free(psid_ssp_array->u.permissions_list.buf + i);
				}
				ARRAY_FREE(&psid_ssp_array->u.permissions_list);
			}
			break;
		 case ARRAY_TYPE_FROM_ISSUER:
			break;
		 default:
			if(NULL!=psid_ssp_array->u.other_permissions.buf)
				ARRAY_FREE(&psid_ssp_array->u.other_permissions);
	 }
}

/**
 *YGH 13
 */

static void psid_priority_ssp_free(psid_priority_ssp* psid_priority_ssp){
      if(NULL!=psid_priority_ssp->service_specific_permissions.buf)
		  ARRAY_FREE(&psid_priority_ssp->service_specific_permissions);
}
/**
 *YGH 14
 */
static void psid_priority_ssp_array_free(psid_priority_ssp_array* psid_priority_ssp_array){
	int i;
        switch(psid_priority_ssp_array->type){
			case ARRAY_TYPE_SPECIFIED:
				if(NULL!=psid_priority_ssp_array->u.permissions_list.buf){
					for(i = 0;i<psid_priority_ssp_array->u.permissions_list.len;i++){					
						psid_priority_ssp_free(psid_priority_ssp_array->u.permissions_list.buf + i);				
					}				
					ARRAY_FREE(&psid_priority_ssp_array->u.permissions_list);			
				}
				break;
			case ARRAY_TYPE_FROM_ISSUER:
			 break;
			default: 
			    if(NULL!=psid_priority_ssp_array->u.other_permissions.buf)
					ARRAY_FREE(&psid_priority_ssp_array->u.other_permissions);
		}				 
	}
/**
 *YGH 15
 */
static void wsa_scope_free(wsa_scope* wsa_scope){
	if(NULL!=wsa_scope->name.buf)
		ARRAY_FREE(&wsa_scope->name);
	psid_priority_ssp_array_free(&wsa_scope->permissions);
	geographic_region_free(&wsa_scope->region);
}

/**
 *YGH 16
 */
static void anonymous_scope_free(anonymous_scope* anonymous_scope){
        if(NULL!=anonymous_scope->additionla_data.buf)
         ARRAY_FREE(&anonymous_scope->additionla_data);
		psid_ssp_array_free(&anonymous_scope->permissions);
		geographic_region_free(&anonymous_scope->region);

}

/**
 *YGH 17
 */
static void identified_scope_free(identified_scope* identified_scope){
	if(NULL!=identified_scope->name.buf)
		ARRAY_FREE(&identified_scope->name);
	psid_ssp_array_free(&identified_scope->permissions);
	geographic_region_free(&identified_scope->region);

}
/**
 *YGH 18
 */
static void identified_not_localized_scope_free(identified_not_localized_scope* 
				identified_not_localized_scope){
	if(NULL!=identified_not_localized_scope->name.buf)
		ARRAY_FREE(&identified_not_localized_scope->name);
	psid_ssp_array_free(&identified_not_localized_scope->permissions);
}
/**
 *YGH 19
 */
static void wsa_ca_scope_free(wsa_ca_scope* wsa_ca_scope){
	if(NULL!=wsa_ca_scope->name.buf)
		ARRAY_FREE(&wsa_ca_scope->name);
	psid_priority_array_free(&wsa_ca_scope->permissions);
	geographic_region_free(&wsa_ca_scope->region);
}

/**
 *YGH 20
 */
static void sec_data_exch_ca_scope_free(sec_data_exch_ca_scope* sec_data_exch_ca_scope){
	if(NULL!=sec_data_exch_ca_scope->name.buf)
		ARRAY_FREE(&sec_data_exch_ca_scope->name);
	psid_array_free(&sec_data_exch_ca_scope->permissions);
	geographic_region_free(&sec_data_exch_ca_scope->region);
}


/**
 *YGH 21
 */
static void root_ca_scope_free(root_ca_scope* root_ca_scope){
      if(NULL!=root_ca_scope->name.buf)
		  ARRAY_FREE(&root_ca_scope->name);
	  if((root_ca_scope->permitted_holder_types & 1<<0)!=0 ||
			(root_ca_scope->permitted_holder_types & 1<<1)!=0 ||
			(root_ca_scope->permitted_holder_types & 1<<2)!=0 ||
			(root_ca_scope->permitted_holder_types & 1<<3)!=0 ||
			(root_ca_scope->permitted_holder_types & 1<<6)!=0){
		  psid_array_free(&root_ca_scope->flags_content.secure_data_permissions);
	  }
	  if((root_ca_scope->permitted_holder_types & 1<<4)!=0 ||
			(root_ca_scope->permitted_holder_types & 1<<5)!=0 ||
			((root_ca_scope->permitted_holder_types > 1<<6) && (root_ca_scope->permitted_holder_types & 1<<7)!=0)){
		  psid_priority_array_free (&root_ca_scope->flags_content.wsa_permissions);
	  }
	  if((root_ca_scope->permitted_holder_types > 1<<6) && (root_ca_scope->permitted_holder_types & 1<<8)!=0){
		  if(NULL!=root_ca_scope->flags_content.other_permissions.buf)
			  ARRAY_FREE(&root_ca_scope->flags_content.other_permissions);
	  }
	  geographic_region_free(&root_ca_scope->region);
}
/**
 *YGH 22
 *@holder_typ 外部数据结构传入的参数
 */
static void cert_specific_data_free(cert_specific_data* cert_specific_data,holder_type holder_type){
           switch(holder_type){
			case ROOT_CA:
			   root_ca_scope_free(&cert_specific_data->u.root_ca_scope);
			   break;
			case SDE_CA:
			case SDE_ENROLMENT:
			   sec_data_exch_ca_scope_free(&cert_specific_data->u.sde_ca_scope);
			   break;
			case WSA_CA:
			case WSA_ENROLMENT:
			   wsa_ca_scope_free(&cert_specific_data->u.wsa_ca_scope);
			   break;
			case CRL_SIGNER:
			   free(cert_specific_data->u.responsible_series);
			   break;
			case SDE_IDENTIFIED_NOT_LOCALIZED:
			   identified_not_localized_scope_free(&cert_specific_data->u.id_non_loc_scope);
			   break;
			case SDE_IDENTIFIED_LOCALIZED:
			   identified_scope_free(&cert_specific_data->u.id_scope);
			   break;
			case SDE_ANONYMOUS:
			   anonymous_scope_free(&cert_specific_data->u.anonymous_scope);
			   break;
			case WSA:
			   wsa_scope_free(&cert_specific_data->u.wsa_scope);
			   break;
			default:
			   if(NULL!=cert_specific_data->u.other_scope.buf)
				   ARRAY_FREE(&cert_specific_data->u.other_scope);
		   }
}
/**
 *YGH 23
 *@uint8 外部数据结构传入
 */
static void tobesigned_certificate_free(tobesigned_certificate* tobesigned_certificate,u8 version_and_type){
	cert_specific_data_free(&tobesigned_certificate->scope,tobesigned_certificate->holder_type);
	switch(version_and_type){
		case 2:
			public_key_free(&tobesigned_certificate->version_and_type.verification_key);
		   break;
	    case 3:
	   	 break;
		default:
		if(NULL!=tobesigned_certificate->version_and_type.other_key_material.buf)
			ARRAY_FREE(&tobesigned_certificate->version_and_type.other_key_material);
	}
	if((tobesigned_certificate->cf & 1<<2)!=0){
		public_key_free(&tobesigned_certificate->flags_content.encryption_key);
	}
	if((tobesigned_certificate->cf & 0xf8)!=0){
		if(NULL!=tobesigned_certificate->flags_content.other_cert_content.buf)
			ARRAY_FREE(&tobesigned_certificate->flags_content.other_cert_content);
	}
}
/**
 *YGH 24
 */
static void certificate_free(certificate* certificate){ 
   switch(certificate->version_and_type){
	   case 2:
         switch(certificate->unsigned_certificate.holder_type){
			 case ROOT_CA:
				 signature_free(&certificate->u.signature,certificate->unsigned_certificate.version_and_type.verification_key.algorithm);
				 break;
			  default:
				 signature_free(&certificate->u.signature,certificate->unsigned_certificate.u.no_root_ca.signature_alg);
		 }
		   break;
		case 3:
		 elliptic_curve_point_free(&certificate->u.reconstruction_value);
	    	 break;
		default:
		 if(NULL!=certificate->u.signature_material.buf)
			 ARRAY_FREE(&certificate->u.signature_material);
   }
   tobesigned_certificate_free(&certificate->unsigned_certificate,certificate->version_and_type);
}

/**
 *YGH 25
 */
static void signer_identifier_free(signer_identifier* signer_identifier){
	int i;
	switch(signer_identifier->type){
		case SELF:
			break;
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
			break;
		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			break;
		case CERTIFICATE:
			certificate_free(&signer_identifier->u.certificate);
			break;
		case CERTIFICATE_CHAIN:
			if(NULL != signer_identifier->u.certificates.buf){
				for(i = 0;i<signer_identifier->u.certificates.len;i++){
					certificate_free(signer_identifier->u.certificates.buf + i);
				}
				ARRAY_FREE(&signer_identifier->u.certificates);
			}
			break;
		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			break;
		default:
			if(NULL != signer_identifier->u.id.buf)
				ARRAY_FREE(&signer_identifier->u.id);
	}
}

 /**
 *YGH 26
 */
static void tobesigned_crl_free(tobesigned_crl* tobesigned_crl){
	switch(tobesigned_crl->type){
		case ID_ONLY:
			if(NULL != tobesigned_crl->u.entries.buf)
				ARRAY_FREE(&tobesigned_crl->u.entries);
			break;
		case ID_AND_EXPIRY:
			if(NULL != tobesigned_crl->u.expiring_entries.buf)
				ARRAY_FREE(&tobesigned_crl->u.expiring_entries);
			break;
		default:
			if(NULL != tobesigned_crl->u.other_entries.buf)
				ARRAY_FREE(&tobesigned_crl->u.other_entries);
			break;
	}
}

/**
 *YGH 27
 */
static void crl_free(crl* crl){
	int n = crl->signer.u.certificates.len - 1;
	tobesigned_crl_free(&crl->unsigned_crl);
	
	switch(crl->signer.type){
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
			signature_free(&crl->signature,ECDSA_NISTP224_WITH_SHA224);
			break;
		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			signature_free(&crl->signature,ECDSA_NISTP256_WITH_SHA256);
			break;
		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			signature_free(&crl->signature,crl->signer.u.other_algorithm.algorithm);
			break;
		case CERTIFICATE:
			if(crl->signer.u.certificate.version_and_type == 2)
				signature_free(&crl->signature,
						crl->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
			else if(crl->signer.u.certificate.version_and_type == 3)
				signature_free(&crl->signature,
						crl->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
			break;
		case CERTIFICATE_CHAIN:
			if((crl->signer.u.certificates.buf + n)->version_and_type == 2)
				signature_free(&crl->signature,
					(crl->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
			else if((crl->signer.u.certificates.buf + n)->version_and_type == 3)
				signature_free(&crl->signature,
					(crl->signer.u.certificates.buf + n)->unsigned_certificate.u.no_root_ca.signature_alg);
			break;
		default:
			break;
	}
	signer_identifier_free(&crl->signer);

}

/**
 *YGH 28
 */
static void tobe_encrypted_certificate_request_error_free(tobe_encrypted_certificate_request_error*
				tobe_encrypted_certificate_request_error){

	switch(tobe_encrypted_certificate_request_error->signer.u.certificate.version_and_type){
		case 2:
			signature_free(&tobe_encrypted_certificate_request_error->signature,
					tobe_encrypted_certificate_request_error->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
			break;
		case 3:
			signature_free(&tobe_encrypted_certificate_request_error->signature,
					tobe_encrypted_certificate_request_error->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
			break;
		default:
			break;
	}
	signer_identifier_free(&tobe_encrypted_certificate_request_error->signer);
}

/**
 *YGH 29
 *@version_and_type由证书链中最后一个证书得到
 */
static void tobe_encrypted_certificate_response_free(tobe_encrypted_certificate_response* 
				tobe_encrypted_certificate_response){
	int i;
	int n = tobe_encrypted_certificate_response->certificate_chain.len - 1;

	switch((tobe_encrypted_certificate_response->certificate_chain.buf + n)->version_and_type){
		case 2:
			break;
		case 3:
			if(NULL != tobe_encrypted_certificate_response->u.recon_priv.buf)
				ARRAY_FREE(&tobe_encrypted_certificate_response->u.recon_priv);
			break;
		default:
			if(NULL != tobe_encrypted_certificate_response->u.other_material.buf)
				ARRAY_FREE(&tobe_encrypted_certificate_response->u.other_material);
			break;
	}
	if(NULL != tobe_encrypted_certificate_response->crl_path.buf){
		for(i = 0;i<tobe_encrypted_certificate_response->crl_path.len;i++){
			crl_free(tobe_encrypted_certificate_response->crl_path.buf + i);
		}
		ARRAY_FREE(&tobe_encrypted_certificate_response->crl_path);
	}

	if(NULL != tobe_encrypted_certificate_response->certificate_chain.buf){
		for(i = 0;i<tobe_encrypted_certificate_response->certificate_chain.len;i++){
			certificate_free(tobe_encrypted_certificate_response->certificate_chain.buf + i);
		}
		ARRAY_FREE(&tobe_encrypted_certificate_response->certificate_chain);
	}


}

/**
 *YGH 30
 */
static void tobesigned_certificate_request_free(tobesigned_certificate_request* 
		tobesigned_certificate_request){

	cert_specific_data_free(&tobesigned_certificate_request->type_specific_data,
			tobesigned_certificate_request->holder_type);
	if((tobesigned_certificate_request->cf & 1<<2)!=0){
		public_key_free(&tobesigned_certificate_request->flags_content.encryption_key);
	}
	if((tobesigned_certificate_request->cf & 0xf8)!=0){
		if(NULL != tobesigned_certificate_request->flags_content.other_cert.buf)
			ARRAY_FREE(&tobesigned_certificate_request->flags_content.other_cert);
	}
	public_key_free(&tobesigned_certificate_request->verification_key);
	public_key_free(&tobesigned_certificate_request->response_encryption_key);
}

/**
 *YGH 31
 */
static void certificate_request_free(certificate_request* certificate_request){
	switch(certificate_request->signer.type){
		case SELF:
			signature_free(&certificate_request->signature,
					certificate_request->unsigned_csr.verification_key.algorithm);
			break;
		case CERTIFICATE:
			if(certificate_request->signer.u.certificate.version_and_type == 2)
				signature_free(&certificate_request->signature,
						certificate_request->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
			else if(certificate_request->signer.u.certificate.version_and_type == 3)
				signature_free(&certificate_request->signature,
						certificate_request->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
			break;
		default:
			break;
	}

	signer_identifier_free(&certificate_request->signer);
	tobesigned_certificate_request_free(&certificate_request->unsigned_csr);
}

/**
 *  YGH 32
 */
static void tobesigned_data_free(tobesigned_data* tobesigned_data, content_type type){
	int i;
	switch(type){
		case SIGNED:	
			if(NULL != tobesigned_data->u.type_signed.data.buf)
				ARRAY_FREE(&tobesigned_data->u.type_signed.data);
			break;
		case SIGNED_PARTIAL_PAYLOAD:
			if(NULL != tobesigned_data->u.type_signed_partical.ext_data.buf)
				ARRAY_FREE(&tobesigned_data->u.type_signed_partical.ext_data);
			if(NULL != tobesigned_data->u.type_signed_partical.data.buf)
				ARRAY_FREE(&tobesigned_data->u.type_signed_partical.data);
			break;
		case SIGNED_EXTERNAL_PAYLOAD:
			if(NULL != tobesigned_data->u.type_signed_external.ext_data.buf)
				ARRAY_FREE(&tobesigned_data->u.type_signed_external.ext_data);
			break;
		default:
			if(NULL != tobesigned_data->u.data.buf)
				ARRAY_FREE(&tobesigned_data->u.data);
			break;
	}
	if((tobesigned_data->tf & 1<<3)!=0){
		if(NULL != tobesigned_data->flags_content.extensions.buf){
			for(i = 0;i<tobesigned_data->flags_content.extensions.len;i++){
				tbsdata_extension_free(tobesigned_data->flags_content.extensions.buf + i);
			}
			ARRAY_FREE(&tobesigned_data->flags_content.extensions);
		}
	}
	if((tobesigned_data->tf & 0xf0)!=0){
		if(NULL != tobesigned_data->flags_content.other_data.buf)
			ARRAY_FREE(&tobesigned_data->flags_content.other_data);
	}
}

/**
 *YGH 33
 */
static void signed_data_free(signed_data* signed_data, content_type type){

	int n = signed_data->signer.u.certificates.len - 1;

	switch(signed_data->signer.type){
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
			signature_free(&signed_data->signature,ECDSA_NISTP224_WITH_SHA224);
			break;
		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			signature_free(&signed_data->signature,ECDSA_NISTP256_WITH_SHA256);
			break;
		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			signature_free(&signed_data->signature,signed_data->signer.u.other_algorithm.algorithm);
			break;
		case CERTIFICATE:
			if(signed_data->signer.u.certificate.version_and_type == 2)
				signature_free(&signed_data->signature,
						signed_data->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
			else if(signed_data->signer.u.certificate.version_and_type == 3)
				signature_free(&signed_data->signature,
						signed_data->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
			break;
		case CERTIFICATE_CHAIN:
			if((signed_data->signer.u.certificates.buf + n)->version_and_type == 2)
				signature_free(&signed_data->signature,
						(signed_data->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
			else if((signed_data->signer.u.certificates.buf + n)->version_and_type == 3)
				signature_free(&signed_data->signature,
						(signed_data->signer.u.certificates.buf + n)->unsigned_certificate.u.no_root_ca.signature_alg);
			break;
		default:
			break;
	}
	signer_identifier_free(&signed_data->signer);
	tobesigned_data_free(&signed_data->unsigned_data,type);
}

/**
 *YGH 34
 */
static void tobe_encrypted_free(tobe_encrypted* tobe_encrypted){
	switch(tobe_encrypted->type){
		case UNSECURED:
			if(NULL != tobe_encrypted->u.plain_text.buf)
				ARRAY_FREE(&tobe_encrypted->u.plain_text);
			break;
		case SIGNED:
		case SIGNED_EXTERNAL_PAYLOAD:
		case SIGNED_PARTIAL_PAYLOAD:
			signed_data_free(&tobe_encrypted->u.signed_data,tobe_encrypted->type);
			break;
		case CERTIFICATE_REQUEST:
			certificate_request_free(&tobe_encrypted->u.request);
			break;
		case CERTIFICATE_RESPONSE:
			tobe_encrypted_certificate_response_free(&tobe_encrypted->u.response);
		case ANOYMOUS_CERTIFICATE_RESPONSE:
			break;
		case CERTIFICATE_REQUSET_ERROR:
			tobe_encrypted_certificate_request_error_free(&tobe_encrypted->u.request_error);
			break;
		case CONTENT_TYPE_CRL_REQUEST:
			break;
		case CRL:
			crl_free(&tobe_encrypted->u.crl);
			break;
		case CERTIFACATE_RESPONSE_ACKNOWLEDGMENT:
			break;
		default:
			if(NULL != tobe_encrypted->u.data.buf)
				ARRAY_FREE(&tobe_encrypted->u.data);
	}
}

/**
 *YGH 35
 */
static void aes_ccm_ciphertext_free(aes_ccm_ciphertext* aes_ccm_ciphertext){
	if(NULL != aes_ccm_ciphertext->ccm_ciphertext.buf)
		ARRAY_FREE(&aes_ccm_ciphertext->ccm_ciphertext);
}

/**
 *YGH 36
 */
static void ecies_nist_p256_encrypted_key_free(ecies_nist_p256_encrypted_key* 
					ecies_nist_p256_encrypted_key){

	elliptic_curve_point_free(&ecies_nist_p256_encrypted_key->v);

	if(NULL != ecies_nist_p256_encrypted_key->c.buf)
		ARRAY_FREE(&ecies_nist_p256_encrypted_key->c);
}

/**
 *YGH 37
 */
static void recipient_info_free(recipient_info* recipient_info, pk_algorithm algorithm){
	switch(algorithm){
		case ECIES_NISTP256:
			ecies_nist_p256_encrypted_key_free(&recipient_info->u.enc_key);
			break;
		default:
			if(NULL != recipient_info->u.other_enc_key.buf)
				ARRAY_FREE(&recipient_info->u.other_enc_key);
			break;
	}
}

/**
 *YGH 38
 *@recipient_info_free 本协议仅支持ECIES_NISTP256,其他算法暂不考虑
 */
static void  encrypted_data_free(encrypted_data* encrypted_data){
	int i;
	if(NULL != encrypted_data->recipients.buf){
		for(i = 0;i<encrypted_data->recipients.len;i++){
			recipient_info_free(encrypted_data->recipients.buf + i,ECIES_NISTP256);
		}
		ARRAY_FREE(&encrypted_data->recipients);
	}
	switch(encrypted_data->symm_algorithm){
		case AES_128_CCM:
			aes_ccm_ciphertext_free(&encrypted_data->u.ciphertext);
			break;
		default:
			if(NULL != encrypted_data->u.other_ciphertext.buf)
				ARRAY_FREE(&encrypted_data->u.other_ciphertext);
			break;
	}
}

/**
 *YGH 39
 */
static void tobesigned_wsa_free(tobesigned_wsa* tobesigned_wsa){
	if(NULL != tobesigned_wsa->permission_indices.buf)
		ARRAY_FREE(&tobesigned_wsa->permission_indices);

	if(NULL != tobesigned_wsa->data.buf)
		ARRAY_FREE(&tobesigned_wsa->data);

	if((tobesigned_wsa->tf & 1<<3)!=0){
		if(NULL != tobesigned_wsa->flags_content.extension.buf){
			tbsdata_extension_free(tobesigned_wsa->flags_content.extension.buf);
			ARRAY_FREE(&tobesigned_wsa->flags_content.extension);
		}
	}
	if((tobesigned_wsa->tf & 0xf0)!=0){
		if(NULL != tobesigned_wsa->flags_content.other_data.buf)
			ARRAY_FREE(&tobesigned_wsa->flags_content.other_data);
	}
}

/**
 *YGH 40
 */
static void signed_wsa_free(signed_wsa* signed_wsa){
	int n = signed_wsa->signer.u.certificates.len - 1;
	if((signed_wsa->signer.type == CERTIFICATE_CHAIN) &&
			((signed_wsa->signer.u.certificates.buf + n)->version_and_type == 2)){
		signature_free(&signed_wsa->signature,
				(signed_wsa->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
	}else{
		signature_free(&signed_wsa->signature,ECDSA_NISTP256_WITH_SHA256);
	}
	signer_identifier_free(&signed_wsa->signer);
	tobesigned_wsa_free(&signed_wsa->unsigned_wsa);
}

/**
 *大力 41
 */

void sec_data_free(sec_data* sec_data){
    if(sec_data == NULL)
        return ;
    switch(sec_data->type){
        case UNSECURED:
            ARRAY_FREE(&sec_data->u.data);
            break;
        case SIGNED:
        case SIGNED_EXTERNAL_PAYLOAD:
        case SIGNED_PARTIAL_PAYLOAD:
			signed_data_free(&sec_data->u.signed_data,sec_data->type);
            break;
        case SIGNED_WSA:
            signed_wsa_free(&sec_data->u.signed_wsa);
            break;
        case ENCRYPTED:
            encrypted_data_free(&sec_data->u.encrypted_data);
            break;
        case CONTENT_TYPE_CRL_REQUEST:
            break;
        case CRL:
			crl_free(&sec_data->u.crl);
            break;
        default:
			ARRAY_FREE(&sec_data->u.other_data);
            break;

    }
}



















