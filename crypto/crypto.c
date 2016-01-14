#include "crypto.h"
#include<stddef.h>
#include<stdlib.h>
#include"data/data.h"
#define check_args_string(n) do{\
    if(n == NULL || n->buf != NULL){\
        wave_error_printf("输入参数有问题,请检查 %s %d");\
        return -1;\
    }\
}while(0)

int crypto_ECDSA_224_get_key(string *prikey,string *pubkey_x,string* pubkey_y){
    check_args_string(prikey);
    check_args_string(pubkey_x);
    check_args_string(pubkey_y);
    
    prikey->len = 28;
    pubkey_x->len = 28;
    pubkey_y->len = 28;
    prikey->buf = (u8*)malloc(prikey->len);
    pubkey_x->buf = (u8*)malloc(pubkey_x->len);
    pubkey_y->buf = (u8*)malloc(pubkey_y->len);

    if(prikey->buf == NULL || pubkey_x->buf == NULL ||
            pubkey_y == NULL ){
        wave_malloc_error();
        goto fail;
    }

    if(ECDSA_224_get_key(prikey->buf,&prikey->len,pubkey_x->buf,&pubkey_x->len,pubkey_y->buf,&pubkey_y->len))
        goto fail;
    return 0;
fail:
    if(prikey->buf != NULL)
        string_free(prikey);
    if(pubkey_x->buf != NULL)
        string_free(pubkey_x);
    if(pubkey_y->buf != NULL)
        string_free(pubkey_y);
    return -1;
}
int crypto_ECDSA_224_uncompress_key_2_compress_key(string* pubkey_x,string* pubkey_y,
                                                string* compress_key,enum ecc_public_keytype *type){
    check_args_string(compress_key);
    
    char flag;
    compress_key->len = pubkey_x->len;
    compress_key->buf = (u8*)malloc(compress_key->len);

    if(compress_key->buf == NULL ){
        wave_malloc_error();
        goto fail;
    }
    if(ECDSA_224_uncompress_key_2_compress_key(pubkey_x->buf,pubkey_x->len,pubkey_y->buf,pubkey_y->len,
							compress_key->buf,&compress_key->len,&flag))
        goto fail;
    if(type != NULL)
        *type = flag;
    return 0;
fail:
    if(compress_key->buf != NULL)
        string_free(compress_key);
    return -1;
}
int crypto_ECDSA_224_compress_key_2_uncompress(string *compress_key,enum ecc_public_keytype old_flag,
                                                string* pubkey_x,string* pubkey_y){
    check_args_string(pubkey_x);
    check_args_string(pubkey_y);
    
    pubkey_x->len = compress_key->len;
    pubkey_y->len = compress_key->len;
    
    pubkey_x->buf = (u8*)malloc(pubkey_x->len);
    pubkey_y->buf = (u8*)malloc(pubkey_y->len);
        
    if(pubkey_x->buf == NULL || pubkey_y->buf ==NULL){
        wave_malloc_error();
        goto fail;
    }
    if(ECDSA_224_compress_key_2_uncompress(compress_key->buf,compress_key->len,(char)old_flag,
                pubkey_x->buf,&pubkey_x->len,pubkey_y->buf,&pubkey_y->len))
        goto fail;
    return 0;
fail:
    if(pubkey_x->buf != NULL)
        string_free(pubkey_x);
    if(pubkey_y->buf != NULL)
        string_free(pubkey_y);
    return -1;
}
int crypto_ECDSA_224_sign_message(string* prikey,string *mess, string* r,string* s){
    check_args_string(r);
    check_args_string(s);

    r->len = 28;
    s->len = 28; 
    r->buf = (u8*)malloc(r->len);
    s->buf = (u8*)malloc(s->len);
    if(r->buf == NULL || s->buf == NULL){
        wave_malloc_error();
        goto fail;
    }

    if(ECDSA_224_sign_message(prikey->buf,prikey->len,mess->buf,mess->len,r->buf,&r->len,s->buf,&s->len))
        goto fail;
    return 0;
fail:
    if(r->buf != NULL){
        string_free(r);
    }
    if(s->buf != NULL)
        string_free(s);
    return -1;
}

bool crypto_ECDSA_224_verify_message(string *pubkey_x,string* pubkey_y,string* r,string* s,string *mess){
    if( ECDSA_224_verify_message(pubkey_x->buf,pubkey_x->len,pubkey_y->buf,pubkey_y->len,r->buf,r->len,s->buf,s->len,
                mess->buf,mess->len) == 0)
        return true;
    return false;
}

int crypto_ECDSA_224_FAST_sign_message(string* prikey,string* mess,  string* signed_r_x,string* signed_r_y,string* signed_s){
        check_args_string(signed_r_x);
        check_args_string(signed_r_y);
        check_args_string(signed_s);

        signed_r_x->len = 28;
        signed_r_y->len = 28;
        signed_s->len = 28;

        signed_r_x->buf = (u8*)malloc(signed_r_x->len);
        signed_r_y->buf = (u8*)malloc(signed_r_y->len);
        signed_s->buf = (u8*)malloc(signed_s->len);

        if(signed_r_x->buf == NULL || 
                signed_r_y->buf == NULL || signed_s->buf == NULL){
            wave_malloc_error();
            goto fail;
        }

        if(ECDSA_224_FAST_sign_message(prikey->buf,prikey->len,mess->buf,mess->len,signed_r_x->buf,&signed_r_x->len,
                        signed_r_y->buf,&signed_r_y->len,signed_s->buf,&signed_s->len))
            goto fail;
        return 0;
fail:
        if(signed_r_x->buf != NULL)
            string_free(signed_r_x);
        if(signed_r_y->buf != NULL)
            string_free(signed_r_y);
        if(signed_s->buf != NULL)
            string_free(signed_s);
        return -1;
}
bool crypto_ECDSA_224_FAST_verify_message(string* pubkey_x,string* pubkey_y,string* mess,
				string* signed_r_x,string* signed_r_y,string* signed_s){
    if( ECDSA_224_FAST_verify_message(pubkey_x->buf,pubkey_x->len,pubkey_y->buf,pubkey_y->len,
				mess->buf,mess->len,signed_r_x->buf,signed_r_x->len,
                signed_r_y->buf,signed_r_y->len,signed_s->buf,signed_s->len) == 0)
        return true;
    return false;
}




int crypto_ECDSA_256_get_key(string *prikey,string *pubkey_x,string* pubkey_y){
    check_args_string(prikey);
    check_args_string(pubkey_x);
    check_args_string(pubkey_y);
       
    prikey->len = 32;
    pubkey_x->len = 32;
    pubkey_y->len = 32;
    prikey->buf = (u8*)malloc(prikey->len);
    pubkey_x->buf = (u8*)malloc(pubkey_x->len);
    pubkey_y->buf = (u8*)malloc(pubkey_y->len);

    if(prikey->buf == NULL || pubkey_x->buf == NULL ||
            pubkey_y == NULL ){
        wave_malloc_error();
        goto fail;
    }

    if(ECDSA_256_get_key(prikey->buf,&prikey->len,pubkey_x->buf,&pubkey_x->len,pubkey_y->buf,&pubkey_y->len))
        goto fail;
    return 0;
fail:
    if(prikey->buf != NULL)
        string_free(prikey);
    if(pubkey_x->buf != NULL)
        string_free(pubkey_x);
    if(pubkey_y->buf != NULL)
        string_free(pubkey_y);
    return -1;
}
int crypto_ECDSA_256_uncompress_key_2_compress_key(string* pubkey_x,string* pubkey_y,
                                                string* compress_key,enum ecc_public_keytype *type){
    check_args_string(compress_key);
    
    char flag;
    compress_key->len = pubkey_x->len;
    compress_key->buf = (u8*)malloc(compress_key->len);

    if(compress_key->buf == NULL ){
        wave_malloc_error();
        goto fail;
    }
    if(ECDSA_256_uncompress_key_2_compress_key(pubkey_x->buf,pubkey_x->len,pubkey_y->buf,pubkey_y->len,
				compress_key->buf,&compress_key->len,&flag))
        goto fail;
    if(type != NULL){
        *type = flag;
    }
    return 0;
fail:
    if(compress_key->buf != NULL)
        string_free(compress_key);
    return -1;
}
int crypto_ECDSA_256_compress_key_2_uncompress(string *compress_key,enum ecc_public_keytype old_flag,
                                                string* pubkey_x,string* pubkey_y){
    check_args_string(pubkey_x);
    check_args_string(pubkey_y);
    
    pubkey_x->len = compress_key->len;
    pubkey_y->len = compress_key->len;
    
    pubkey_x->buf = (u8*)malloc(pubkey_x->len);
    pubkey_y->buf = (u8*)malloc(pubkey_y->len);
        
    if(pubkey_x->buf == NULL || pubkey_y->buf ==NULL){
        wave_malloc_error();
        goto fail;
    }
    if(ECDSA_256_compress_key_2_uncompress(compress_key->buf,compress_key->len,(char)old_flag,
                pubkey_x->buf,&pubkey_x->len,pubkey_y->buf,&pubkey_y->len))
        goto fail;
	return 0;
fail:
    if(pubkey_x->buf != NULL)
        string_free(pubkey_x);
    if(pubkey_y->buf != NULL)
        string_free(pubkey_y);
    return -1;
}
int crypto_ECDSA_256_sign_message(string* prikey,string *mess, string* r,string* s){
    check_args_string(r);
    check_args_string(s);

    r->len = 32;
    s->len = 32; 
    r->buf = (u8*)malloc(r->len);
    s->buf = (u8*)malloc(s->len);
    if(r->buf == NULL || s->buf == NULL){
        wave_malloc_error();
        goto fail;
    }

    if(ECDSA_256_sign_message(prikey->buf,prikey->len,mess->buf,mess->len,r->buf,&r->len,s->buf,&s->len))
        goto fail;
    return 0;
fail:
    if(r->buf != NULL){
        string_free(r);
    }
    if(s->buf != NULL)
        string_free(s);
    return -1;
}

bool crypto_ECDSA_256_verify_message(string *pubkey_x,string* pubkey_y,string* r,string* s,string *mess){
    if( ECDSA_256_verify_message(pubkey_x->buf,pubkey_x->len,pubkey_y->buf,pubkey_y->len,r->buf,r->len,s->buf,s->len,
                mess->buf,mess->len) == 0)
        return true;
    return false;
}

int crypto_ECDSA_256_FAST_sign_message(string* prikey,string* mess,  string* signed_r_x,string* signed_r_y,string* signed_s){
        check_args_string(signed_r_x);
        check_args_string(signed_r_y);
        check_args_string(signed_s);

        signed_r_x->len = 32;
        signed_r_y->len = 32;
        signed_s->len = 32;

        signed_r_x->buf = (u8*)malloc(signed_r_x->len);
        signed_r_y->buf = (u8*)malloc(signed_r_y->len);
        signed_s->buf = (u8*)malloc(signed_s->len);

        if(signed_r_x->buf == NULL || 
                signed_r_y->buf == NULL || signed_s->buf == NULL){
            wave_malloc_error();
            goto fail;
        }

        if(ECDSA_256_FAST_sign_message(prikey->buf,prikey->len,mess->buf,mess->len,signed_r_x->buf,&signed_r_x->len,
                        signed_r_y->buf,&signed_r_y->len,signed_s->buf,&signed_s->len))
            goto fail;
        return 0;
fail:
        if(signed_r_x->buf != NULL)
            string_free(signed_r_x);
        if(signed_r_y->buf != NULL)
            string_free(signed_r_y);
        if(signed_s->buf != NULL)
            string_free(signed_s);
        return -1;
}
bool crypto_ECDSA_256_FAST_verify_message(string* pubkey_x,string* pubkey_y,string* mess,
					string* signed_r_x,string* signed_r_y,string* signed_s){
    if( ECDSA_256_FAST_verify_message(pubkey_x->buf,pubkey_x->len,pubkey_y->buf,pubkey_y->len,mess->buf,mess->len,signed_r_x->buf,signed_r_x->len,
                    signed_r_y->buf,signed_r_y->len,signed_s->buf,signed_s->len) == 0)
        return true;
    return false;
}

int crypto_ECIES_get_key(string *prikey,string *pubkey_x,string* pubkey_y){
    check_args_string(prikey);
    check_args_string(pubkey_x);
    check_args_string(pubkey_y);
       
    prikey->len = 32;
    pubkey_x->len = 32;
    pubkey_y->len = 32;
    prikey->buf = (u8*)malloc(prikey->len);
    pubkey_x->buf = (u8*)malloc(pubkey_x->len);
    pubkey_y->buf = (u8*)malloc(pubkey_y->len);

    if(prikey->buf == NULL || pubkey_x->buf == NULL ||
            pubkey_y == NULL ){
        wave_malloc_error();
        goto fail;
    }

    if(ECIES_get_key(prikey->buf,&prikey->len,pubkey_x->buf,&pubkey_x->len,pubkey_y->buf,&pubkey_y->len))
        goto fail;
    return 0;
fail:
    if(prikey->buf != NULL)
        string_free(prikey);
    if(pubkey_x->buf != NULL)
        string_free(pubkey_x);
    if(pubkey_y->buf != NULL)
        string_free(pubkey_y);
    return -1;
}

int crypto_ECIES_uncompress_key_2_compress_key(string* pubkey_x,string* pubkey_y,
                                                string* compress_key,enum ecc_public_keytype *type){
    check_args_string(compress_key);
    
    char flag;
    compress_key->len = pubkey_x->len;
    compress_key->buf = (u8*)malloc(compress_key->len);

    if(compress_key->buf == NULL ){
        wave_malloc_error();
        goto fail;
    }
    if(ECIES_uncompress_key_2_compress_key(pubkey_x->buf,pubkey_x->len,pubkey_y->buf,pubkey_y->len,compress_key->buf,&compress_key->len,&flag))
        goto fail;
    if(type != NULL)
        *type = flag;
    return 0;
fail:
    if(compress_key->buf != NULL)
        string_free(compress_key);
    return -1;
}

int crypto_ECIES_compress_key_2_uncompress(string *compress_key,enum ecc_public_keytype old_flag,
                                                string* pubkey_x,string* pubkey_y){
    check_args_string(pubkey_x);
    check_args_string(pubkey_y);
    
    pubkey_x->len = compress_key->len;
    pubkey_y->len = compress_key->len;
    
    pubkey_x->buf = (u8*)malloc(pubkey_x->len);
    pubkey_y->buf = (u8*)malloc(pubkey_y->len);
        
    if(pubkey_x->buf == NULL || pubkey_y->buf ==NULL){
        wave_malloc_error();
        goto fail;
    }
    if(ECIES_compress_key_2_uncompress(compress_key->buf,compress_key->len,(char)old_flag,
                pubkey_x->buf,&pubkey_x->len,pubkey_y->buf,&pubkey_y->len))
        goto fail;
	return 0;
fail:
    if(pubkey_x->buf != NULL)
        string_free(pubkey_x);
    if(pubkey_y->buf != NULL)
        string_free(pubkey_y);
    return -1;
}
int crypto_ECIES_encrypto_message(string* mess,string* pubkey_x,string* pubkey_y,
                            string* ephe_pubkey_x,string* ephe_pubkey_y,string* encrypted_mess,string* tag){
    check_args_string(ephe_pubkey_x);
    check_args_string(ephe_pubkey_y);
    check_args_string(encrypted_mess);
	check_args_string(tag);

    ephe_pubkey_x->len = 32;
    ephe_pubkey_y->len = 32;
    encrypted_mess->len = mess->len;
    tag->len = 20;

    ephe_pubkey_x->buf = (u8*)malloc(ephe_pubkey_x->len);
    ephe_pubkey_y->buf = (u8*)malloc(ephe_pubkey_y->len);
    encrypted_mess->buf = (u8*)malloc(encrypted_mess->len);
    tag->buf = (u8*)malloc(tag->len);

    if(ephe_pubkey_x->buf == NULL || 
            ephe_pubkey_y->buf == NULL ||
            encrypted_mess->buf == NULL||
            tag->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    
    if( ECIES_encrypto_message(mess->buf,mess->len,pubkey_x->buf,pubkey_x->len,pubkey_y->buf,pubkey_y->len,
                        ephe_pubkey_x->buf,&ephe_pubkey_x->len,ephe_pubkey_y->buf,&ephe_pubkey_y->len,encrypted_mess->buf,&encrypted_mess->len,
                        tag->buf,&tag->len)){
        goto fail;
    }
    return 0;
fail:
    if(ephe_pubkey_x->buf != NULL)
        string_free(ephe_pubkey_x);
    if(ephe_pubkey_y->buf != NULL)
        string_free(ephe_pubkey_y);
    if(encrypted_mess->buf != NULL)
        string_free(encrypted_mess);
    if(tag->buf != NULL)
        string_free(tag);
    return -1;
}
int crypto_ECIES_decrypto_message(string* encrypted_mess,string* ephe_pubkey_x,string* ephe_pubkey_y,string* tag,string* prikey,
                                string* mess){
    check_args_string(mess);

    mess->len = encrypted_mess->len;

    mess->buf = (u8*)malloc(mess->len);
    if(mess->buf == NULL){
        wave_malloc_error();
        goto fail;
    }

    if( ECIES_decrypto_message(encrypted_mess->buf,encrypted_mess->len,ephe_pubkey_x->buf,ephe_pubkey_x->len,
						ephe_pubkey_y->buf,ephe_pubkey_y->len,
                        tag->buf,tag->len,prikey->buf,prikey->len, mess->buf,&mess->len)){
        goto fail;
    }
    return 0;
fail:
    if(mess->buf != NULL)
        string_free(mess);
    return -1;
}

int crypto_AES_128_CCM_Get_Key_and_Nonce(string* sym_key,string* nonce){
    check_args_string(sym_key);
    check_args_string(nonce);

    sym_key->len = 128/8;
    nonce->len = 12;

    sym_key->buf = (u8*)malloc(sym_key->len);
    nonce->buf = (u8*)malloc(nonce->len);

    if(sym_key->buf == NULL ||
            nonce->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    
    if(AES_128_CCM_Get_Key_and_Nonce(sym_key->buf,&sym_key->len,nonce->buf,&nonce->len))
        goto fail;
    return 0;
fail:
    if(sym_key->buf != NULL)
        string_free(sym_key);
    if(nonce->buf != NULL)
        string_free(nonce);
    return -1;
}

int crypto_AES_128_CCM_encrypto_message(string *plaintext,string* sym_key,string* nonce, string* ciphertext){
    check_args_string(ciphertext);
    
    ciphertext->len = plaintext->len + 16;
    ciphertext->buf = (u8*)malloc(ciphertext->len);
    if(ciphertext->buf == NULL){
	wave_malloc_error();
	goto fail;
    }

    if(AES_128_CCM_encrypto_message(plaintext->buf,plaintext->len,sym_key->buf,sym_key->len,nonce->buf,nonce->len,
			ciphertext->buf,&ciphertext->len))
	goto fail;
    return 0;
fail:
    if(ciphertext->buf != NULL)
	string_free(ciphertext);
    return -1;
}

int crypto_AES_128_CCM_decrypto_message(string *ciphertext,string* sym_key,string* nonce,string *plaintext){
    check_args_string(plaintext);

    plaintext->len = ciphertext->len;
    plaintext->buf = (u8*)malloc(plaintext->len);

    if(plaintext->buf == NULL){
	wave_malloc_error();
	goto fail;	
    }
    if( AES_128_CCM_decrypto_message(ciphertext->buf,ciphertext->len,sym_key->buf,sym_key->len,nonce->buf,nonce->len,
				plaintext->buf,&plaintext->len))
	goto fail;
    return -1;
fail:
    if(plaintext->buf != NULL)
	free(plaintext);
    return -1;
}
int crypto_HASH_256(string *mess,string* digest){
    check_args_string(digest);

    digest->len = 32;
    digest->buf = (u8*)malloc(digest->len);
    if(digest->buf == NULL){
	wave_malloc_error();
	goto fail;	
    }
    if(sha_256(mess->buf,mess->len,digest->buf,&digest->len))
	goto fail;
    return 0;
fail:
    if(digest->buf != NULL)
	string_free(digest);
    return -1;
}
int crypto_HASH_224(string *mess,string* digest){
    check_args_string(digest);

    digest->len = 28;
    digest->buf = (u8*)malloc(digest->len);
    if(digest->buf == NULL){
	wave_malloc_error();
	goto fail;	
    }
    if(sha_224(mess->buf,mess->len,digest->buf,&digest->len))
	goto fail;
    return 0;
fail:
    if(digest->buf != NULL)
	string_free(digest);
    return -1;
}

int crypto_cert_pk_extraction_SHA224(string* ca_pub_x,string* ca_pub_y,string* recon_x,string* recon_y,string* digest,
				string* pubkey_x,string* pubkey_y){
    check_args_string(pubkey_x);
    check_args_string(pubkey_y);

    pubkey_x->len = 28;
    pubkey_y->len = 28;
    pubkey_x->buf = (u8*)malloc(pubkey_x->len);
    pubkey_y->buf = (u8*)malloc(pubkey_y->len);

    if(pubkey_x->buf == NULL || pubkey_y->buf == NULL){
	wave_malloc_error();
	goto fail;
    }
    if( cert_pk_extraction_SHA224(ca_pub_x->buf,ca_pub_x->len,ca_pub_y->buf,ca_pub_y->len,recon_x->buf,recon_x->len,recon_y->buf,
			recon_y->len,digest->buf,digest->len,pubkey_x->buf,&pubkey_x->len,pubkey_y->buf,&pubkey_y->len))
	goto fail;
    return 0;
fail:
    if(pubkey_x->buf != NULL)
	string_free(pubkey_x);
    if(pubkey_y->buf != NULL)
	string_free(pubkey_y);
    return -1;
}

int crypto_cert_reception_SHA224(string* old_prikey,
			                    string* a,string *b,string* prikey){
    check_args_string(prikey);

    prikey->len = 28;
    prikey->buf = (u8*)malloc(prikey->len);
    if( prikey->buf == NULL){
	    wave_malloc_error();
	    goto fail;
    }
    if( cert_reception_SHA224(old_prikey->buf,old_prikey->len,a->buf,a->len,b->buf,b->len,
			                prikey->buf,&prikey->len))
	    goto fail;
    return 0;
fail:
    if(prikey->buf != NULL)
	    string_free(prikey);
    return -1;
}

int crypto_cert_pk_extraction_SHA256(string* ca_pub_x,string* ca_pub_y,string* recon_x,string* recon_y,string* digest,
				string* pubkey_x,string* pubkey_y){
    check_args_string(pubkey_x);
    check_args_string(pubkey_y);

    pubkey_x->len = 32;
    pubkey_y->len = 32;
    pubkey_x->buf = (u8*)malloc(pubkey_x->len);
    pubkey_y->buf = (u8*)malloc(pubkey_y->len);

    if(pubkey_x->buf == NULL || pubkey_y->buf == NULL){
	wave_malloc_error();
	goto fail;
    }
    if( cert_pk_extraction_SHA256(ca_pub_x->buf,ca_pub_x->len,ca_pub_y->buf,ca_pub_y->len,recon_x->buf,recon_x->len,recon_y->buf,
			recon_y->len,digest->buf,digest->len,pubkey_x->buf,&pubkey_x->len,pubkey_y->buf,&pubkey_y->len))
	goto fail;
    return 0;
fail:
    if(pubkey_x->buf != NULL)
	string_free(pubkey_x);
    if(pubkey_y->buf != NULL)
	string_free(pubkey_y);
    return -1;
}

int crypto_cert_reception_SHA256(string* old_prikey,string* a,string *b,string* prikey){
    check_args_string(prikey);

    prikey->len = 32;
    prikey->buf = (u8*)malloc(prikey->len);
    if(prikey->buf == NULL){
	    wave_malloc_error();
	    goto fail;
    }
    if( cert_reception_SHA256(old_prikey->buf,old_prikey->len,a->buf,a->len,b->buf,b->len,prikey->buf,&prikey->len))
	    goto fail;
    return 0;
fail:
    if(prikey->buf != NULL)
	    string_free(prikey);
    return -1;
}

