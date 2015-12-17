/**
 * File Name: data_printf.c
 * 
 * Description: 打印证书
 */

#include"utils/debug.h"
#include"data_handle.h"

#define N 4 //缩进空格数
#define PRINTF32(N) wave_printf(MSG_INFO,"%x %x %x %x\n",*N,*(N+1),*(N+2),*(N+3))

static void space_print(int n){
    int i;
    for(i = 0;i < n;i++)
        printf(" ");
}

void two_d_location_printf(two_d_location* two_d_location,int n){
    char* buf;

    space_print(n);
    wave_printf(MSG_INFO,"latitude: ");
    buf = (char*)&two_d_location->latitude;
    PRINTF32(buf);

    space_print(n);
    wave_printf(MSG_INFO,"longitude: ");
    buf = (char*)&two_d_location->longitude;
    PRINTF32(buf);
}

void rectangular_region_printf(rectangular_region* rectangular_region,int n){
    space_print(n);
    wave_printf(MSG_INFO,"north_west:\n");
    two_d_location_printf(&rectangular_region->north_west,n+N);

    space_print(n);
    wave_printf(MSG_INFO,"south_east:\n");
    two_d_location_printf(&rectangular_region->south_east,n+N);
}

void circular_region_printf(circular_region* circular_region,int n){
    space_print(n);
    wave_printf(MSG_INFO,"center:\n");
    two_d_location_printf(&circular_region->center,n+N);

    space_print(n);
    wave_printf(MSG_INFO,"radius: %x %x\n",*((char*)&circular_region->radius),
                                            *((char*)&circular_region->radius + 1));
}

void geographic_region_printf(geographic_region* geographic_region,int n){
    int i;
    
    space_print(n);
    wave_printf(MSG_INFO,"region_type: %x\n",geographic_region->region_type);

    switch(geographic_region->region_type){
        case FROM_ISSUER:
            break;
        case CIRCLE:
            space_print(n);
            wave_printf(MSG_INFO,"circular_region:\n");
            circular_region_printf(&geographic_region->u.circular_region,n+N);
            break;
        case RECTANGLE:
            for(i=0;i<geographic_region->u.rectangular_region.len;i++){
                space_print(n);
                wave_printf(MSG_INFO,"rectangular_region %d:\n",i+1);
                rectangular_region_printf(geographic_region->u.rectangular_region.buf + i,n+N);
            }
            break;
        case POLYGON:
            for(i=0;i<geographic_region->u.polygonal_region.len;i++){
                space_print(n);
                wave_printf(MSG_INFO,"polygonal_region %d:\n",i+1);
                two_d_location_printf(geographic_region->u.polygonal_region.buf + i,n+N);
            }
            break;
        case NONE:
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"other_region:");
            for(i=0;i<geographic_region->u.other_region.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(geographic_region->u.other_region.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}

void psid_priority_printf(psid_priority* psid_priority,int n){
    char* buf = (char*)&psid_priority->psid;
    space_print(n);
    wave_printf(MSG_INFO,"psid: ");
    PRINTF32(buf);

    space_print(n);
    wave_printf(MSG_INFO,"max_priority: %x\n",psid_priority->max_priority);
}

void psid_priority_array_printf(psid_priority_array* psid_pa,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"type: %x\n",psid_pa->type);

    switch(psid_pa->type){
        case ARRAY_TYPE_SPECIFIED:
            for(i=0;i<psid_pa->u.permissions_list.len;i++){
                space_print(n);
                wave_printf(MSG_INFO,"permissions_list %d:\n:",i+1);
                psid_priority_printf(psid_pa->u.permissions_list.buf + i,n+N);
            }
            break;
        case ARRAY_TYPE_FROM_ISSUER:
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"other_permissions:");
            for(i=0;i<psid_pa->u.other_permissions.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(psid_pa->u.other_permissions.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}

void psid_array_printf(psid_array* psid_array,int n){
    int i;
    
    space_print(n);
    wave_printf(MSG_INFO,"type: %x\n",psid_array->type);

    switch(psid_array->type){
        case ARRAY_TYPE_SPECIFIED:
            space_print(n);
            wave_printf(MSG_INFO,"permissions_list:\n");
            for(i=0;i<psid_array->u.permissions_list.len;i++){
                space_print(n+N);
                PRINTF32((char*)(psid_array->u.permissions_list.buf + i));
            }
            break;
        case ARRAY_TYPE_FROM_ISSUER:
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"other_permissions: ");
            for(i=0;i<psid_array->u.other_permissions.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(psid_array->u.other_permissions.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}
void psid_ssp_printf(psid_ssp* psid_ssp,int n){
    int i;
    char* buf = (char*)&psid_ssp->psid;

    space_print(n);
    wave_printf(MSG_INFO,"psid: ");
    PRINTF32(buf);

    space_print(n);
    wave_printf(MSG_INFO,"service_specific_permissions:");
    for(i=0;i<psid_ssp->service_specific_permissions.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(psid_ssp->service_specific_permissions.buf + i));
    }
    wave_printf(MSG_INFO,"\n");
}

void psid_ssp_array_printf(psid_ssp_array* psid_ssp_array,int n){
    int i;
    
    space_print(n);
    wave_printf(MSG_INFO,"type: %x\n",psid_ssp_array->type);

    switch(psid_ssp_array->type){
        case ARRAY_TYPE_SPECIFIED:
            for(i=0;i<psid_ssp_array->u.permissions_list.len;i++){
                space_print(n);
                wave_printf(MSG_INFO,"permissions_list %d:\n",i+1);
                psid_ssp_printf(psid_ssp_array->u.permissions_list.buf + i,n+N);
            }
            break;
        case ARRAY_TYPE_FROM_ISSUER:
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"other_permissions:");
            for(i=0;i<psid_ssp_array->u.other_permissions.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(psid_ssp_array->u.other_permissions.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}

void psid_priority_ssp_printf(psid_priority_ssp* psid_ps,int n){
    int i;
    char* buf = (char*)&psid_ps->psid;
    
    space_print(n);
    wave_printf(MSG_INFO,"psid: ");
    PRINTF32(buf);

    space_print(n);
    wave_printf(MSG_INFO,"max_priority: %x\n",psid_ps->max_priority);

    space_print(n);
    wave_printf(MSG_INFO,"service_specific_permissions:");
    for(i=0;i<psid_ps->service_specific_permissions.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(psid_ps->service_specific_permissions.buf + i));
    }
    wave_printf(MSG_INFO,"\n");
}

void psid_priority_ssp_array_printf(psid_priority_ssp_array* psid_psa,int n){
    int i;
    
    space_print(n);
    wave_printf(MSG_INFO,"type: %x\n",psid_psa->type);

    switch(psid_psa->type){
        case ARRAY_TYPE_SPECIFIED:
            for(i=0;i<psid_psa->u.permissions_list.len;i++){
                space_print(n);
                wave_printf(MSG_INFO,"permissions_list %d:\n",i+1);
                psid_priority_ssp_printf(psid_psa->u.permissions_list.buf + i,n+N);
            }
            break;
        case ARRAY_TYPE_FROM_ISSUER:
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"other_permissions:");
            for(i=0;i<psid_psa->u.other_permissions.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(psid_psa->u.other_permissions.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}

void root_ca_scope_printf(root_ca_scope* root_ca_scope,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"name:");
    for(i=0;i<root_ca_scope->name.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(root_ca_scope->name.buf + i));
    }
    wave_printf(MSG_INFO,"\n");

    char* buf = (char*)(&root_ca_scope->permitted_holder_types);
    space_print(n);
    if(root_ca_scope->permitted_holder_types < 1<<7){
        wave_printf(MSG_INFO,"permitted_holder_types: %x\n",*buf);
    }
    else if(root_ca_scope->permitted_holder_types < 1<<14){
        wave_printf(MSG_INFO,"permitted_holder_types: %x %x\n",*buf,*(buf+1));
    }

    if((root_ca_scope->permitted_holder_types & 1<<0)!=0 ||
        (root_ca_scope->permitted_holder_types & 1<<1)!=0 ||
        (root_ca_scope->permitted_holder_types & 1<<2)!=0 ||
        (root_ca_scope->permitted_holder_types & 1<<3)!=0 ||
        (root_ca_scope->permitted_holder_types & 1<<6)!= 0){
        space_print(n);
        wave_printf(MSG_INFO,"secure_data_permissions:\n");
        psid_array_printf(&root_ca_scope->flags_content.secure_data_permissions,n+N);
    }

    if((root_ca_scope->permitted_holder_types & 1<<4)!=0 ||
        (root_ca_scope->permitted_holder_types & 1<<5)!=0 ||
        ((root_ca_scope->permitted_holder_types > 1<<6) && (root_ca_scope->permitted_holder_types & 1<<7)!=0)){
        space_print(n);
        wave_printf(MSG_INFO,"wsa_permissions:\n");
        psid_priority_array_printf(&root_ca_scope->flags_content.wsa_permissions,n+N);
    }

    if((root_ca_scope->permitted_holder_types > 1<<6) && (root_ca_scope->permitted_holder_types & 1<<8)!=0){
        space_print(n);
        wave_printf(MSG_INFO,"other_permissions:");
        for(i=0;i<root_ca_scope->flags_content.other_permissions.len;i++){
            if(i%16 == 0){
                wave_printf(MSG_INFO,"\n");
                space_print(n+N);
            }
            wave_printf(MSG_INFO,"%x ",*(root_ca_scope->flags_content.other_permissions.buf + i));
        }
        wave_printf(MSG_INFO,"\n");
    }

    space_print(n);
    wave_printf(MSG_INFO,"region:\n");
    geographic_region_printf(&root_ca_scope->region,n+N);
}

void sec_data_exch_ca_scope_printf(sec_data_exch_ca_scope* sec_decs,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"name:");
    for(i=0;i<sec_decs->name.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(sec_decs->name.buf + i));
    }
    wave_printf(MSG_INFO,"\n");
   
    char* buf = (char*)(&sec_decs->permitted_holder_types);
    space_print(n);
    if(sec_decs->permitted_holder_types < 1<<7){
        wave_printf(MSG_INFO,"permitted_holder_types: %x\n",*buf);
    }
    else if(sec_decs->permitted_holder_types < 1<<14){
        wave_printf(MSG_INFO,"permitted_holder_types: %x %x\n",*buf,*(buf+1));
    }

    space_print(n);
    wave_printf(MSG_INFO,"permissions:\n");
    psid_array_printf(&sec_decs->permissions,n+N);

    space_print(n);
    wave_printf(MSG_INFO,"region:\n");
    geographic_region_printf(&sec_decs->region,n+N);
}

void wsa_ca_scope_printf(wsa_ca_scope* wsa_cs,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"name:");
    for(i=0;i<wsa_cs->name.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(wsa_cs->name.buf + i));
    }
    wave_printf(MSG_INFO,"\n");

    space_print(n);
    wave_printf(MSG_INFO,"permissions:\n");
    psid_priority_array_printf(&wsa_cs->permissions,n+N);

    space_print(n);
    wave_printf(MSG_INFO,"region:\n");
    geographic_region_printf(&wsa_cs->region,n+N);
}

void identified_not_localized_scope_printf(identified_not_localized_scope* id_nls,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"name:");
    for(i=0;i<id_nls->name.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(id_nls->name.buf + i));
    }
    wave_printf(MSG_INFO,"\n");

    space_print(n);
    wave_printf(MSG_INFO,"permissions:\n");
    psid_ssp_array_printf(&id_nls->permissions,n+N);
}

void identified_scope_printf(identified_scope* identified_scope,int n){
    int i;
    
    space_print(n);
    wave_printf(MSG_INFO,"name:");
    for(i=0;i<identified_scope->name.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(identified_scope->name.buf + i));
    }
    wave_printf(MSG_INFO,"\n");

    space_print(n);
    wave_printf(MSG_INFO,"permissions:\n");
    psid_ssp_array_printf(&identified_scope->permissions,n+N);

    space_print(n);
    wave_printf(MSG_INFO,"region:\n");
    geographic_region_printf(&identified_scope->region,n+N);
}

void anonymous_scope_printf(anonymous_scope* anonymous_scope,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"additionla_data:");
    for(i=0;i<anonymous_scope->additionla_data.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(anonymous_scope->additionla_data.buf + i));
    }
    wave_printf(MSG_INFO,"\n");

    space_print(n);
    wave_printf(MSG_INFO,"permissions:\n");
    psid_ssp_array_printf(&anonymous_scope->permissions,n+N);

    space_print(n);
    wave_printf(MSG_INFO,"region:\n");
    geographic_region_printf(&anonymous_scope->region,n+N);
}

void wsa_scope_printf(wsa_scope* wsa_scope,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"name:");
    for(i=0;i<wsa_scope->name.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(wsa_scope->name.buf + i));
    }
    wave_printf(MSG_INFO,"\n");

    space_print(n);
    wave_printf(MSG_INFO,"permissions:\n");
    psid_priority_ssp_array_printf(&wsa_scope->permissions,n+N);

    space_print(n);
    wave_printf(MSG_INFO,"region:\n");
    geographic_region_printf(&wsa_scope->region,n+N);
}

void cert_specific_data_printf(cert_specific_data* cert_sd,int n,holder_type holder_type){
    int i;

    switch(holder_type){
        case ROOT_CA:
            space_print(n);
            wave_printf(MSG_INFO,"root_ca_scope:\n");
            root_ca_scope_printf(&cert_sd->u.root_ca_scope,n+N);
            break;
        case SDE_CA:
        case SDE_ENROLMENT:
            space_print(n);
            wave_printf(MSG_INFO,"sde_ca_scope:\n");
            sec_data_exch_ca_scope_printf(&cert_sd->u.sde_ca_scope,n+N);
            break;
        case WSA_CA:
        case WSA_ENROLMENT:
            space_print(n);
            wave_printf(MSG_INFO,"wsa_ca_scope:\n");
            wsa_ca_scope_printf(&cert_sd->u.wsa_ca_scope,n+N);
            break;
        case CRL_SIGNER:
            space_print(n);
            wave_printf(MSG_INFO,"responsible_series:");
            for(i=0;i<cert_sd->u.responsible_series.len*4;i++){
                if(i%4 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(cert_sd->u.responsible_series.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
            break;
        case SDE_IDENTIFIED_NOT_LOCALIZED:
            space_print(n);
            wave_printf(MSG_INFO,"id_non_loc_scope:\n");
            identified_not_localized_scope_printf(&cert_sd->u.id_non_loc_scope,n+N);
            break;
        case SDE_IDENTIFIED_LOCALIZED:
            space_print(n);
            wave_printf(MSG_INFO,"id_scope:\n");
            identified_scope_printf(&cert_sd->u.id_scope,n+N);
            break;
        case SDE_ANONYMOUS:
            space_print(n);
            wave_printf(MSG_INFO,"anonymous_scope:\n");
            anonymous_scope_printf(&cert_sd->u.anonymous_scope,n+N);
            break;
        case WSA:
            space_print(n);
            wave_printf(MSG_INFO,"wsa_scope:\n");
            wsa_scope_printf(&cert_sd->u.wsa_scope,n+N);
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"other_scope:");
            for(i=0;i<cert_sd->u.other_scope.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(cert_sd->u.other_scope.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}

void public_key_printf(public_key* public_key,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"algorithm: %x\n",public_key->algorithm);
    
    switch(public_key->algorithm){
        case ECDSA_NISTP224_WITH_SHA224:
        case ECDSA_NISTP256_WITH_SHA256:
            space_print(n);
            wave_printf(MSG_INFO,"public_key:\n");
            elliptic_curve_point_printf(&public_key->u.public_key,n+N);
            break;
        case ECIES_NISTP256:
            space_print(n);
            wave_printf(MSG_INFO,"ecies_nistp256:\n");

            space_print(n+N);
            wave_printf(MSG_INFO,"supported_symm_alg: %x\n",public_key->u.ecies_nistp256.supported_symm_alg);

            space_print(n+N);
            wave_printf(MSG_INFO,"public_key:\n");
            elliptic_curve_point_printf(&public_key->u.ecies_nistp256.public_key,n+N*2);
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"other_key:");
            for(i=0;i<public_key->u.other_key.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(public_key->u.other_key.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}

void ecdsa_signature_printf(ecdsa_signature* ecdsa_sig,int n){
    int i;
    
    space_print(n);
    wave_printf(MSG_INFO,"r:\n");
    elliptic_curve_point_printf(&ecdsa_sig->r,n+N);

    space_print(n);
    wave_printf(MSG_INFO,"s:");
    for(i=0;i<ecdsa_sig->s.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(ecdsa_sig->s.buf + i));
    }
    wave_printf(MSG_INFO,"\n");
}

void tobesigned_certificate_printf(tobesigned_certificate* tbs_cert,int n,char version_and_type){
    int i;
    char* buf;

    space_print(n);
    wave_printf(MSG_INFO,"holder_type: %x\n",tbs_cert->holder_type);

    space_print(n);
    wave_printf(MSG_INFO,"certificate_content_flags: %x\n",tbs_cert->cf);
    
    switch(tbs_cert->holder_type){
        case ROOT_CA:
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"no_root_ca:\n");

            space_print(n+N);
            wave_printf(MSG_INFO,"signer_id: ");
            for(i=0;i<8;i++)
                wave_printf(MSG_INFO,"%x ",*(&tbs_cert->u.no_root_ca.signer_id + i));
            wave_printf(MSG_INFO,"\n");

            space_print(n+N);
            wave_printf(MSG_INFO,"signature_alg: %x\n",tbs_cert->u.no_root_ca.signature_alg);
    }

    space_print(n);
    wave_printf(MSG_INFO,"scope:\n");
    cert_specific_data_printf(&tbs_cert->scope,n+N,tbs_cert->holder_type);

    space_print(n);
    wave_printf(MSG_INFO,"expiration: ");
    for(i=0;i<4;i++)
        wave_printf(MSG_INFO,"%x ",*((char*)&tbs_cert->expiration + i));
    wave_printf(MSG_INFO,"\n");

    space_print(n);
    wave_printf(MSG_INFO,"crl_series: ");
    for(i=0;i<4;i++)
        wave_printf(MSG_INFO,"%x ",*((char*)&tbs_cert->crl_series + i));
    wave_printf(MSG_INFO,"\n");

    switch(version_and_type){
        case 2:
            space_print(n);
            wave_printf(MSG_INFO,"verification_key:\n");
            public_key_printf(&tbs_cert->version_and_type.verification_key,n+N);
            break;
        case 3:
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"other_key_material:");
            for(i=0;i<tbs_cert->version_and_type.other_key_material.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(tbs_cert->version_and_type.other_key_material.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }

    if((tbs_cert->cf & 1<<0)!=0){
        if((tbs_cert->cf & 1<<1)!=0){
            space_print(n);
            wave_printf(MSG_INFO,"lifetime: ");
            for(i=0;i<2;i++)
                wave_printf(MSG_INFO,"%x ",*((char*)&tbs_cert->flags_content.lifetime + i));
            wave_printf(MSG_INFO,"\n");
        }else{
            space_print(n);
            wave_printf(MSG_INFO,"start_validity: ");
            buf = (char*)&tbs_cert->flags_content.start_validity;
            PRINTF32(buf);
        }

        if((tbs_cert->cf & 1<<2)!=0){
            space_print(n);
            wave_printf(MSG_INFO,"encryption_key:\n");
            public_key_printf(&tbs_cert->flags_content.encryption_key,n+N);
        }

        if((tbs_cert->cf & 0xf8)!=0){
            space_print(n);
            wave_printf(MSG_INFO,"other_cert_content:");
            for(i=0;i<tbs_cert->flags_content.other_cert_content.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(tbs_cert->flags_content.other_cert_content.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
        }
    }
    
}

void signature_printf(signature* signature,int n,pk_algorithm algorithm){
    int i;

    switch(algorithm){
        case ECDSA_NISTP224_WITH_SHA224:
        case ECDSA_NISTP256_WITH_SHA256:
            space_print(n);
            wave_printf(MSG_INFO,"ecdsa_signature:\n");
            ecdsa_signature_printf(&signature->u.ecdsa_signature,n+N);
            break;
        default:
            space_print(n);
            wave_printf(MSG_INFO,"signature:");
            for(i=0;i<signature->u.signature.len;i++){
                if(i%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(n+N);
                }
                wave_printf(MSG_INFO,"%x ",*(signature->u.signature.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}

void elliptic_curve_point_printf(elliptic_curve_point* ell_cp,int n){
    int i;

    space_print(n);
    wave_printf(MSG_INFO,"type: %x\n",ell_cp->type);
    
    space_print(n);
    wave_printf(MSG_INFO,"x:");
    for(i=0;i<ell_cp->x.len;i++){
        if(i%16 == 0){
            wave_printf(MSG_INFO,"\n");
            space_print(n+N);
        }
        wave_printf(MSG_INFO,"%x ",*(ell_cp->x.buf + i));
    }
    wave_printf(MSG_INFO,"\n");

    if(ell_cp->type == UNCOMPRESSED){
        space_print(n);
        wave_printf(MSG_INFO,"y:");
        for(i=0;i<ell_cp->u.y.len;i++){
            if(i%16 == 0){
                wave_printf(MSG_INFO,"\n");
                space_print(n+N);
            }
            wave_printf(MSG_INFO,"%x ",*(ell_cp->u.y.buf + i));
        }
        wave_printf(MSG_INFO,"\n");
    }
}


void certificate_printf(certificate* cert){
    int i;

    wave_printf(MSG_INFO,"version_and_type: %x\n",cert->version_and_type);
    tobesigned_certificate_printf(&cert->unsigned_certificate,N,cert->version_and_type); //缩进4空格
    
    switch(cert->version_and_type){
        case 2:
            wave_printf(MSG_INFO,"signature:\n");
            if(cert->unsigned_certificate.holder_type == ROOT_CA){
                signature_printf(&cert->u.signature,N,
                        cert->unsigned_certificate.version_and_type.verification_key.algorithm);
            }else{
                signature_printf(&cert->u.signature,N,
                        cert->unsigned_certificate.u.no_root_ca.signature_alg);
            }
            break;
        case 3:
            wave_printf(MSG_INFO,"reconstruction_value:\n");
            elliptic_curve_point_printf(&cert->u.reconstruction_value,N);
            break;
        default:
            wave_printf(MSG_INFO,"signature_material:");
            for(i = 0;i< cert->u.signature_material.len;i++){ 
                if((i+1)%16 == 0){
                    wave_printf(MSG_INFO,"\n");
                    space_print(N);
                }
                wave_printf(MSG_INFO,"%x ",*(cert->u.signature_material.buf + i));
            }
            wave_printf(MSG_INFO,"\n");
    }
}
