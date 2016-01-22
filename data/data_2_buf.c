/*=============================================================================
#
# Author: 杨广华 - edesale@qq.com
#
# QQ : 374970456
#
# Last modified: 2015-10-10 18:02
#
# Filename: data_2_buf.c
#
# Description:1.命名格式为struct_2_buf,struct为结构体名字
#			  2.变长ARRAY的编码格式(length + data),针对其编码定义了几个变量：
#				mbuf_beg为变长ARRAY的起始位置
#				mbuf_end为变长ARRAY的结束位置
#				min_len为变长ARRAY中length的最小字节数
#
=============================================================================*/
#include"data_handle.h"
#include"utils/debug.h"
#include"stddef.h"
#include"utils/common.h"

#define getchar1(n) *((char*)&n)	//取n的基地址开始的两字节，下面依次类推
#define getchar2(n) *((char*)&n + 1)
#define getchar3(n) *((char*)&n + 2)
#define getchar4(n) *((char*)&n + 3)
#define getchar5(n) *((char*)&n + 4)
#define getchar6(n) *((char*)&n + 5)
#define getchar7(n) *((char*)&n + 6)
#define getchar8(n) *((char*)&n + 7)

static inline tobuf32(u8* buf,u32 value){	//将u32类型的value采用大端编码编码到buf中
    value = host_to_be32(value);			//host_to_be32  将主机编码改为大端编码
    *buf++ = getchar1(value);				//fixlength vector 
    *buf++ = getchar2(value);
    *buf++ = getchar3(value);
    *buf++ = getchar4(value);
}
static inline tobuf16(u8* buf,u16 value){//fixlength vector
    value = host_to_be16(value);
    *buf++ = getchar1(value);
    *buf++ = getchar2(value);
}
static inline tobuf64(u8* buf,u64 value){
    value = host_to_be64(value);
    *buf++ = getchar1(value);
    *buf++ = getchar2(value);
    *buf++ = getchar3(value);
    *buf++ = getchar4(value);
    *buf++ = getchar5(value);
    *buf++ = getchar6(value);
    *buf++ = getchar7(value);
    *buf++ = getchar8(value);
}
static void varible_len1_encoding(u8* buf,u8 len){	//变量长度可变编码, Variable length 长度小于2的7次方
    *buf = len;
}
static void varible_len2_encoding(u8* buf,u16 len){  //变量长度可变编码，Variable  length 小于2的14
    u16 size = 0x8000;
    size = size | len;
    tobuf16(buf,size);
}
static void varible_len3_encoding(u8* buf,u32 len){ //Variable length 小于2的21次方
    u32 size = 0x00c00000;
    size = size | len;
    size = host_to_be32(size);
    *buf++ = getchar2(size);
    *buf++ = getchar3(size);
    *buf++ = getchar4(size);
}
static void varible_len4_encoding(u8* buf,u32 len){//同上 小于28次方
    u32 size = 0xe0000000;
    size = size | len;
    tobuf32(buf,size);
}
static void varible_len5_encoding(u8* buf,u64 len){//同上 小于35次方
    u64 size = 0x000000f000000000ull;
    size = size | len;
    size = host_to_be64(size);
    *buf++ = getchar4(size);
    *buf++ = getchar5(size);
    *buf++ = getchar6(size);
    *buf++ = getchar7(size);
    *buf++ = getchar8(size);
}
static void varible_len6_encoding(u8* buf,u64 len){//同上 小于42次方
    u64 size = 0x0000f80000000000ull;
    size = size | len;
    size = host_to_be64(size);
    *buf++ = getchar3(size);
    *buf++ = getchar4(size);
    *buf++ = getchar5(size);
    *buf++ = getchar6(size);
    *buf++ = getchar7(size);
    *buf++ = getchar8(size);
}
static void varible_len7_encoding(u8* buf,u64 len){//同上，小于49次方
    u64 size = 0x00fc000000000000ull;
    size = size | len;
    size = host_to_be64(size);
    *buf++ = getchar2(size);
    *buf++ = getchar3(size);
    *buf++ = getchar4(size);
    *buf++ = getchar5(size);
    *buf++ = getchar6(size);
    *buf++ = getchar7(size);
    *buf++ = getchar8(size);
}
static void varible_len8_encoding(u8* buf,u64 len){//同上 小于56次方
    u64 size = 0xfe00000000000000ull;
    size = size | len;
    tobuf64(buf,size);
}
static void  varible_len_encoding(u8* buf,u64 len){//对Variable length的length进行编码 
    if(len < 1<<7){
        varible_len1_encoding(buf,(u8)len);
        return ;
    }
    if(len < 1<<14){
        varible_len2_encoding(buf,(u16)len);
        return ;
    }
    if(len < 1<<21){
        varible_len3_encoding(buf,(u32)len);
        return ;
    }
    if(len < 1<<28){
        varible_len4_encoding(buf,(u32)len);
        return ;
    }
    if(len < 1ull<<35){  //默认为4字节，后加ull表示为8字节
        varible_len5_encoding(buf,(u64)len);
        return ;
    }
    if(len < 1ull<<42){
        varible_len6_encoding(buf,(u64)len);
        return ;
    }
    if(len < 1ull<<49){
        varible_len7_encoding(buf,(u64)len);
        return ;
    }
    varible_len8_encoding(buf,(u64)len);
    return ;
        
}
static u32 varible_len_calculate(u64 len){  
    if(len < 1<<7){
        return 1;
    }
    if(len < 1<<14){
        return 2;
    }
    if(len < 1<<21){
        return 3;
    }
    if(len < 1<<28){
        return 4;
    }
    if(len < 1ull<<35){
        return 5;
    }
    if(len < 1ull<<42){
        return 6;
    }
    if(len < 1ull<<49){
        return 7;
    }
    return 8;
}

static u32 psid_encoding(u8* buf,const psid* psid){
	if((*psid & 15<<28) == 15<<28){
		wave_error_printf("psid大于4字节 %s %d",__FILE__,__LINE__);
		return -1;
	}
	u32 size;
	u32 value = host_to_be32(*psid);
	if((*psid & 14<<28) == 14<<28){
		size = 4;
	}
	else if((*psid & 6<<21) == 6<<21){
		size = 3;
		if((*psid & 0xff000000) != 0){
			wave_error_printf("psid格式错误 %s %d",__FILE__,__LINE__);
			return -1;
		}
	}
	else if((*psid & 2<<14) == 2<<14){
		size = 2;
		if((*psid & 0xffff0000) != 0){
			wave_error_printf("psid格式错误 %s %d",__FILE__,__LINE__);
			return -1;
		}
	}
	else if((*psid & 1<<7) == 0){
		size = 1;
		if((*psid & 0xffffff00) != 0){
			wave_error_printf("psid格式错误 %04x %s %d",*psid,__FILE__,__LINE__);
			return -1;
		}
	}else{
		wave_error_printf("psid格式错误 %04x %s %d",*psid,__FILE__,__LINE__);
		return -1;
	}

	switch(size){
		case 1:
            *buf++ = getchar4(value);
			break;
		case 2:
            *buf++ = getchar3(value);
            *buf++ = getchar4(value);
			break;
		case 3:
            *buf++ = getchar2(value);
            *buf++ = getchar3(value);
            *buf++ = getchar4(value);
			break;
		default:
            *buf++ = getchar1(value);
	        *buf++ = getchar2(value);
	        *buf++ = getchar3(value);
	        *buf++ = getchar4(value);
			break;
	}
	return size;
}

/**
 *   data_2  1
 */

static u32 time64_with_standard_deviation_2_buf(const time64_with_standard_deviation *time64_with_standard_deviation,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	if(len < 9){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	tobuf64(mbuf,time64_with_standard_deviation->time);
	mbuf += 8;
	size -= 8;
	res += 8;

	*mbuf = time64_with_standard_deviation->long_std_dev;
	mbuf++;
	size--;
	res++;
	return res;
}

/**
 *   data_2  2
 */

static u32 tbsdata_extension_2_buf(const tbsdata_extension *tbsdata_extension,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	int i;
	if(len < 2){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = tbsdata_extension->type;
	mbuf++;
	size--;
	res++;

	u32 encode_len = varible_len_calculate(tbsdata_extension->value.len);
	if (size < encode_len + tbsdata_extension->value.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,tbsdata_extension->value.len);
	mbuf += encode_len;

	for(i=0;i < tbsdata_extension->value.len;i++){
		*mbuf++ = *(tbsdata_extension->value.buf + i);
	}
	size = size - encode_len - tbsdata_extension->value.len;
	res = res + encode_len + tbsdata_extension->value.len;
	return res;

}

/**
 *   data_2  3
 */

static u32 three_d_location_2_buf(const three_d_location *three_d_location,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	int i;
	if(len < 10){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	tobuf32(mbuf,three_d_location->latitude);
	mbuf += 4;
	size -= 4;
	res += 4;

	tobuf32(mbuf,three_d_location->longitude);
	mbuf += 4;
	size -= 4;
	res +=4;

	for(i=0;i<2;i++){
		*mbuf++ = *(three_d_location->elevation + i);
	}
	size -= 2;
	res += 2;
	return res;
}

/**
 *   data_2  4
 */

u32 hashedid8_2_buf(const hashedid8 *hashedid8,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	int i;
	if(len < 8){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	for(i=0;i<8;i++){
		*mbuf++ = *(hashedid8->hashedid8 + i);
	}
	size -= 8;
	res += 8;
	return res;
}

/**
 *   data_2  5
 */

static u32 elliptic_curve_point_2_buf(const elliptic_curve_point *elliptic_curve_point,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;
	if(len < 29){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	*mbuf = elliptic_curve_point->type;
	mbuf++;
	size--;
	res++;

	for(i=0;i < elliptic_curve_point->x.len;i++){
		*mbuf++ = *(elliptic_curve_point->x.buf + i);
	}
	size = size - elliptic_curve_point->x.len;
	res = res + elliptic_curve_point->x.len;

	if(elliptic_curve_point->type == UNCOMPRESSED){
		for(i=0;i < elliptic_curve_point->u.y.len;i++){
			*mbuf++ = *(elliptic_curve_point->u.y.buf + i);
		}
		size = size  - elliptic_curve_point->u.y.len;
		res = res  + elliptic_curve_point->u.y.len;
	}
	return res;
}
 
/**
 *   data_2  6
 */

static u32 ecdsa_signature_2_buf(const ecdsa_signature *ecdsa_signature,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 30){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = elliptic_curve_point_2_buf(&ecdsa_signature->r,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	for(i=0;i < ecdsa_signature->s.len;i++){
		*mbuf++ = *(ecdsa_signature->s.buf + i);
	}
	size = size - ecdsa_signature->s.len;
	res = res + ecdsa_signature->s.len;

	return res;
}


/**
 *   data_2  7
 */

static u32 signature_2_buf(const signature *signature,u8* buf,u32 len,pk_algorithm algorithm){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 1){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	switch(algorithm){
		case ECDSA_NISTP224_WITH_SHA224:
		case ECDSA_NISTP256_WITH_SHA256:
			encode_len = ecdsa_signature_2_buf(&signature->u.ecdsa_signature,mbuf,size);
			return encode_len;
		default:
			encode_len = varible_len_calculate(signature->u.signature.len);
			if (size < encode_len + signature->u.signature.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,signature->u.signature.len);
			mbuf += encode_len;

			for(i=0;i < signature->u.signature.len;i++){
				*mbuf++ = *(signature->u.signature.buf + i);
			}
			size = size - encode_len - signature->u.signature.len;
			res = res + encode_len + signature->u.signature.len;
			return res;
	}
}

/**
 *   data_2  8
 */

static u32 public_key_2_buf(const public_key *public_key,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 2){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = public_key->algorithm;
	 mbuf++;
	 size--;
	 res++;

	 switch(public_key->algorithm){
		 case ECDSA_NISTP224_WITH_SHA224:
		 case ECDSA_NISTP256_WITH_SHA256:
			 encode_len = elliptic_curve_point_2_buf(&public_key->u.public_key,mbuf,size);
			 if(encode_len < 0)
				 return encode_len;
			 return encode_len + res;
		 case ECIES_NISTP256:
			 *mbuf = public_key->u.ecies_nistp256.supported_symm_alg;
			 mbuf++;
			 size--;
			 res++;
			 encode_len = elliptic_curve_point_2_buf(&public_key->u.ecies_nistp256.public_key,mbuf,size);
			 if(encode_len < 0)
				 return encode_len;
			 return encode_len + res;
		 default:
			 encode_len = varible_len_calculate(public_key->u.other_key.len);
			 if (size < encode_len + public_key->u.other_key.len){
				 wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				 return NOT_ENOUGHT;
			 }
			 varible_len_encoding(mbuf,public_key->u.other_key.len);
			 mbuf += encode_len;

			 for(i=0;i < public_key->u.other_key.len;i++){
				 *mbuf++ = *(public_key->u.other_key.buf + i);
			 }
			 size = size - encode_len - public_key->u.other_key.len;
			 res = res + encode_len + public_key->u.other_key.len;
			 return res;
	 }
}

/**
 *   data_2  9
 */

static u32 two_d_location_2_buf(const two_d_location *two_d_location,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	if(len < 8){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	tobuf32(mbuf,two_d_location->latitude);
	mbuf += 4;
	size -= 4;
	res += 4;

	tobuf32(mbuf,two_d_location->longitude);
	mbuf += 4;
	size -=4;
	res +=4;
	return res;
}

/**
 *   data_2  10
 */

static u32 rectangular_region_2_buf(const rectangular_region *rectangular_region,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	if(len < 16){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = two_d_location_2_buf(&rectangular_region->north_west,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = two_d_location_2_buf(&rectangular_region->south_east,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	return res;
}

/**
 *   data_2  11
 */

static u32 circular_region_2_buf(const circular_region *circular_region,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	if(len < 10){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = two_d_location_2_buf(&circular_region->center,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	tobuf16(mbuf,circular_region->radius);
	mbuf += 2;
	size -= 2;
	res += 2;
	return res;
}

/**
 *   data_2  12
 *
 *   每个rectangular_region长度为16字节
 */

static u32 geographic_region_2_buf(const geographic_region *geographic_region,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 1){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = geographic_region->region_type;
	mbuf++;
	size--;
	res++;

	switch(geographic_region->region_type){
		case FROM_ISSUER:
			return res;
		case CIRCLE:
			encode_len = circular_region_2_buf(&geographic_region->u.circular_region,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case RECTANGLE:
			encode_len = varible_len_calculate(geographic_region->u.rectangular_region.len*16);
			if (size < encode_len + geographic_region->u.rectangular_region.len*16){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,geographic_region->u.rectangular_region.len*16);
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;

			for(i=0;i < geographic_region->u.rectangular_region.len;i++){
				encode_len = rectangular_region_2_buf(geographic_region->u.rectangular_region.buf + i,mbuf,size);
				if(encode_len < 0)
					return encode_len;
				mbuf += encode_len;
				size -= encode_len;
				res += encode_len;
			}
			return res;

		case POLYGON:
			encode_len = varible_len_calculate(geographic_region->u.polygonal_region.len*8);
			if(size < encode_len + geographic_region->u.polygonal_region.len*8){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,geographic_region->u.polygonal_region.len*8);
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;

			for(i=0;i < geographic_region->u.polygonal_region.len;i++){
				encode_len = two_d_location_2_buf(geographic_region->u.polygonal_region.buf + i,mbuf,size);
				if(encode_len < 0)
					return encode_len;
				mbuf += encode_len;
				size -= encode_len;
				res += encode_len;
			}
			return res;
		case NONE:
			return res;
		default:
			encode_len = varible_len_calculate(geographic_region->u.other_region.len);
			if (size < encode_len + geographic_region->u.other_region.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,geographic_region->u.other_region.len);
			mbuf += encode_len;

			for(i=0;i < geographic_region->u.other_region.len;i++){
				*mbuf++ = *(geographic_region->u.other_region.buf + i);
			}
			size = size - encode_len - geographic_region->u.other_region.len;
			res = res + encode_len + geographic_region->u.other_region.len;
			return res;
	}
}

/**
 *   data_2  13
 */

static u32 psid_priority_2_buf(const psid_priority *psid_priority,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;

	if(len < 2){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = psid_encoding(mbuf,&psid_priority->psid);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	*mbuf = psid_priority->max_priority;
	mbuf++;
	size--;
	res++;
	return res;
}

/**
 *   data_2  14
 */

static u32 psid_priority_array_2_buf(const psid_priority_array *psid_priority_array,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
    u8* mbuf_beg;
    u8* mbuf_end;
	int i;
    int count;

	if(len < 1){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = psid_priority_array->type;
	mbuf++;
	size--;
	res++;

	switch(psid_priority_array->type){
		case ARRAY_TYPE_SPECIFIED:
            mbuf_beg = mbuf;
            count = 0;

			for(i=0;i < psid_priority_array->u.permissions_list.len;i++){
				encode_len = psid_priority_2_buf(psid_priority_array->u.permissions_list.buf + i,mbuf,size);
				if(encode_len < 0)
					return encode_len;
				mbuf += encode_len;
				size -= encode_len;
				res += encode_len;
                count += encode_len;
			}

            encode_len = varible_len_calculate(count);
            if(size < encode_len){
                wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
                return NOT_ENOUGHT;
            }

            mbuf_end = mbuf;
            while(mbuf_end != mbuf_beg){
                mbuf_end--;
                *(mbuf_end + encode_len) = *mbuf_end;
            }
            varible_len_encoding(mbuf_beg,count);
            res += encode_len;

			return res;
		case ARRAY_TYPE_FROM_ISSUER:
			return res;
		default:
			encode_len = varible_len_calculate(psid_priority_array->u.other_permissions.len);
			if (size < encode_len + psid_priority_array->u.other_permissions.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,psid_priority_array->u.other_permissions.len);
			mbuf += encode_len;

			for(i=0;i < psid_priority_array->u.other_permissions.len;i++){
				*mbuf++ = *(psid_priority_array->u.other_permissions.buf + i);
			}
			size = size - encode_len - psid_priority_array->u.other_permissions.len;
			res = res + encode_len + psid_priority_array->u.other_permissions.len;
			return res;
	}
}

/**
 *   data_2  15
 */

static u32 psid_array_2_buf(const psid_array *psid_array,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	u8* mbuf_beg;
	u8* mbuf_end;
	u32 min_len;
	int i;

	if(len < 1){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = psid_array->type;
	mbuf++;
	size--;
	res++;

	switch(psid_array->type){
		case ARRAY_TYPE_SPECIFIED:
			min_len = varible_len_calculate(psid_array->u.permissions_list.len);
			if (size < min_len + psid_array->u.permissions_list.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);	
				return NOT_ENOUGHT;
			}
			
			mbuf_beg = mbuf;
			u32 data_len = 0;
			for(i=0;i < psid_array->u.permissions_list.len;i++){
				encode_len = psid_encoding(mbuf,psid_array->u.permissions_list.buf + i);
				if(encode_len < 0)
					return encode_len;
				data_len += encode_len;
				mbuf += encode_len;
				size -= encode_len;
				res += encode_len;
			}
			mbuf_end = mbuf;

			encode_len = varible_len_calculate(data_len);
			if(size < encode_len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}

			mbuf = mbuf_end + encode_len;
			while(mbuf_beg != mbuf_end){
				mbuf_end--;
				*(mbuf_end + encode_len) = *mbuf_end;
			}
            res += encode_len;
			varible_len_encoding(mbuf_beg,data_len);

			return res;
		case ARRAY_TYPE_FROM_ISSUER:
			return res;
		default:
			encode_len = varible_len_calculate(psid_array->u.other_permissions.len);
			if (size < encode_len + psid_array->u.other_permissions.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,psid_array->u.other_permissions.len);
			mbuf += encode_len;

			for(i=0;i < psid_array->u.other_permissions.len;i++){
				*mbuf++ = *(psid_array->u.other_permissions.buf + i);
			}
			size = size - encode_len - psid_array->u.other_permissions.len;
			res = res + encode_len + psid_array->u.other_permissions.len;
			return res;
	}
}

/**
 *   data_2  16
 */

static u32 psid_ssp_2_buf(const psid_ssp *psid_ssp,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 2){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = psid_encoding(mbuf,&psid_ssp->psid);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = varible_len_calculate(psid_ssp->service_specific_permissions.len);
	if (size < encode_len + psid_ssp->service_specific_permissions.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,psid_ssp->service_specific_permissions.len);
	mbuf += encode_len;

	for(i=0;i < psid_ssp->service_specific_permissions.len;i++){
		*mbuf++ = *(psid_ssp->service_specific_permissions.buf + i);
	}
	size = size - encode_len - psid_ssp->service_specific_permissions.len;
	res = res + encode_len + psid_ssp->service_specific_permissions.len;

	return res;
}

/**
 *   data_2  17
 *
 *  
 */

static u32 psid_ssp_array_2_buf(const psid_ssp_array *psid_ssp_array,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	u8* mbuf_beg;
	u8* mbuf_end;
	u32 min_len;
	int i;

	if(len < 1){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = psid_ssp_array->type;
	mbuf++;
	size--;
	res++;

	switch(psid_ssp_array->type){
		case ARRAY_TYPE_SPECIFIED:
			min_len = varible_len_calculate(psid_ssp_array->u.permissions_list.len*2);
			if (size < min_len + psid_ssp_array->u.permissions_list.len*2){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}

			mbuf_beg = mbuf;
			u32 data_len = 0;
			for(i=0;i < psid_ssp_array->u.permissions_list.len;i++){
				encode_len = psid_ssp_2_buf(psid_ssp_array->u.permissions_list.buf + i,mbuf,size);
				if(encode_len < 0)
					return encode_len;
				mbuf += encode_len;
				data_len += encode_len;
			}
			mbuf_end = mbuf;
			size -= data_len;
			res += data_len;

			encode_len = varible_len_calculate(data_len);
			if(size < encode_len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}

			mbuf = mbuf_end + encode_len;
			while(mbuf_beg != mbuf_end){
				mbuf_end--;
				*(mbuf_end + encode_len) = *mbuf_end;
			}

			varible_len_encoding(mbuf_beg,data_len);

			return encode_len + res;

		case ARRAY_TYPE_FROM_ISSUER:
			return res;
		default:
			encode_len = varible_len_calculate(psid_ssp_array->u.other_permissions.len);
			if (size < encode_len + psid_ssp_array->u.other_permissions.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,psid_ssp_array->u.other_permissions.len);
			mbuf += encode_len;
	
			for(i=0;i < psid_ssp_array->u.other_permissions.len;i++){
				*mbuf++ = *(psid_ssp_array->u.other_permissions.buf + i);
			}
			size = size - encode_len - psid_ssp_array->u.other_permissions.len;
			res = res + psid_ssp_array->u.other_permissions.len;
			return res;
	}
}

/**
 *   data_2  18
 */

static u32 psid_priority_ssp_2_buf(const psid_priority_ssp *psid_priority_ssp,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 3){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = psid_encoding(mbuf,&psid_priority_ssp->psid);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	*mbuf = psid_priority_ssp->max_priority;
	mbuf++;
	size--;
	res++;

	encode_len = varible_len_calculate(psid_priority_ssp->service_specific_permissions.len);
	if (size < encode_len + psid_priority_ssp->service_specific_permissions.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,psid_priority_ssp->service_specific_permissions.len);
	mbuf += encode_len;

	for(i=0;i < psid_priority_ssp->service_specific_permissions.len;i++){
		*mbuf++ = *(psid_priority_ssp->service_specific_permissions.buf + i);
	}
	size = size - encode_len - psid_priority_ssp->service_specific_permissions.len;
	res = res + encode_len + psid_priority_ssp->service_specific_permissions.len;
	return res;
}

/**
 *   data_2  19
 */

static u32 psid_priority_ssp_array_2_buf(const psid_priority_ssp_array *psid_priority_ssp_array,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	u8* mbuf_beg;
	u8* mbuf_end;
	u32 min_len;
	int i;

	if(len < 1){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = psid_priority_ssp_array->type;
	mbuf++;
	size--;
	res++;

	switch(psid_priority_ssp_array->type){
		case ARRAY_TYPE_SPECIFIED:	
			min_len = varible_len_calculate(psid_priority_ssp_array->u.permissions_list.len*10);
			if (size < min_len + psid_priority_ssp_array->u.permissions_list.len*10){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}

			mbuf_beg = mbuf;
			u32 data_len = 0;
			for(i=0;i < psid_priority_ssp_array->u.permissions_list.len;i++){
				encode_len = psid_priority_ssp_2_buf(psid_priority_ssp_array->u.permissions_list.buf + i,mbuf,size);
				if(encode_len < 0)
					return encode_len;
				mbuf += encode_len;
				data_len += encode_len;
			}
			mbuf_end = mbuf;
			size -= data_len;
			res += data_len;

			encode_len = varible_len_calculate(data_len);
			if(size < encode_len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}

			mbuf = mbuf_end + encode_len;
			while(mbuf_beg != mbuf_end){
				mbuf_end--;
				*(mbuf_end + encode_len) = *mbuf_end;
			}

			varible_len_encoding(mbuf_beg,data_len);

			return encode_len + res;

		case ARRAY_TYPE_FROM_ISSUER:
			return res;
		default:
			encode_len = varible_len_calculate(psid_priority_ssp_array->u.other_permissions.len);
			if (size < encode_len + psid_priority_ssp_array->u.other_permissions.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,psid_priority_ssp_array->u.other_permissions.len);
			mbuf += encode_len;

			for(i=0;i < psid_priority_ssp_array->u.other_permissions.len;i++){
				*mbuf++ = *(psid_priority_ssp_array->u.other_permissions.buf + i);
			}
			size = size - encode_len - psid_priority_ssp_array->u.other_permissions.len;
			res = res + encode_len + psid_priority_ssp_array->u.other_permissions.len;
			return res;
	}
}

/**
 *   data_2  20
 */

static u32 wsa_scope_2_buf(const wsa_scope *wsa_scope,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 3){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = varible_len_calculate(wsa_scope->name.len);
	if (size < encode_len + wsa_scope->name.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,wsa_scope->name.len);
	mbuf += encode_len;

	for(i=0;i < wsa_scope->name.len;i++){
		*mbuf++ = *(wsa_scope->name.buf + i);
	}
	size = size - encode_len - wsa_scope->name.len;
	res = res + encode_len + wsa_scope->name.len;

	encode_len = psid_priority_ssp_array_2_buf(&wsa_scope->permissions,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = geographic_region_2_buf(&wsa_scope->region,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	return res;
}

/**
 *   data_2  21
 */

static u32 anonymous_scope_2_buf(const anonymous_scope *anonymous_scope,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 5){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = varible_len_calculate(anonymous_scope->additionla_data.len);
	if (size < encode_len + anonymous_scope->additionla_data.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,anonymous_scope->additionla_data.len);
	mbuf += encode_len;

	for(i=0;i < anonymous_scope->additionla_data.len;i++){
		*mbuf++ = *(anonymous_scope->additionla_data.buf + i);
	}
	size = size - encode_len - anonymous_scope->additionla_data.len;
	res = res + encode_len + anonymous_scope->additionla_data.len;
	
	encode_len = psid_ssp_array_2_buf(&anonymous_scope->permissions,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = geographic_region_2_buf(&anonymous_scope->region,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;
	return res;
}

/**
 *   data_2  22
 */

static u32 identified_scope_2_buf(const identified_scope *identified_scope,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 3){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = varible_len_calculate(identified_scope->name.len);
	if (size < encode_len + identified_scope->name.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,identified_scope->name.len);
	mbuf += encode_len;

	for(i=0;i < identified_scope->name.len;i++){
		*mbuf++ = *(identified_scope->name.buf + i);
	}
	size = size - encode_len - identified_scope->name.len;
	res = res + encode_len + identified_scope->name.len;

	encode_len = psid_ssp_array_2_buf(&identified_scope->permissions,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = geographic_region_2_buf(&identified_scope->region,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;
	return res;
}

/**
 *   data_2  23
 */

static u32 identified_not_localized_scope_2_buf(const identified_not_localized_scope *identified_not_localized_scope,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 2){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = varible_len_calculate(identified_not_localized_scope->name.len);
	if (size < encode_len + identified_not_localized_scope->name.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,identified_not_localized_scope->name.len);
	mbuf += encode_len;

	for(i=0;i < identified_not_localized_scope->name.len;i++){
		*mbuf++ = *(identified_not_localized_scope->name.buf + i);
	}
	size = size - encode_len - identified_not_localized_scope->name.len;
	res = res + encode_len + identified_not_localized_scope->name.len;

	encode_len = psid_ssp_array_2_buf(&identified_not_localized_scope->permissions,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;
	return res;
}

/**
 *   data_2  24
 */

static u32 wsa_ca_scope_2_buf(const wsa_ca_scope *wsa_ca_scope,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 3){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = varible_len_calculate(wsa_ca_scope->name.len);
	if (size < encode_len + wsa_ca_scope->name.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,wsa_ca_scope->name.len);
	mbuf += encode_len;

	for(i=0;i < wsa_ca_scope->name.len;i++){
		*mbuf++ = *(wsa_ca_scope->name.buf + i);
	}
	size = size - encode_len - wsa_ca_scope->name.len;
	res = res + encode_len + wsa_ca_scope->name.len;
	
	encode_len = psid_priority_array_2_buf(&wsa_ca_scope->permissions,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = geographic_region_2_buf(&wsa_ca_scope->region,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;
	return res;
}

/**
 *   data_2  25
 */

static u32 sec_data_exch_ca_scope_2_buf(const sec_data_exch_ca_scope *sec_data_exch_ca_scope,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 4){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = varible_len_calculate(sec_data_exch_ca_scope->name.len);
	if (size < encode_len + sec_data_exch_ca_scope->name.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,sec_data_exch_ca_scope->name.len);
	mbuf += encode_len;

	for(i=0;i < sec_data_exch_ca_scope->name.len;i++){
		*mbuf++ = *(sec_data_exch_ca_scope->name.buf + i);
	}
	size = size - encode_len - sec_data_exch_ca_scope->name.len;
	res = res + encode_len + sec_data_exch_ca_scope->name.len;
	
	if(sec_data_exch_ca_scope->permitted_holder_types < 1<<7){
		*mbuf = sec_data_exch_ca_scope->permitted_holder_types;
		mbuf++;
		size--;
		res++;
	}
	else if(sec_data_exch_ca_scope->permitted_holder_types < 1<<14){
		*((u16*)mbuf) = host_to_be16(sec_data_exch_ca_scope->permitted_holder_types | 0x8000);
		mbuf += 2;
		size -= 2;
		res += 2;
	}

	encode_len = psid_array_2_buf(&sec_data_exch_ca_scope->permissions,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = geographic_region_2_buf(&sec_data_exch_ca_scope->region,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -+ encode_len;
	res += encode_len;
	return res;
}

/**
 *   data_2  26
 */

static u32 root_ca_scope_2_buf(const root_ca_scope *root_ca_scope,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 4){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = varible_len_calculate(root_ca_scope->name.len);
	if (size < encode_len + root_ca_scope->name.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,root_ca_scope->name.len);
	mbuf += encode_len;

	for(i=0;i < root_ca_scope->name.len;i++){
		*mbuf++ = *(root_ca_scope->name.buf + i);
	}
	size = size - encode_len - root_ca_scope->name.len;
	res = res + encode_len + root_ca_scope->name.len;
	
	if(root_ca_scope->permitted_holder_types < 1<<7){
		*mbuf = root_ca_scope->permitted_holder_types;
		mbuf++;
		size--;
		res++;
	}
	else if(root_ca_scope->permitted_holder_types < 1<<14){
		*((u16*)mbuf) = host_to_be16(root_ca_scope->permitted_holder_types | 0x8000);
		mbuf += 2;
		size -= 2;
		res += 2;
	}

	if((root_ca_scope->permitted_holder_types & 1<<0)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<1)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<2)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<3)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<6)!=0){
		encode_len = psid_array_2_buf(&root_ca_scope->flags_content.secure_data_permissions,mbuf,size);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		size -= encode_len;
		res += encode_len;
	}

	if((root_ca_scope->permitted_holder_types & 1<<4)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<5)!=0 ||
		((root_ca_scope->permitted_holder_types > 1<<6) && (root_ca_scope->permitted_holder_types & 1<<7)!=0)){
		encode_len = psid_priority_array_2_buf(&root_ca_scope->flags_content.wsa_permissions,mbuf,size);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		size -= encode_len;
		res += encode_len;
	}

	if((root_ca_scope->permitted_holder_types > 1<<6) && (root_ca_scope->permitted_holder_types & 1<<8)!=0){
		encode_len = varible_len_calculate(root_ca_scope->flags_content.other_permissions.len);
		if (size < encode_len + root_ca_scope->flags_content.other_permissions.len){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}
		varible_len_encoding(mbuf,root_ca_scope->flags_content.other_permissions.len);
		mbuf += encode_len;

		for(i=0;i < root_ca_scope->flags_content.other_permissions.len;i++){
			*mbuf++ = *(root_ca_scope->flags_content.other_permissions.buf + i);
		}
		size = size - encode_len - root_ca_scope->flags_content.other_permissions.len;
		res = res + encode_len + root_ca_scope->flags_content.other_permissions.len;
	}
	
	encode_len = geographic_region_2_buf(&root_ca_scope->region,mbuf,size);
	if(encode_len <0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;
	return res;
}

/**
 *   data_2  27
 */

static u32 cert_specific_data_2_buf(const cert_specific_data *cert_specific_data,
		u8* buf,u32 len,holder_type holder_type){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 1){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	switch(holder_type){
		case ROOT_CA:
			encode_len = root_ca_scope_2_buf(&cert_specific_data->u.root_ca_scope,mbuf,size);
			return encode_len;
		case SDE_CA:
		case SDE_ENROLMENT:
			encode_len = sec_data_exch_ca_scope_2_buf(&cert_specific_data->u.sde_ca_scope,mbuf,size);
			return encode_len;
		case WSA_CA:
		case WSA_ENROLMENT:
			encode_len = wsa_ca_scope_2_buf(&cert_specific_data->u.wsa_ca_scope,mbuf,size);
			return encode_len;
		case CRL_SIGNER:
			encode_len = varible_len_calculate(cert_specific_data->u.responsible_series.len*4);
			if (size < encode_len + cert_specific_data->u.responsible_series.len*4){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,cert_specific_data->u.responsible_series.len*4);
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;

			for(i=0;i < cert_specific_data->u.responsible_series.len;i++){
				tobuf32(mbuf,*(cert_specific_data->u.responsible_series.buf + i));
				mbuf += 4;
				size -= 4;
				res += 4;
			}
			return res;
		case SDE_IDENTIFIED_NOT_LOCALIZED:
			encode_len = identified_not_localized_scope_2_buf(&cert_specific_data->u.id_non_loc_scope,mbuf,size);
			return encode_len;
		case SDE_IDENTIFIED_LOCALIZED:
			encode_len = identified_scope_2_buf(&cert_specific_data->u.id_scope,mbuf,size);
			return encode_len;
		case SDE_ANONYMOUS:
			encode_len = anonymous_scope_2_buf(&cert_specific_data->u.anonymous_scope,mbuf,size);
			return encode_len;
		case WSA:
			encode_len = wsa_scope_2_buf(&cert_specific_data->u.wsa_scope,mbuf,size);
			return encode_len;
		default:
			encode_len = varible_len_calculate(cert_specific_data->u.other_scope.len);
			if (size < encode_len + cert_specific_data->u.other_scope.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,cert_specific_data->u.other_scope.len);
			mbuf += encode_len;

			for(i=0;i < cert_specific_data->u.other_scope.len;i++){
				*mbuf++ = *(cert_specific_data->u.other_scope.buf + i);
			}
			size = size - encode_len - cert_specific_data->u.other_scope.len;
			res = res + encode_len + cert_specific_data->u.other_scope.len;
			return res;
	}
}

/**
 *   data_2  28
 */

u32 tobesigned_certificate_2_buf(const tobesigned_certificate *tobesigned_certificate,
		u8* buf,u32 len,u8 version_and_type){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 12){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = tobesigned_certificate->holder_type;
	mbuf++;
	size--;
	res++;

	*mbuf = tobesigned_certificate->cf;
	mbuf++;
	size--;
	res++;

	switch(tobesigned_certificate->holder_type){
		case ROOT_CA:
			break;
		default:
			encode_len = hashedid8_2_buf(&tobesigned_certificate->u.no_root_ca.signer_id,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;

			*mbuf = tobesigned_certificate->u.no_root_ca.signature_alg;
			mbuf++;
			size--;
			res++;
			break;
	}
	encode_len = cert_specific_data_2_buf(&tobesigned_certificate->scope,mbuf,size,tobesigned_certificate->holder_type);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	tobuf32(mbuf,tobesigned_certificate->expiration);
	mbuf += 4;
	size -= 4;
	res += 4;

	tobuf32(mbuf,tobesigned_certificate->crl_series);
	mbuf += 4;
	size -= 4;
	res += 4;

	switch(version_and_type){
		case 2:
			encode_len = public_key_2_buf(&tobesigned_certificate->version_and_type.verification_key,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;
			break;
		case 3:
			break;
		default:
			encode_len = varible_len_calculate(tobesigned_certificate->version_and_type.other_key_material.len);
			if (size < encode_len + tobesigned_certificate->version_and_type.other_key_material.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_certificate->version_and_type.other_key_material.len);
			mbuf += encode_len;

			for(i=0;i < tobesigned_certificate->version_and_type.other_key_material.len;i++){
				*mbuf++ = *(tobesigned_certificate->version_and_type.other_key_material.buf + i);
			}
			size = size - encode_len - tobesigned_certificate->version_and_type.other_key_material.len;
			res = res + encode_len + tobesigned_certificate->version_and_type.other_key_material.len;
			break;
	}

	if((tobesigned_certificate->cf & 1<<0)!=0){
		if((tobesigned_certificate->cf & 1<<1)!=0){
			tobuf16(mbuf,tobesigned_certificate->flags_content.lifetime);
			mbuf += 2;
			size -= 2;
			res += 2;
		}else{
			tobuf32(mbuf,tobesigned_certificate->flags_content.start_validity);
			mbuf += 4;
			size -= 4;
			res += 4;
		}
	}

	if((tobesigned_certificate->cf & 1<<2)!=0){
		encode_len = public_key_2_buf(&tobesigned_certificate->flags_content.encryption_key,mbuf,size);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		size -= encode_len;
		res += encode_len;
	}

	if((tobesigned_certificate->cf & 0xf8)!=0){//本协议中cf为1字节
		encode_len = varible_len_calculate(tobesigned_certificate->flags_content.other_cert_content.len);
		if (size < encode_len + tobesigned_certificate->flags_content.other_cert_content.len){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}
		varible_len_encoding(mbuf,tobesigned_certificate->flags_content.other_cert_content.len);
		mbuf += encode_len;

		for(i=0;i < tobesigned_certificate->flags_content.other_cert_content.len;i++){
			*mbuf++ = *(tobesigned_certificate->flags_content.other_cert_content.buf + i);
		}
		size = size - encode_len - tobesigned_certificate->flags_content.other_cert_content.len;
		res = res + encode_len + tobesigned_certificate->flags_content.other_cert_content.len;
	}
	
	return res;
}

/**
 *   data_2  29
 */

u32 certificate_2_buf(const certificate *certificate,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 14){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	*mbuf = certificate->version_and_type;
    if(certificate->version_and_type != 2){
        wave_error_printf("version and type != 2 %s %d",__FILE__,__LINE__);
        return -3;
    }
	mbuf++;
	size--;
	res++;

	encode_len = tobesigned_certificate_2_buf(&certificate->unsigned_certificate,mbuf,size,certificate->version_and_type);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	switch(certificate->version_and_type){
		case 2:
			if(certificate->unsigned_certificate.holder_type == ROOT_CA){
				encode_len = signature_2_buf(&certificate->u.signature,mbuf,size,
						certificate->unsigned_certificate.version_and_type.verification_key.algorithm);
				if(encode_len < 0)
					return encode_len;
			}else{
				encode_len = signature_2_buf(&certificate->u.signature,mbuf,size,
						certificate->unsigned_certificate.u.no_root_ca.signature_alg);
				if(encode_len < 0)
					return encode_len;
			}
			return encode_len + res;
		case 3:
			encode_len = elliptic_curve_point_2_buf(&certificate->u.reconstruction_value,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		default:
			encode_len = varible_len_calculate(certificate->u.signature_material.len);
			if (size < encode_len + certificate->u.signature_material.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,certificate->u.signature_material.len);
			mbuf += encode_len;
		
			for(i=0;i < certificate->u.signature_material.len;i++){
				*mbuf++ = *(certificate->u.signature_material.buf + i);
			}
			size = size - encode_len - certificate->u.signature_material.len;
			res = res + encode_len + certificate->u.signature_material.len;
			return res;
	}
}

/**
 *   data_2  30
 */

static u32 signer_identifier_2_buf(const signer_identifier *signer_identifier,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	u8* mbuf_beg;
	u8* mbuf_end;
	u32 min_len;
	int i;

	if(len < 1){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = signer_identifier->type;
	mbuf++;
	size--;
	res++;

	switch(signer_identifier->type){
		case SELF:
			return res;
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			encode_len = hashedid8_2_buf(&signer_identifier->u.digest,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE:
			encode_len = certificate_2_buf(&signer_identifier->u.certificate,mbuf,size);
           
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE_CHAIN:
			min_len = varible_len_calculate(signer_identifier->u.certificates.len*22);
			if (size < min_len + signer_identifier->u.certificates.len*22){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}

			mbuf_beg = mbuf;
			u32 data_len = 0;
			for(i=0;i < signer_identifier->u.certificates.len;i++){
				encode_len = certificate_2_buf(signer_identifier->u.certificates.buf + i,mbuf,size);
				if(encode_len < 0)
					return encode_len;
				mbuf += encode_len;
				data_len += encode_len;
			}
			mbuf_end = mbuf;
			size -= data_len;
			res += data_len;

			encode_len = varible_len_calculate(data_len);
			if(size < encode_len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}

			mbuf = mbuf_end + encode_len;
			while(mbuf_beg != mbuf_end){
				mbuf_end--;
				*(mbuf_end + encode_len) = *mbuf_end;
			}

			varible_len_encoding(mbuf_beg,data_len);

			return encode_len + res;

		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			*mbuf = signer_identifier->u.other_algorithm.algorithm;
			mbuf++;
			size--;
			res++;

			encode_len = hashedid8_2_buf(&signer_identifier->u.other_algorithm.digest,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		default:
			encode_len = varible_len_calculate(signer_identifier->u.id.len);
			if (size < encode_len + signer_identifier->u.id.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,signer_identifier->u.id.len);
			mbuf += encode_len;
		
			for(i=0;i < signer_identifier->u.id.len;i++){
				*mbuf++ = *(signer_identifier->u.id.buf + i);
			}
			size = size - encode_len - signer_identifier->u.id.len;
			res = res + encode_len + signer_identifier->u.id.len;
			return res;
	}
}

/**
 *   data_2  31
 */

static u32 crl_request_2_buf(const crl_request *crl_request,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	if(len < 16){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = hashedid8_2_buf(&crl_request->issuer,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	tobuf32(mbuf,crl_request->crl_series);
	mbuf += 4;
	size -= 4;
	res += 4;

	tobuf32(mbuf,crl_request->issue_date);
	mbuf += 4;
	size -= 4;
	res += 4;
	return res;
}

/**
 *   data_2  32
 */

static u32 certid10_2_buf(const certid10 *certid10,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	int i;

	if(len < 10){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	for(i=0;i<10;i++){
		*mbuf++ = *(certid10->certid10 + i);
	}
	size -= 10;
	res += 10;
	return res;
}

/**
 *   data_2  33
 */

static u32 id_and_date_2_buf(const id_and_date *id_and_date,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	if(len < 14){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = certid10_2_buf(&id_and_date->id,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	tobuf32(mbuf,id_and_date->expiry);
	mbuf += 4;
	size -= 4;
	res += 4;
	return res;
}


/**
 *   data_2  34
 */

u32 tobesigned_crl_2_buf(const tobesigned_crl *tobesigned_crl,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 30){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = tobesigned_crl->type;
	mbuf++;
	size--;
	res++;

	tobuf32(mbuf,tobesigned_crl->crl_series);
	mbuf += 4;
	size -= 4;
	res += 4;

	encode_len = hashedid8_2_buf(&tobesigned_crl->ca_id,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	tobuf32(mbuf,tobesigned_crl->crl_serial);
	mbuf += 4;
	size -= 4;
	res += 4;

	tobuf32(mbuf,tobesigned_crl->start_period);
	mbuf += 4;
	size -= 4;
	res += 4;
	
	tobuf32(mbuf,tobesigned_crl->issue_date);
	mbuf += 4;
	size -= 4;
	res += 4;
	
	tobuf32(mbuf,tobesigned_crl->next_crl);
	mbuf += 4;
	size -= 4;
	res += 4;

	switch(tobesigned_crl->type){
		case ID_ONLY:
			encode_len = varible_len_calculate(tobesigned_crl->u.entries.len*10);
			if (size < encode_len + tobesigned_crl->u.entries.len*10){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_crl->u.entries.len*10);
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;

			for(i=0;i < tobesigned_crl->u.entries.len;i++){
				encode_len = certid10_2_buf(tobesigned_crl->u.entries.buf + i,mbuf,size);
				if(encode_len < 0)
					return encode_len;
				mbuf += encode_len;
				size -= encode_len;
				res += encode_len;
			}
			return res;
		case ID_AND_EXPIRY:
			encode_len = varible_len_calculate(tobesigned_crl->u.expiring_entries.len*14);
			if (size < encode_len + tobesigned_crl->u.expiring_entries.len*14){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_crl->u.expiring_entries.len*14);
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;

			for(i=0;i < tobesigned_crl->u.expiring_entries.len;i++){
				encode_len = id_and_date_2_buf(tobesigned_crl->u.expiring_entries.buf + i,mbuf,size);
				if(encode_len < 0)
					return encode_len;
				mbuf += encode_len;
				size -= encode_len;
				res += encode_len;
			}
			return res;
		default:
			encode_len = varible_len_calculate(tobesigned_crl->u.other_entries.len);
			if (size < encode_len + tobesigned_crl->u.other_entries.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_crl->u.other_entries.len);
			mbuf += encode_len;

			for(i=0;i < tobesigned_crl->u.other_entries.len;i++){
				*mbuf++ = *(tobesigned_crl->u.other_entries.buf + i);
			}
			size = size - encode_len - tobesigned_crl->u.other_entries.len;
			res = res + encode_len + tobesigned_crl->u.other_entries.len;
			return res;
	}
}

/**
 *   data_2  35
 */

u32 crl_2_buf(const crl *crl,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int n;

	if(len < 33){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = crl->version;
	mbuf++;
	size--;
	res++;

	encode_len = signer_identifier_2_buf(&crl->signer,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = tobesigned_crl_2_buf(&crl->unsigned_crl,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	switch(crl->signer.type){
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
			encode_len = signature_2_buf(&crl->signature,mbuf,size,ECDSA_NISTP224_WITH_SHA224);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			encode_len = signature_2_buf(&crl->signature,mbuf,size,ECDSA_NISTP256_WITH_SHA256);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			encode_len = signature_2_buf(&crl->signature,mbuf,size,crl->signer.u.other_algorithm.algorithm);
			if(encode_len < 0)
				return encode_len;
		case CERTIFICATE:
			if(crl->signer.u.certificate.version_and_type == 2){
				encode_len = signature_2_buf(&crl->signature,mbuf,size,
						crl->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
				if(encode_len < 0)
					return encode_len;
			}
			else if(crl->signer.u.certificate.version_and_type == 3){
				encode_len = signature_2_buf(&crl->signature,mbuf,size,
						crl->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
				if(encode_len < 0)
					return encode_len;
			}
			return encode_len + res;
		case CERTIFICATE_CHAIN:
			n = crl->signer.u.certificates.len - 1;
			if((crl->signer.u.certificates.buf + n)->version_and_type == 2){
				encode_len = signature_2_buf(&crl->signature,mbuf,size,
						(crl->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
				if(encode_len < 0)
					return encode_len;
			}
			else if((crl->signer.u.certificates.buf + n)->version_and_type == 3){
				encode_len = signature_2_buf(&crl->signature,mbuf,size,
						(crl->signer.u.certificates.buf + n)->unsigned_certificate.u.no_root_ca.signature_alg);
				if(encode_len < 0)
					return encode_len;
			}
			return encode_len + res;
		default:
			wave_error_printf("signer.type不符 %s %d",__FILE__,__LINE__);
			return -1;
	}
}

/**
 *   data_2  36
 */

u32 tobe_encrypted_certificate_response_acknowledgment_2_buf(const tobe_encrypted_certificate_response_acknowledgment*
		tobe_encrypted_certificate_response_acknowledgment,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	int i;

	if(len < 10){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	for(i=0;i<10;i++){
		*mbuf++ = *(tobe_encrypted_certificate_response_acknowledgment->response_hash + i);
	}
	size -= 10;
	res += 10;
	return res;
}

/**
 *   data_2  37
 */

static u32 tobe_encrypted_certificate_request_error_2_buf(const tobe_encrypted_certificate_request_error*
		tobe_encrypted_certificate_request_error,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 13){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = signer_identifier_2_buf(&tobe_encrypted_certificate_request_error->signer,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	for(i=0;i<10;i++){
		*mbuf++ = *(tobe_encrypted_certificate_request_error->request_hash + i);
	}
	size -= 10;
	res += 10;
	
	*mbuf = tobe_encrypted_certificate_request_error->reason;
	mbuf++;
	size--;
	res++;

	switch(tobe_encrypted_certificate_request_error->signer.u.certificate.version_and_type){
		case 2:
			encode_len = signature_2_buf(&tobe_encrypted_certificate_request_error->signature,mbuf,size,
					tobe_encrypted_certificate_request_error->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case 3:
			encode_len = signature_2_buf(&tobe_encrypted_certificate_request_error->signature,mbuf,size,
					tobe_encrypted_certificate_request_error->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		default:
			wave_error_printf("version_and_type不符 %s %d",__FILE__,__LINE__);
			return res;
	}
}

/**
 *   data_2  38
 */

static u32 tobe_encrypted_certificate_response_2_buf(const tobe_encrypted_certificate_response*
		tobe_encrypted_certificate_response,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	u8* mbuf_beg;
	u8* mbuf_end;
	u32 min_len;
	u32 data_len;
	int i;
	int n;

	if(len < 3){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	min_len = varible_len_calculate(tobe_encrypted_certificate_response->certificate_chain.len*22);
	if (size < min_len + tobe_encrypted_certificate_response->certificate_chain.len*22){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	mbuf_beg = mbuf;
	data_len = 0;
	for(i=0;i < tobe_encrypted_certificate_response->certificate_chain.len;i++){
		encode_len = certificate_2_buf(tobe_encrypted_certificate_response->certificate_chain.buf + i,mbuf,size);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		data_len += encode_len;
	}
	mbuf_end = mbuf;
	size -= data_len;
	res += data_len;

	encode_len = varible_len_calculate(data_len);
	if(size < encode_len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	mbuf = mbuf_end + encode_len;
	while(mbuf_beg != mbuf_end){
		mbuf_end--;
		*(mbuf_end + encode_len) = *mbuf_end;
	}

	varible_len_encoding(mbuf_beg,data_len);

	size -= encode_len;
	res += encode_len;
	
	n = tobe_encrypted_certificate_response->certificate_chain.len - 1;
	switch((tobe_encrypted_certificate_response->certificate_chain.buf + n)->version_and_type){
		case 2:
			break;
		case 3:
			encode_len = varible_len_calculate(tobe_encrypted_certificate_response->u.recon_priv.len);
			if (size < encode_len + tobe_encrypted_certificate_response->u.recon_priv.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobe_encrypted_certificate_response->u.recon_priv.len);
			mbuf += encode_len;

			for(i=0;i < tobe_encrypted_certificate_response->u.recon_priv.len;i++){
				*mbuf++ = *(tobe_encrypted_certificate_response->u.recon_priv.buf + i);
			}
			size = size - encode_len - tobe_encrypted_certificate_response->u.recon_priv.len;
			res = res + encode_len + tobe_encrypted_certificate_response->u.recon_priv.len;
			break;
		default:
			encode_len = varible_len_calculate(tobe_encrypted_certificate_response->u.other_material.len);
			if (size < encode_len + tobe_encrypted_certificate_response->u.other_material.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobe_encrypted_certificate_response->u.other_material.len);
			mbuf += encode_len;

			for(i=0;i < tobe_encrypted_certificate_response->u.other_material.len;i++){
				*mbuf++ = *(tobe_encrypted_certificate_response->u.other_material.buf + i);
			}
			size = size - encode_len - tobe_encrypted_certificate_response->u.other_material.len;
			res = res + encode_len + tobe_encrypted_certificate_response->u.other_material.len;
			break;
	}
	
	min_len = varible_len_calculate(tobe_encrypted_certificate_response->crl_path.len*34);
	if (size < min_len + tobe_encrypted_certificate_response->crl_path.len*34){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	mbuf_beg = mbuf;
	data_len = 0;
	for(i=0;i < tobe_encrypted_certificate_response->crl_path.len;i++){
		encode_len = crl_2_buf(tobe_encrypted_certificate_response->crl_path.buf + i,mbuf,size);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		data_len += encode_len;
	}
	mbuf_end = mbuf;
	size -= data_len;
	res += data_len;

	encode_len = varible_len_calculate(data_len);
	if(size < encode_len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	mbuf = mbuf_end + encode_len;
	while(mbuf_beg != mbuf_end){
		mbuf_end--;
		*(mbuf_end + encode_len) = *mbuf_end;
	}

	varible_len_encoding(mbuf_beg,data_len);

	size -= encode_len;
	res += encode_len;
	
	return res;
}

/**
 *   data_2  39
 */

u32 tobesigned_certificate_request_2_buf(const tobesigned_certificate_request*
		tobesigned_certificate_request,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 17){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = tobesigned_certificate_request->version_and_type;
	mbuf++;
	size--;
	res++;

	tobuf32(mbuf,tobesigned_certificate_request->request_time);
	mbuf += 4;
	size -= 4;
	res += 4;

	*mbuf = tobesigned_certificate_request->holder_type;
	mbuf++;
	size--;
	res++;

	*mbuf = tobesigned_certificate_request->cf;
	mbuf++;
	size--;
	res++;

	encode_len = cert_specific_data_2_buf(&tobesigned_certificate_request->type_specific_data,
			mbuf,size,tobesigned_certificate_request->holder_type);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	tobuf32(mbuf,tobesigned_certificate_request->expiration);
	mbuf += 4;
	size -= 4;
	res += 4;

	if((tobesigned_certificate_request->cf & 1<<0)!=0){
		if((tobesigned_certificate_request->cf & 1<<1)!=0){
			tobuf16(mbuf,tobesigned_certificate_request->flags_content.lifetime);
			mbuf +=2;
			size -=2;
			res += 2;
		}else{
			tobuf32(mbuf,tobesigned_certificate_request->flags_content.start_validity);
			mbuf += 4;
			size -= 4;
			res += 4;
		}
	}

	if((tobesigned_certificate_request->cf & 1<<2)!=0){
		encode_len = public_key_2_buf(&tobesigned_certificate_request->flags_content.encryption_key,mbuf,size);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		size -= encode_len;
		res += encode_len;
	}

	if((tobesigned_certificate_request->cf & 0xf8)!=0){
		encode_len = varible_len_calculate(tobesigned_certificate_request->flags_content.other_cert.len);
		if (size < encode_len + tobesigned_certificate_request->flags_content.other_cert.len){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}
		varible_len_encoding(mbuf,tobesigned_certificate_request->flags_content.other_cert.len);
		mbuf += encode_len;

		for(i=0;i < tobesigned_certificate_request->flags_content.other_cert.len;i++){
			*mbuf++ = *(tobesigned_certificate_request->flags_content.other_cert.buf + i);
		}
		size = size - encode_len - tobesigned_certificate_request->flags_content.other_cert.len;
		res = res + encode_len + tobesigned_certificate_request->flags_content.other_cert.len;
	}
	
	encode_len = public_key_2_buf(&tobesigned_certificate_request->verification_key,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = public_key_2_buf(&tobesigned_certificate_request->response_encryption_key,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	return res;
}

/**
 *   data_2  40
 */

u32 certificate_request_2_buf(const certificate_request *certificate_request,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	if(len < 28){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = signer_identifier_2_buf(&certificate_request->signer,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = tobesigned_certificate_request_2_buf(&certificate_request->unsigned_csr,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	switch(certificate_request->signer.type){
		case SELF:
			encode_len = signature_2_buf(&certificate_request->signature,mbuf,size,
					certificate_request->unsigned_csr.verification_key.algorithm);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE:
			if(certificate_request->signer.u.certificate.version_and_type == 2){
				encode_len = signature_2_buf(&certificate_request->signature,mbuf,size,
						certificate_request->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
				if(encode_len < 0)
					return encode_len;
			}
			else if(certificate_request->signer.u.certificate.version_and_type == 3){
				encode_len = signature_2_buf(&certificate_request->signature,mbuf,size,
						certificate_request->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
				if(encode_len < 0)
					return encode_len;
			}
			return encode_len + res;
		default:
			wave_error_printf("signer.type不符 %s %d",__FILE__,__LINE__);
			return -1;
	}
}

/**
 *   data_2  41
 */

u32 tobesigned_data_2_buf(const tobesigned_data *tobesigned_data,u8* buf,u32 len,content_type type){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	u8* mbuf_beg;
	u8* mbuf_end;
	u32 min_len;
	int i;

	if(len < 28){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = tobesigned_data->tf;
	mbuf++;
	size--;
	res++;

	switch(type){
		case SIGNED:
			encode_len = psid_encoding(mbuf,&tobesigned_data->u.type_signed.psid);
			if(encode_len < 0)
				return encode_len;
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;
		   
			encode_len = varible_len_calculate(tobesigned_data->u.type_signed.data.len);
			if (size < encode_len + tobesigned_data->u.type_signed.data.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_data->u.type_signed.data.len);
			mbuf += encode_len;

			for(i=0;i < tobesigned_data->u.type_signed.data.len;i++){
				*mbuf++ = *(tobesigned_data->u.type_signed.data.buf + i);
			}
			size = size - encode_len - tobesigned_data->u.type_signed.data.len;
			res = res + encode_len + tobesigned_data->u.type_signed.data.len;
			break;

		case SIGNED_PARTIAL_PAYLOAD:
			encode_len = psid_encoding(mbuf,&tobesigned_data->u.type_signed_partical.psid);
			if(encode_len < 0)
				return encode_len;
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;
			
			encode_len = varible_len_calculate(tobesigned_data->u.type_signed_partical.ext_data.len);
			if (size < encode_len + tobesigned_data->u.type_signed_partical.ext_data.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_data->u.type_signed_partical.ext_data.len);
			mbuf += encode_len;

			for(i=0;i < tobesigned_data->u.type_signed_partical.ext_data.len;i++){
				*mbuf++ = *(tobesigned_data->u.type_signed_partical.ext_data.buf + i);
			}
			size = size - encode_len - tobesigned_data->u.type_signed_partical.ext_data.len;
			res = res + encode_len + tobesigned_data->u.type_signed_partical.ext_data.len;

			encode_len = varible_len_calculate(tobesigned_data->u.type_signed_partical.data.len);
			if (size < encode_len + tobesigned_data->u.type_signed_partical.data.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_data->u.type_signed_partical.data.len);
			mbuf += encode_len;

			for(i=0;i < tobesigned_data->u.type_signed_partical.data.len;i++){
				*mbuf++ = *(tobesigned_data->u.type_signed_partical.data.buf + i);
			}
			size = size - encode_len - tobesigned_data->u.type_signed_partical.data.len;
			res = res + encode_len + tobesigned_data->u.type_signed_partical.data.len;
			break;

		case SIGNED_EXTERNAL_PAYLOAD:
			encode_len = psid_encoding(mbuf,&tobesigned_data->u.type_signed_external.psid);
			if(encode_len < 0)
				return encode_len;
			mbuf += encode_len;
			size -= encode_len;
			res += encode_len;

			encode_len = varible_len_calculate(tobesigned_data->u.type_signed_external.ext_data.len);
			if (size < encode_len + tobesigned_data->u.type_signed_external.ext_data.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_data->u.type_signed_external.ext_data.len);
			mbuf += encode_len;

			for(i=0;i < tobesigned_data->u.type_signed_external.ext_data.len;i++){
				*mbuf++ = *(tobesigned_data->u.type_signed_external.ext_data.buf + i);
			}
			size = size - encode_len - tobesigned_data->u.type_signed_external.ext_data.len;
			res = res + encode_len + tobesigned_data->u.type_signed_external.ext_data.len;

			break;
		default:
			encode_len = varible_len_calculate(tobesigned_data->u.data.len);
			if (size < encode_len + tobesigned_data->u.data.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobesigned_data->u.data.len);
			mbuf += encode_len;

			for(i=0;i < tobesigned_data->u.data.len;i++){
				*mbuf++ = *(tobesigned_data->u.data.buf + i);
			}
			size = size - encode_len - tobesigned_data->u.data.len;
			res = res + encode_len + tobesigned_data->u.data.len;
			break;
	}
	
	if((tobesigned_data->tf & 1<<0)!=0){
		encode_len = time64_with_standard_deviation_2_buf(&tobesigned_data->flags_content.generation_time,mbuf,size);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		size -= encode_len;
		res += encode_len;
	}

	if((tobesigned_data->tf & 1<<1)!=0){
		tobuf64(mbuf,tobesigned_data->flags_content.exipir_time);
		mbuf += 8;
		size -= 8;
		res += 8;
	}
	
	if((tobesigned_data->tf & 1<<2)!=0){
		encode_len = three_d_location_2_buf(&tobesigned_data->flags_content.generation_location,mbuf,size);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		size -= encode_len;
		res += encode_len;
	}
	
	if((tobesigned_data->tf & 1<<3)!=0){
		min_len = varible_len_calculate(tobesigned_data->flags_content.extensions.len*2);
		if (size < min_len + tobesigned_data->flags_content.extensions.len*2){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}

		mbuf_beg = mbuf;
		u32 data_len = 0;
		for(i=0;i < tobesigned_data->flags_content.extensions.len;i++){
			encode_len = tbsdata_extension_2_buf(tobesigned_data->flags_content.extensions.buf + i,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			mbuf += encode_len;
			data_len += encode_len;
		}
		mbuf_end = mbuf;
		size -= data_len;
		res += data_len;

		encode_len = varible_len_calculate(data_len);
		if(size < encode_len){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}

		mbuf = mbuf_end + encode_len;
		while(mbuf_beg != mbuf_end){
			mbuf_end--;
			*(mbuf_end + encode_len) = *mbuf_end;
		}

		varible_len_encoding(mbuf_beg,data_len);

		size -= encode_len;
		res += encode_len;	
	}

	if((tobesigned_data->tf & 0xf0)!=0){
		encode_len = varible_len_calculate(tobesigned_data->flags_content.other_data.len);
		if (size < encode_len + tobesigned_data->flags_content.other_data.len){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}
		varible_len_encoding(mbuf,tobesigned_data->flags_content.other_data.len);
		mbuf += encode_len;
	
		for(i=0;i < tobesigned_data->flags_content.other_data.len;i++){
			*mbuf++ = *(tobesigned_data->flags_content.other_data.buf + i);
		}
		size = size - encode_len - tobesigned_data->flags_content.other_data.len;
		res = res + encode_len + tobesigned_data->flags_content.other_data.len;
	}
	
	return res;
}

/**
 *   data_2  42
 */

u32 signed_data_2_buf(const signed_data *signed_data,u8* buf,u32 len,content_type type){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int n;

	if(len < 30){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = signer_identifier_2_buf(&signed_data->signer,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;
	
	encode_len = tobesigned_data_2_buf(&signed_data->unsigned_data,mbuf,size,type);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	switch(signed_data->signer.type){
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
			encode_len = signature_2_buf(&signed_data->signature,mbuf,size,ECDSA_NISTP224_WITH_SHA224);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			encode_len = signature_2_buf(&signed_data->signature,mbuf,size,ECDSA_NISTP256_WITH_SHA256);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			encode_len = signature_2_buf(&signed_data->signature,mbuf,size,
					signed_data->signer.u.other_algorithm.algorithm);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE:
			if(signed_data->signer.u.certificate.version_and_type == 2){
				encode_len = signature_2_buf(&signed_data->signature,mbuf,size,
						signed_data->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
				if(encode_len < 0)
					return encode_len;
				return encode_len + res;
			}
			else if(signed_data->signer.u.certificate.version_and_type == 3){
				encode_len = signature_2_buf(&signed_data->signature,mbuf,size,
						signed_data->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
				if(encode_len < 0)
					return encode_len;
				return encode_len + res;
			}
		case CERTIFICATE_CHAIN:
			n = signed_data->signer.u.certificates.len - 1;
			if((signed_data->signer.u.certificates.buf + n)->version_and_type == 2){
				encode_len = signature_2_buf(&signed_data->signature,mbuf,size,
						(signed_data->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
				if(encode_len < 0)
					return encode_len;
				return encode_len + res;
			}
			else if((signed_data->signer.u.certificates.buf + n)->version_and_type == 3){
				encode_len = signature_2_buf(&signed_data->signature,mbuf,size,
						(signed_data->signer.u.certificates.buf + n)->unsigned_certificate.u.no_root_ca.signature_alg);
				if(encode_len < 0)
					return encode_len;
				return encode_len + res;
			}
		default:
			wave_error_printf("signer.type不符 %s %d",__FILE__,__LINE__);
			return -1;
	}
}

/**
 *   data_2  43
 */

u32 tobe_encrypted_2_buf(const tobe_encrypted *tobe_encrypted,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 2){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = tobe_encrypted->type;
	mbuf++;
	size--;
	res++;

	switch(tobe_encrypted->type){
		case UNSECURED:
			encode_len = varible_len_calculate(tobe_encrypted->u.plain_text.len);
			if (size < encode_len + tobe_encrypted->u.plain_text.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobe_encrypted->u.plain_text.len);
			mbuf += encode_len;

			for(i=0;i < tobe_encrypted->u.plain_text.len;i++){
				*mbuf++ = *(tobe_encrypted->u.plain_text.buf + i);
			}
			size = size - encode_len - tobe_encrypted->u.plain_text.len;
			res = res + encode_len + tobe_encrypted->u.plain_text.len;
			return res;
		case SIGNED:
		case SIGNED_EXTERNAL_PAYLOAD:
		case SIGNED_PARTIAL_PAYLOAD:
			encode_len = signed_data_2_buf(&tobe_encrypted->u.signed_data,mbuf,size,tobe_encrypted->type);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE_REQUEST:
			encode_len = certificate_request_2_buf(&tobe_encrypted->u.request,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFICATE_RESPONSE:
			encode_len = tobe_encrypted_certificate_response_2_buf(&tobe_encrypted->u.response,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case ANOYMOUS_CERTIFICATE_RESPONSE:
			*mbuf = tobe_encrypted->u.anon_response;
			return res + 1;
		case CERTIFICATE_REQUSET_ERROR:
			encode_len = tobe_encrypted_certificate_request_error_2_buf(&tobe_encrypted->u.request_error,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CONTENT_TYPE_CRL_REQUEST:
			encode_len = crl_request_2_buf(&tobe_encrypted->u.crl_request,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CRL:
			encode_len = crl_2_buf(&tobe_encrypted->u.crl,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		case CERTIFACATE_RESPONSE_ACKNOWLEDGMENT:
			encode_len = tobe_encrypted_certificate_response_acknowledgment_2_buf(&tobe_encrypted->u.ack,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		default:
			encode_len = varible_len_calculate(tobe_encrypted->u.data.len);
			if (size < encode_len + tobe_encrypted->u.data.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,tobe_encrypted->u.data.len);
			mbuf += encode_len;

			for(i=0;i < tobe_encrypted->u.data.len;i++){
				*mbuf++ = *(tobe_encrypted->u.data.buf + i);
			}
			size = size - encode_len - tobe_encrypted->u.data.len;
			res = res + encode_len + tobe_encrypted->u.data.len;
			return res;
	}
}

/**
 *   data_2  44
 */

static u32 aes_ccm_ciphertext_2_buf(const aes_ccm_ciphertext *aes_ccm_ciphertext,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 13){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	for(i=0;i<12;i++){
		*mbuf++ = *(aes_ccm_ciphertext->nonce + i);
	}
	size -= 12;
	res += 12;

	encode_len = varible_len_calculate(aes_ccm_ciphertext->ccm_ciphertext.len);
	if (size < encode_len + aes_ccm_ciphertext->ccm_ciphertext.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,aes_ccm_ciphertext->ccm_ciphertext.len);
	mbuf += encode_len;

	for(i=0;i < aes_ccm_ciphertext->ccm_ciphertext.len;i++){
		*mbuf++ = *(aes_ccm_ciphertext->ccm_ciphertext.buf + i);
	}
	size = size - encode_len - aes_ccm_ciphertext->ccm_ciphertext.len;
	res = res + encode_len + aes_ccm_ciphertext->ccm_ciphertext.len;

	return res;
}

/**
 *   data_2  45
 */

static u32 ecies_nist_p256_encrypted_key_2_buf(const ecies_nist_p256_encrypted_key *ecies_nist_p256_encrypted_key,
		u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 50){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = elliptic_curve_point_2_buf(&ecies_nist_p256_encrypted_key->v,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	encode_len = varible_len_calculate(ecies_nist_p256_encrypted_key->c.len);
	if (size < encode_len + ecies_nist_p256_encrypted_key->c.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,ecies_nist_p256_encrypted_key->c.len);
	mbuf += encode_len;

	for(i=0;i < ecies_nist_p256_encrypted_key->c.len;i++){
		*mbuf++ = *(ecies_nist_p256_encrypted_key->c.buf + i);
	}
	size = size - encode_len - ecies_nist_p256_encrypted_key->c.len;
	res = res + encode_len + ecies_nist_p256_encrypted_key->c.len;
	
	for(i=0;i<20;i++){
		*mbuf++ = *(ecies_nist_p256_encrypted_key->t + i);
	}
	size -= 20;
	res += 20;
	return res;
}

/**
 *   data_2  46
 */

static u32 recipient_info_2_buf(const recipient_info *recipient_info,u8* buf,u32 len,pk_algorithm algorithm){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int i;

	if(len < 9){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = hashedid8_2_buf(&recipient_info->cert_id,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	switch(algorithm){
		case ECIES_NISTP256:
			encode_len = ecies_nist_p256_encrypted_key_2_buf(&recipient_info->u.enc_key,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		default:
			encode_len = varible_len_calculate(recipient_info->u.other_enc_key.len);
			if (size < encode_len + recipient_info->u.other_enc_key.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,recipient_info->u.other_enc_key.len);
			mbuf += encode_len;

			for(i=0;i < recipient_info->u.other_enc_key.len;i++){
				*mbuf++ = *(recipient_info->u.other_enc_key.buf + i);
			}
			size = size - encode_len - recipient_info->u.other_enc_key.len;
			res = res + encode_len + recipient_info->u.other_enc_key.len;
			return res;
	}
}

/**
 *   data_2  47
 *   @recipient_info_2_buf 本协议仅支持ECIES_NISTP256,其他算法暂不考虑
 */

u32 encrypted_data_2_buf(const encrypted_data *encrypted_data,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	u8* mbuf_beg;
	u8* mbuf_end;
	u32 min_len;
	int i;

	if(len < 3){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	*mbuf = encrypted_data->symm_algorithm;
	mbuf++;
	size--;
	res++;
	
	min_len = varible_len_calculate(encrypted_data->recipients.len*9);
	if (size < min_len + encrypted_data->recipients.len*9){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	mbuf_beg = mbuf;
	u32 data_len = 0;
	for(i=0;i < encrypted_data->recipients.len;i++){
		encode_len = recipient_info_2_buf(encrypted_data->recipients.buf + i,mbuf,size,ECIES_NISTP256);
		if(encode_len < 0)
			return encode_len;
		mbuf += encode_len;
		data_len += encode_len;
	}
	mbuf_end = mbuf;
	size -= data_len;
	res += data_len;

	encode_len = varible_len_calculate(data_len);
	if(size < encode_len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	mbuf = mbuf_end + encode_len;
	while(mbuf_beg != mbuf_end){
		mbuf_end--;
		*(mbuf_end + encode_len) = *mbuf_end;
	}

	varible_len_encoding(mbuf_beg,data_len);

	size -= encode_len;
	res += encode_len;
	
	switch(encrypted_data->symm_algorithm){
		case AES_128_CCM:
			encode_len = aes_ccm_ciphertext_2_buf(&encrypted_data->u.ciphertext,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			return encode_len + res;
		default:
			encode_len = varible_len_calculate(encrypted_data->u.other_ciphertext.len);
			if (size < encode_len + encrypted_data->u.other_ciphertext.len){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
				return NOT_ENOUGHT;
			}
			varible_len_encoding(mbuf,encrypted_data->u.other_ciphertext.len);
			mbuf += encode_len;

			for(i=0;i < encrypted_data->u.other_ciphertext.len;i++){
				*mbuf++ = *(encrypted_data->u.other_ciphertext.buf + i);
			}
			size = size - encode_len - encrypted_data->u.other_ciphertext.len;
			res = res + encode_len + encrypted_data->u.other_ciphertext.len;
			return res;
	}
}

/**
 *   data_2  48
 */

u32 tobesigned_wsa_2_buf(const tobesigned_wsa *tobesigned_wsa,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	u8* mbuf_beg;
	u8* mbuf_end;
	u32 min_len;
	int i;

	if(len < 30){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = varible_len_calculate(tobesigned_wsa->permission_indices.len);
	if (size < encode_len + tobesigned_wsa->permission_indices.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,tobesigned_wsa->permission_indices.len);
	mbuf += encode_len;

	for(i=0;i < tobesigned_wsa->permission_indices.len;i++){
		*mbuf++ = *(tobesigned_wsa->permission_indices.buf + i);
	}
	size = size - encode_len - tobesigned_wsa->permission_indices.len;
	res = res + encode_len + tobesigned_wsa->permission_indices.len;
	
	*mbuf = tobesigned_wsa->tf;
	mbuf++;
	size--;
	res++;

	encode_len = varible_len_calculate(tobesigned_wsa->data.len);
	if (size < encode_len + tobesigned_wsa->data.len){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}
	varible_len_encoding(mbuf,tobesigned_wsa->data.len);
	mbuf += encode_len;

	for(i=0;i < tobesigned_wsa->data.len;i++){
		*mbuf++ = *(tobesigned_wsa->data.buf + i);
	}
	size = size - encode_len - tobesigned_wsa->data.len;
	res = res + encode_len + tobesigned_wsa->data.len;

	encode_len = time64_with_standard_deviation_2_buf(&tobesigned_wsa->generation_time,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	tobuf64(mbuf,tobesigned_wsa->expire_time);
	mbuf += 8;
	size -= 8;
	res += 8;

	encode_len = three_d_location_2_buf(&tobesigned_wsa->generation_location,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;
	
	if((tobesigned_wsa->tf & 1<<3)!=0){
		min_len = varible_len_calculate(tobesigned_wsa->flags_content.extension.len*2);
		if (size < min_len + tobesigned_wsa->flags_content.extension.len*2){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}
	
		mbuf_beg = mbuf;
		u32 data_len = 0;
		for(i=0;i < tobesigned_wsa->flags_content.extension.len;i++){
			encode_len = tbsdata_extension_2_buf(tobesigned_wsa->flags_content.extension.buf + i,mbuf,size);
			if(encode_len < 0)
				return encode_len;
			mbuf += encode_len;
			data_len += encode_len;
		}
		mbuf_end = mbuf;
		size -= data_len;
		res += data_len;

		encode_len = varible_len_calculate(data_len);
		if(size < encode_len){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}

		mbuf = mbuf_end + encode_len;
		while(mbuf_beg != mbuf_end){
			mbuf_end--;
			*(mbuf_end + encode_len) = *mbuf_end;
		}

		varible_len_encoding(mbuf_beg,data_len);

		size -= encode_len;
		res += encode_len; 
	}
	
	if((tobesigned_wsa->tf & 0xf0)!=0){
		encode_len = varible_len_calculate(tobesigned_wsa->flags_content.other_data.len);
		if (size < encode_len + tobesigned_wsa->flags_content.other_data.len){
			wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
			return NOT_ENOUGHT;
		}
		varible_len_encoding(mbuf,tobesigned_wsa->flags_content.other_data.len);
		mbuf += encode_len;

		for(i=0;i < tobesigned_wsa->flags_content.other_data.len;i++){
			*mbuf++ = *(tobesigned_wsa->flags_content.other_data.buf + i);
		}
		size = size - encode_len - tobesigned_wsa->flags_content.other_data.len;
		res = res + encode_len + tobesigned_wsa->flags_content.other_data.len;
	}

	return res;
}

/**
 *   data_2  49
 */

u32 signed_wsa_2_buf(const signed_wsa *signed_wsa,u8* buf,u32 len){
	u8* mbuf = buf;
	u32 size = len;
	u32 res = 0;
	u32 encode_len;
	int n;

	if(len < 32){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
		return NOT_ENOUGHT;
	}

	encode_len = signer_identifier_2_buf(&signed_wsa->signer,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;
	
	encode_len = tobesigned_wsa_2_buf(&signed_wsa->unsigned_wsa,mbuf,size);
	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	n = signed_wsa->signer.u.certificates.len - 1;
	if((signed_wsa->signer.type == CERTIFICATE_CHAIN) &&
		((signed_wsa->signer.u.certificates.buf + n)->version_and_type == 2)){
		encode_len = signature_2_buf(&signed_wsa->signature,mbuf,size,
				(signed_wsa->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
	}else{
		encode_len = signature_2_buf(&signed_wsa->signature,mbuf,size,
				ECDSA_NISTP256_WITH_SHA256);
	}

	if(encode_len < 0)
		return encode_len;
	mbuf += encode_len;
	size -= encode_len;
	res += encode_len;

	return res;
}

/**
 *   data_2  50
 */

u32 sec_data_2_buf(sec_data *sec_data,u8* buf,u32 len){
    u8* mbuf = buf;
    u32 size = len;
    u32 res = 0;
	u32 encode_len;
	int i;

    if(len < 3){
		wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
        return NOT_ENOUGHT;
	}

    *mbuf = sec_data->protocol_version;
    mbuf++;
    size--;
    res++;

    *mbuf = sec_data->type;
    mbuf++;
    size--;
    res++;
    switch(sec_data->type){
        case UNSECURED:
            encode_len = varible_len_calculate(sec_data->u.data.len);
            if(encode_len + sec_data->u.data.len > size){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
                return NOT_ENOUGHT;
			}
            varible_len_encoding(mbuf,sec_data->u.data.len);
            mbuf += encode_len;
            
            for(i=0;i<sec_data->u.data.len;i++){
                *mbuf++ = *(sec_data->u.data.buf +i);
            }
            size = size - encode_len - sec_data->u.data.len;
            res = res + encode_len + sec_data->u.data.len;
            return res;

        case SIGNED:
        case SIGNED_EXTERNAL_PAYLOAD:
		case SIGNED_PARTIAL_PAYLOAD:
            encode_len = signed_data_2_buf(&sec_data->u.signed_data,mbuf,size,sec_data->type);
            if(encode_len < 0)
                return encode_len;
            return encode_len + res;
        case SIGNED_WSA:
//			signed_wsa_free(&sec_data->u.signed_wsa);
            encode_len = signed_wsa_2_buf(&sec_data->u.signed_wsa,mbuf,size);
            if(encode_len < 0)
                 return encode_len;
            return encode_len + res;
        case ENCRYPTED:
            encode_len = encrypted_data_2_buf(&sec_data->u.encrypted_data,mbuf,size);
            if(encode_len < 0)
                return encode_len;
            return encode_len + res;
        case CONTENT_TYPE_CRL_REQUEST:
            encode_len = crl_request_2_buf(&sec_data->u.crl_request,mbuf,size);
            if(encode_len < 0)
                return encode_len;
            return encode_len + res;
        case CRL:
            encode_len = crl_2_buf(&sec_data->u.crl,mbuf,size);
            if(encode_len < 0)
                return encode_len;
            return encode_len + res;
        default:
            encode_len = varible_len_calculate(sec_data->u.other_data.len);
            if(encode_len + sec_data->u.other_data.len > size){
				wave_error_printf("buf空间不够 %s %d",__FILE__,__LINE__);
                return NOT_ENOUGHT;
			}
            varible_len_encoding(mbuf,sec_data->u.other_data.len);
            mbuf += encode_len;
            
            for(i=0;i<sec_data->u.other_data.len;i++){
                *mbuf++ = *(sec_data->u.other_data.buf +i);
            }
            size = size - encode_len - sec_data->u.other_data.len;
            res = res + encode_len + sec_data->u.other_data.len;
            return res;
    }   
}
