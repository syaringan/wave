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
# Description:  将buf转换成结构体
#
=============================================================================*/
#include"data_handle.h"
#include"stddef.h"

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
    value = host_to_be32(value);
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
    u64 size = 0x000000f000000000;
    size = size | len;
    size = host_to_be64(size);
    *buf++ = getchar4(size);
    *buf++ = getchar5(size);
    *buf++ = getchar6(size);
    *buf++ = getchar7(size);
    *buf++ = getchar8(size);
}
static void varible_len6_encoding(u8* buf,u64 len){//同上 小于42次方
    u64 size = 0x0000f80000000000;
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
    u64 size = 0x00fc000000000000;
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
    u64 size = 0xfe00000000000000;
    size = size | len;
    tobuf64(buf,size);
}
static void  varible_len_encoding(u8* buf,u64 len){//对Variable length的length进行编码 
    if(len < 2<<7){
        varible_len1_encoding(u8* buf,(u8)len);
        return ;
    }
    if(len < 2<<14){
        varible_len2_encoding(u8* buf,(u16)len);
        return ;
    }
    if(len < 2<<21){
        varible_len3_encoding(u8* buf,(u32)len);
        return ;
    }
    if(len < 2<<28){
        varible_len4_encoding(u8* buf,(u32)len);
        return ;
    }
    if(len < 2<<35){
        varible_len5_encoding(u8* buf,(u64)len);
        return ;
    }
    if(len < 2<<42){
        varible_len6_encoding(u8* buf,(u64)len);
        return ;
    }
    if(len < 2<<49){
        varible_len7_encoding(u8* buf,(u64)len);
        return ;
    }
    varible_len8_encoding(u8* buf,(u64)len);
    return ;
        
}
static u32 varible_len_calculate(u8* buf,u64 len){ //  
    if(len < 2<<7){
        return 1;
    }
    if(len < 2<<14){
        return 2;
    }
    if(len < 2<<21){
        return 3;
    }
    if(len < 2<<28){
        return 4;
    }
    if(len < 2<<35){
        return 5;
    }
    if(len < 2<<42){
        return 6;
    }
    if(len < 2<<49){
        return 7;
    }
    return 8;
}



/**
 *	to_buf 1
 */
static u32 time64_with_standard_deviation_2_buf(const time64_with_standard_deviation* 
				time64_with_standard_deviation, u8* buf, u32 len){
	u8* mbuf = buf;
	u32 size = len;
	tobuf64(mbuf, time64_with_standard_deviation->time);
	if(size < 5)
		return 0;
	mbuf += 4;
	size -= 4;
	*mbuf = time64_with_standard_deviation->long_std_dev
	mbuf += 1;
	size -= 1;
	return len - size;
}
/**
 * to_buf 2
 */
static u32 tbsdata_extension_2_buf(const tbsdata_extension* tbsdata_extension,
				u8* buf, u32 len){
	u8* mbuf = buf;
	u32 size = len;
	*mbuf = (u8)tbsdata_extension->type;
	mbuf++;
	size--;
	
	u32 encode_length = varible_len_calculate(mbuf, tbsdata_extension->value.len);
	if(size < encode_length + tbsdata_extension->value.len)
		return NOT_ENOUTGHT;
	varilbe_len_encoding(mbuf, tbsdata_extension->value.len);
	mbuf += encode_length;
	
	
		
	
	
	
}






u32 sec_data_2_buf(const sec_data *sec_data,u8* buf,u32 len){
    u8* mbuf = buf;
    u32 size = len;
    u32 res = 0;
    if(len < 4)
        return NOT_ENOUGHT;

    *mbuf = sec_data->protocol_version;
    mbuf++;
    size--;
    res++;

    tobuf16(mbuf,sec_data->type);
    mbuf = mbuf + 2;
    size = size - 2;
    res  = res + 2;
    switch(sec_data->type){
        case UNSECURED:
            u32 encode_len = varible_len_calculate(sec_data->u.data.len);
            if(encode_len + sec_data->u.data.len > size)
                return NOT_ENOUGHT;
            varible_len_encoding(mbuf,sec_data->u.data.len);
            mbuf += encode_len;
            
            for(int i=0;i<sec_data->u.data.len;i++){
                *mbuf++ = *(sec_data->u.data.buf +i);
            }
            size = size - encode_len - sec_data->u.data.len;
            res = res + encode_len + sec_data->u.data.len;
            return res;
        case SIGNED:
        case SIGNED_EXTERNAL_PAYLOAD:
        case SIGNED_PARTIAL_PAYLOAD:
            u32 encode_len = signed_data_2_buf(&sec_data->u.signed_data,mbuf,size);
            if(encode_len < 0)
                return encode_len;
            return encode_len + res;
        case SIGNED_WSA:
            signed_wsa_free(&sec_data->u.signed_wsa);
            u32 encode_len = signed_wsa_2_buf(&sec_data->u.signed_wsa,mbuf,size);
            if(encode_len < 0)
                 return encode_len;
            return encode_len + res;
        case ENCRYPTED:
            u32 encode_len = encrypted_data_2_buf(&sec_data->u.encrypted_data,mbuf,size);
            if(encode_len < 0)
                return encode_len;
            return encode_len + res;
        case CONTENT_TYPE_CRL_REQUEST:
            u32 encode_len = crl_request_2_buf(&sec_data->u.crl_request,mbuf,size);
            if(encode_len < 0)
                return encode_len;
            return encode_len + res;
        case CRL:
            u32 encode_len = crl_2_buf(&sec_data->u.crl,mbuf,size);
            if(encode_len < 0)
                return encode_len;
            return encode_len + res;
        default:
            u32 encode_len = varible_len_calculate(sec_data->u.other_data.len);
            if(encode_len + sec_data->u.other_data.len > size)
                return NOT_ENOUGHT;
            varible_len_encoding(mbuf,sec_data->u.other_data.len);
            mbuf += encode_len;
            
            for(int i=0;i<sec_data->u.other_data.len;i++){
                *mbuf++ = *(sec_data->u.other_data.buf +i);
            }
            size = size - encode_len - sec_data->u.other_data.len;
            res = res + encode_len + sec_data->u.other_data.len;
            return res;
    }   
}
