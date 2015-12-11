/*=============================================================================
#
# Author: 杨广华 - edesale@qq.com
#
# QQ : 374970456
#
# Last modified: 2015-10-12 21:55
#
# Filename: buf_2_data.c
#
# Description:将buf中的信息填充到结构体中
# 
#	命名规则为:buf_2_sturct(const u8* buf, const u32 len, struct*)
#   其中buf为将要被填充的字节流，len为字节流buf大小，struct为将要填充的结构体
#	函数返回值 0， 填充失败； 大于0， 填充了多少字节
=============================================================================*/
#include"data_handle.h"
#include"utils/debug.h"
#include<stdlib.h>
#include<stddef.h>

#define get8(addr)  *( (u8*)addr  )
#define get16(addr) *( (u16*)addr )
#define get32(addr) *( (u32*)addr )
#define get64(addr) *( (u64*)addr )


/**	向array 中 buf所指向的内存填充
 *	@array_buf  array_buf指向需要被填充的内存的首地址，
 *	@mbuf mbuf指向将要被填充进buf所指向内存的网络流的首地址
 *	@len 所需要填充的个数
 *	YGH
 */

static void fill_buf8(u8* array_buf, u8* mbuf, u16 len){
	u16 i;
	for(i = 0; i< len;i++){
		*array_buf = *mbuf;
		array_buf++;
		mbuf++;
	}
}
/**获取变长编码variable-length vectors with variable-length length enconding （协议6.1.6.2节）的头部ll段的编码bit位数 
 *	@mbuf 表示长度的网络流的首地址
 *  返回值：数据的长度，类型为U16，data.h 中定义len类型为u16
 *  YGH
 */
static u16 head_bit_num(u8* mbuf){
	u8 ll;
	ll = get8(mbuf);
	if(ll <= 0x7f)
		return 1;
	else if(ll <= 0xbf)
		return 2;
	else if(ll <= 0xdf)
		return 3;
	else if(ll <= 0xef)
		return 4;
	else if(ll <= 0xf7)
		return 5; 
	else if(ll <= 0xfb)
		return 6;
	else if(ll <= 0xfd)
		return 7;
	else if(ll <= 0xfe)
		return 8;
}

/*
static u16 flag_length(u8* mbuf){
	u8 length;
	length = get4(mbuf);
	if(length<=0x07)
		return 1;
	else if(length <=0x0b )
		return 2;
	else if(length<=0x0d)
		return 3;
	else if(length<=0x0e)
		return 4;
}
*/
/** 计算variable-length vectors with variable-length length enconding中 数据的个数
 *	@full_encoding_length数据个数
 *	@mbuf 头部的起始地址
 *	返回值： 头部长度
 *	YGH
 */
static u32 variablelength_data_num(u8* mbuf,u16 full_encoding_length){
	u16 full_encoding_length16;
	u32 full_encoding_length32;
	u64 full_encoding_length64;
	switch(full_encoding_length){
		case 1:
			full_encoding_length16 = get16(mbuf);
			full_encoding_length16 = be_to_host16(full_encoding_length16);
			full_encoding_length16 = full_encoding_length16>>8;
			return full_encoding_length16;
		case 2:
			full_encoding_length16 = get16(mbuf);
			full_encoding_length16 = be_to_host16(full_encoding_length16);
			return full_encoding_length16 & 0x3fff;
		case 3:
			full_encoding_length32 = get32(mbuf);
			full_encoding_length32 = be_to_host32(full_encoding_length32);
			full_encoding_length32 = full_encoding_length32>>8;
			full_encoding_length32 = full_encoding_length32 & 0x003fffff;
			return (u16)full_encoding_length32;
		case 4:
			full_encoding_length32 = get32(mbuf);
			full_encoding_length32 = be_to_host32(full_encoding_length32);
			full_encoding_length32 = full_encoding_length32;
			full_encoding_length32 = full_encoding_length32 & 0x0fffffff;
			return (u16)full_encoding_length32;
		case 5:
			full_encoding_length64 = get64(mbuf);
			full_encoding_length64 = be_to_host64(full_encoding_length64);
			full_encoding_length64 = full_encoding_length64 >> 24;
			full_encoding_length64 = full_encoding_length64 & 0x00000007ffffffffull;
			return (u16)full_encoding_length64;
		case 6:
			full_encoding_length64 = get64(mbuf);
			full_encoding_length64 = be_to_host64(full_encoding_length64);
			full_encoding_length64 = full_encoding_length64 >> 16;
			full_encoding_length64 = full_encoding_length64 & 0x000003ffffffffffull;
			return (u16)full_encoding_length64;
		case 7:
			full_encoding_length64 = get64(mbuf);
			full_encoding_length64 = be_to_host64(full_encoding_length64);
			full_encoding_length64 = full_encoding_length64 >> 8;
			full_encoding_length64 = full_encoding_length64 & 0x0001ffffffffffffull;
			return (u16)full_encoding_length64;
		case 8:
			full_encoding_length64 = get64(mbuf);
			full_encoding_length64 = be_to_host64(full_encoding_length64);
			full_encoding_length64 = full_encoding_length64 & 0x00ffffffffffffffull;
			return (u16)full_encoding_length64;
	}
}

static u32 psid_decoding(u8* buf,psid* psid){
	u8* mbuf = buf;
	
	if((*buf & 0xf0) == 0xf0){
//		wave_error_printf("psid大于4字节 %s %d",__FILE__,__LINE__);
		wave_error_printf("psid");
		return -1;
	}

	*psid = *mbuf++;
	if((*buf & 1<<7) == 0){	
		return 1;
	}

	*psid = (*psid<<8) + *mbuf++;
	if((*buf & 1<<6) == 0){
		return 2;
	}

	*psid = (*psid<<8) + *mbuf++;
	if((*buf & 1<<5) == 0){
		return 3;
	}else{
		*psid = (*psid<<8) + *mbuf;
		return 4;
	}
}


/**
 * buf_to 1
 */
static u32 buf_2_time64_with_standard_deviation(  u8* buf,   u32 len, 
				time64_with_standard_deviation* time64_with_standard_deviation){
	u8* mbuf = buf;
	u32 size = len;
	//u32 used_length = 0;
	
	if(size < 9){	
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	
	time64_with_standard_deviation->time = get64(mbuf);
	time64_with_standard_deviation->time = be_to_host64(time64_with_standard_deviation->time);  //定义在wave/utils/common.h中
	mbuf += 8;
	size -= 8;
	//used_length += 4;

	time64_with_standard_deviation->long_std_dev = get8(mbuf);
	mbuf += 1;
	size -= 1;
	//used_length += 1;
	
	return len - size;
}
/**
 *	buf_to 2
 */

static u32 buf_2_tbsdata_extension(  u8* buf, const u32 len, tbsdata_extension* tbsdata_extension){
	u8* mbuf = buf;
	u32 size = len;
	u16 bitnum;//代表头部编码长度
	
	if(size < 2){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	tbsdata_extension->type = get8(mbuf);
	mbuf += 1;
	size -= 1;
			

	bitnum = head_bit_num(mbuf);
	tbsdata_extension->value.len = variablelength_data_num(mbuf, bitnum);
	if(size < tbsdata_extension->value.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
		
	mbuf += bitnum;
	size -= bitnum;
	tbsdata_extension->value.buf = (u8*)malloc(sizeof(u8)*tbsdata_extension->value.len);
	if(NULL == tbsdata_extension->value.buf ){
		return -1;
	}
	fill_buf8(buf, mbuf, tbsdata_extension->value.len);
	mbuf+= tbsdata_extension->value.len *sizeof(u8);
	size -= tbsdata_extension->value.len * sizeof(u8);
	return len - size;
}
/**
 *	buf_to 3
 */
static u32 buf_2_three_d_location(  u8* buf,   u32 len, three_d_location* three_d_location){
	u8* mbuf = buf;
	u32 size = len;
	//u32 used_length = 0;

	if(size<10){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	if(size >= 4 ){
		three_d_location->latitude	= get32(mbuf);
		three_d_location->latitude = be_to_host32(three_d_location->latitude);
		mbuf += 4;
		size -= 4;
	//	used_lenth += 4;
	}
	if(size >= 4){
		three_d_location->longitude = get32(mbuf);
		three_d_location->longitude = be_to_host32(three_d_location->longitude);
		mbuf += 4;
		size -= 4;
	//	used_lenth += 4;
	}
	
	if(size >= 2){
		three_d_location->elevation[1] = get8(mbuf);
		mbuf++;
		three_d_location->elevation[2] = get8(mbuf);
		mbuf++;
		size -= 2;
	//	used_lenth += 2;
	}
	return len - size;
}

/**
 *	buf_to 4
 */
u32 buf_2_hashedid8(  u8* buf,  u32 len, hashedid8* hashedid8){
	u8* mbuf = buf; 
	u32 size = len;
	int i;
	if (size < 8){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	for(i = 0; i < 8; i++ ){
		hashedid8->hashedid8[i] = get8(mbuf);
		mbuf++;
		size--;
	}
	return 8;
}

/**
 *	buf_to 5
 *	@pk_algorithm 外部传入参数
 *	@field_size 外部传入参数，注意在填充结构体时，外部传入参数是不需要真正填充进结构体的
 *	因为结构体定义中，并没有extern数据，而且编码中，extern也没有编在buf所指像的网络流中
 */
static u32 buf_2_elliptic_curve_point(  u8* buf,   u32 len, 
				elliptic_curve_point* elliptic_curve_point,pk_algorithm pk_algorithm){

	u8* mbuf = buf;
	u32 size = len;
	u16 bitnum;
	u16 field_size;

	if(size < 29){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	if(pk_algorithm == ECDSA_NISTP224_WITH_SHA224)
		field_size = 28;
	else if((pk_algorithm == ECDSA_NISTP256_WITH_SHA256) || (pk_algorithm == ECIES_NISTP256))
		field_size = 32;
	else {
		wave_error_printf("传入算法错误 %s %d",__FILE__,__LINE__);
		return -1;
	}

	elliptic_curve_point->type = get8(mbuf);
	mbuf++;
	size--;

	elliptic_curve_point->x.len = field_size;

	if(size < elliptic_curve_point->x.len*sizeof(u8)){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	elliptic_curve_point->x.buf = (u8*)malloc(sizeof(u8)* elliptic_curve_point->x.len);
	if(NULL == elliptic_curve_point->x.buf){
		return -1;
	}

	fill_buf8(elliptic_curve_point->x.buf, mbuf, elliptic_curve_point->x.len);
	mbuf += elliptic_curve_point->x.len * sizeof(u8);
	size -= elliptic_curve_point->x.len * sizeof(u8);

	if(elliptic_curve_point->type == UNCOMPRESSED){

		elliptic_curve_point->u.y.len = field_size;

		if(size <elliptic_curve_point->u.y.len*sizeof(u8)){
			wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
			return -1;
		}
		elliptic_curve_point->u.y.buf = (u8*)malloc(sizeof(u8)* elliptic_curve_point->u.y.len);
		if(NULL == elliptic_curve_point->u.y.buf){
			return -1;
		}
		fill_buf8(elliptic_curve_point->u.y.buf, mbuf, elliptic_curve_point->u.y.len);
		mbuf += elliptic_curve_point->u.y.len * sizeof(u8);
		size -= elliptic_curve_point->u.y.len * sizeof(u8);
	}

	return len - size;
}
/**
 *	buf_to 6
 *
 */
static u32 buf_2_ecdsa_signature(  u8* buf,  u32 len,ecdsa_signature* ecdsa_signature, 
		pk_algorithm pk_algorithm){
	u8* mbuf = buf;
	u16 bitnum ;
	u32 size = len;
	u32 elliptic_length;
	u16 field_size;

	if(size<30){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	//协议中未定义ECIES_NISTP256的field_size,推出该值与算法ECDSA_NISTP256_WITH_SHA256相同,
	//因此若算法不为ECDSA_NISTP224_WITH_SHA224,则field_size取32
	if(pk_algorithm == ECDSA_NISTP224_WITH_SHA224)
		field_size = 28;
	else if((pk_algorithm == ECDSA_NISTP256_WITH_SHA256) || (pk_algorithm == ECIES_NISTP256))
		field_size = 32;
	else{
		wave_error_printf("传入算法错误 %s %d",__FILE__,__LINE__);
		return -1;
	}

	elliptic_length = buf_2_elliptic_curve_point(mbuf,size, &ecdsa_signature->r,pk_algorithm);
	if(0 > elliptic_length)
		return -1;
	mbuf += elliptic_length;
	size -= elliptic_length;

	ecdsa_signature->s.len = field_size;

	if(size < ecdsa_signature->s.len*sizeof(u8)){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	ecdsa_signature->s.buf = (u8*)malloc(sizeof(u8)* ecdsa_signature->s.len);
	if(NULL == ecdsa_signature->s.buf){
		return -1;
	}

	fill_buf8(ecdsa_signature->s.buf, mbuf, ecdsa_signature->s.len);
	mbuf += ecdsa_signature->s.len * sizeof(u8);
	size -= ecdsa_signature->s.len * sizeof(u8);

	return len - size;
}


//buf_to 7
static u32 buf_2_signature(  u8* buf,  u32 len,signature* signature,pk_algorithm pk_algorithm){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 ecdsa_signature_length;

	if(size < 1){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	switch(pk_algorithm){
		case ECDSA_NISTP224_WITH_SHA224:
		case ECDSA_NISTP256_WITH_SHA256:
			ecdsa_signature_length=buf_2_ecdsa_signature(mbuf,size,&signature->u.ecdsa_signature,pk_algorithm);
			if(0>ecdsa_signature_length)
				return -1;
			mbuf+=ecdsa_signature_length;
			size-=ecdsa_signature_length;
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			mbuf+=bitnum;
			size-=bitnum;
			signature->u.signature.len=variablelength_data_num(mbuf,bitnum);
			if(size<signature->u.signature.len*sizeof(u8)){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			signature->u.signature.buf=(u8*)malloc(sizeof(u8)*signature->u.signature.len);
			if(NULL == signature->u.signature.buf){
				return -1;
			}
			fill_buf8(signature->u.signature.buf,mbuf,signature->u.signature.len);
			mbuf+=signature->u.signature.len;
			size-=signature->u.signature.len;
			return len-size;
	}
}


//buf_to 8
static u32 buf_2_public_key( u8* buf,  u32 len,public_key* public_key){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 elliptic_length;
	u32 elliptic_length2;

	if(size<2 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	public_key->algorithm=get8(mbuf); 
	mbuf++;
	size--;
 
	switch(public_key->algorithm){
		case ECDSA_NISTP224_WITH_SHA224:
        case ECDSA_NISTP256_WITH_SHA256:
			elliptic_length=buf_2_elliptic_curve_point(mbuf,size,&public_key->u.public_key,public_key->algorithm);
			if(0>elliptic_length)
				return -1;
			mbuf+=elliptic_length;
			size-=elliptic_length;
			return len-size;

		case ECIES_NISTP256:
			public_key->u.ecies_nistp256.supported_symm_alg=get8(mbuf);
			mbuf++;
			size--;
			elliptic_length2=buf_2_elliptic_curve_point(mbuf,size,&public_key->u.ecies_nistp256.public_key,
					ECDSA_NISTP256_WITH_SHA256);//协议中未定义ECIES_NISTP256的field_size,推出该值与算法ECDSA_NISTP256_WITH_SHA256相同
			if(0>elliptic_length2)
				return -1;
			mbuf+=elliptic_length2;
			size-=elliptic_length2;
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			mbuf+=bitnum;
			size-=bitnum;
			public_key->u.other_key.len=variablelength_data_num(mbuf,bitnum);
			if(size<public_key->u.other_key.len*sizeof(u8)){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			public_key->u.other_key.buf=(u8*)malloc(sizeof(u8)*public_key->u.other_key.len);
			if(NULL == public_key->u.other_key.buf){
				return -1;
			}
			fill_buf8(public_key->u.other_key.buf,mbuf,public_key->u.other_key.len);
			mbuf+=public_key->u.other_key.len;
			size-=public_key->u.other_key.len;
			return len-size;
	}
}
    

//buf_2 9
static u32 buf_2_two_d_location(  u8* buf,  u32 len,two_d_location* two_d_location){
	u8*  mbuf=buf;
	u32 size=len;
	
	if(size<8){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
     
	two_d_location->latitude=get32(mbuf);
	two_d_location->latitude=be_to_host32(two_d_location->latitude);
	mbuf+=4;
	size-=4;

	two_d_location->longitude=get32(mbuf);
	two_d_location->longitude=be_to_host32(two_d_location->longitude);
	mbuf+=4;
	size-=4;

	return len-size;

}


//buf_to 10
static u32 buf_2_rectangular_region(u8* buf, u32 len,rectangular_region* rectangular_region){
  u8* mbuf=buf;
  u32 size=len;
  u32 rectangular_length1;
  u32 rectangular_length2;

  if(size < 16){
	  wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
	  return -1;
  }

  rectangular_length1=buf_2_two_d_location(mbuf,size,&rectangular_region->north_west);
  if(0>rectangular_length1)
	  return -1;
  mbuf+=rectangular_length1;
  size-=rectangular_length1;

  rectangular_length2=buf_2_two_d_location(mbuf,size,&rectangular_region->south_east);
  if(0>rectangular_length2)
	  return -1;
  mbuf+=rectangular_length2;
  size-=rectangular_length2;

  return len-size;
}
  

//buf_to 11
static u32 buf_2_circular_region(  u8* buf,  u32 len,circular_region* circular_region){
  u8* mbuf=buf;
  u32 size=len;
  u32 two_length;

  if(size < 10){
	  wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
	  return -1;
  }

  two_length=buf_2_two_d_location(mbuf,size,&circular_region->center);
  if(0>two_length)
	  return -1;
  mbuf+=two_length;
  size-=two_length;

  if(size<2){
	  wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
	  return -1;
  }
  circular_region->radius=get16(mbuf);
  circular_region->radius=be_to_host16(circular_region->radius);
  mbuf+=2;
  size-=2;

  return len-size;
}


//buf_to 12
static u32 buf_2_geographic_region( u8* buf, u32 len,geographic_region* geographic_region){

	u8* mbuf=buf;
	u32 size=len;
	u32 geographic_length;
	u32 polygonal_length;
	u32 two_length;
	u16 bitnum;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size<1 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	geographic_region->region_type=get8(mbuf);
	mbuf++;
	size--;
  
	switch(geographic_region->region_type){
		case FROM_ISSUER:
			return len - size;
		case CIRCLE:
			geographic_length=buf_2_circular_region(mbuf,size,&geographic_region->u.circular_region);
			if(0>geographic_length)
				return -1;
			mbuf+=geographic_length;
			size-=geographic_length;
			return len-size;

		case RECTANGLE:
			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);
			geographic_region->u.rectangular_region.len = data_length/16;

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			geographic_region->u.rectangular_region.buf=(rectangular_region*)malloc(sizeof(rectangular_region)*1);
			if(NULL == geographic_region->u.rectangular_region.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				geographic_region->u.rectangular_region.buf=(rectangular_region*)realloc(
						geographic_region->u.rectangular_region.buf,sizeof(rectangular_region)*(i+1));
				decode_len = buf_2_rectangular_region(mbuf,data_length-decode_len_sum,
						geographic_region->u.rectangular_region.buf + i);
				if(decode_len < 0)
					return decode_len;
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			size -= data_length;

			return len-size;

		case POLYGON:
			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);
			geographic_region->u.polygonal_region.len = data_length/8;

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			geographic_region->u.polygonal_region.buf=(two_d_location*)malloc(sizeof(two_d_location)*1);
			if(NULL == geographic_region->u.polygonal_region.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				geographic_region->u.polygonal_region.buf=(two_d_location*)realloc(
						geographic_region->u.polygonal_region.buf,sizeof(two_d_location)*(i+1));
				decode_len = buf_2_two_d_location(mbuf,data_length-decode_len_sum,
						geographic_region->u.polygonal_region.buf + i);
				if(decode_len < 0)
					return decode_len;
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			size -= data_length;

			return len-size;
		case NONE:
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			geographic_region->u.other_region.len=variablelength_data_num(mbuf,bitnum);
			if(size<geographic_region->u.other_region.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			geographic_region->u.other_region.buf=(u8*)malloc(sizeof(u8)*geographic_region->u.other_region.len);
			if(NULL==geographic_region->u.other_region.buf){
				return -1;
			}
			fill_buf8(geographic_region->u.other_region.buf,mbuf,geographic_region->u.other_region.len);
			mbuf+=geographic_region->u.other_region.len*sizeof(u8);
			size-=geographic_region->u.other_region.len*sizeof(u8);
			return len-size;
	}
}



//buf_2  13

static u32 buf_2_psid_priority(u8* buf,u32 len,psid_priority* psid_priority){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 decode_len;
   
	if(size<2){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	decode_len = psid_decoding(mbuf,&psid_priority->psid);
	if(decode_len < 0)
		return decode_len;
	mbuf += decode_len;
	size -= decode_len;

    psid_priority->max_priority=get8(mbuf);
	mbuf++;
	size--;

	return len-size;
}

//buf_2 14
static u32 buf_2_psid_priority_array(  u8* buf,const u32 len,psid_priority_array* psid_priority_array){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size< 1 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	psid_priority_array->type=get8(mbuf);
	mbuf++;
	size--;
  
	switch(psid_priority_array->type){
		case ARRAY_TYPE_SPECIFIED:

			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);
			psid_priority_array->u.permissions_list.len = data_length/5;

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			psid_priority_array->u.permissions_list.buf=(psid_priority*)malloc(sizeof(psid_priority)*1);
			if(NULL == psid_priority_array->u.permissions_list.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				psid_priority_array->u.permissions_list.buf=(psid_priority*)realloc(
						psid_priority_array->u.permissions_list.buf,sizeof(psid_priority)*(i+1));
				decode_len = buf_2_psid_priority(mbuf,data_length-decode_len_sum,
						psid_priority_array->u.permissions_list.buf + i);
				if(decode_len < 0)
					return decode_len;
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			size -= data_length;

			return len-size;

		case ARRAY_TYPE_FROM_ISSUER:
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			psid_priority_array->u.other_permissions.len=variablelength_data_num(mbuf,bitnum);
			if(size<psid_priority_array->u.other_permissions.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			psid_priority_array->u.other_permissions.buf=(u8*)malloc(sizeof(u8)*psid_priority_array->u.other_permissions.len);
			if(NULL == psid_priority_array->u.other_permissions.buf){
				return -1;
			}
			fill_buf8(psid_priority_array->u.other_permissions.buf,mbuf,psid_priority_array->u.other_permissions.len);	
			mbuf+=psid_priority_array->u.other_permissions.len*sizeof(u8);
			size-=psid_priority_array->u.other_permissions.len*sizeof(u8);
			return len-size;
   }
}

//buf_2 15

static u32 buf_2_psid_array(  u8* buf,  u32 len,psid_array* psid_array){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size<1){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	psid_array->type=get8(mbuf);
	mbuf++;
	size--;
  
	switch(psid_array->type){
		case ARRAY_TYPE_SPECIFIED:

			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			psid_array->u.permissions_list.buf=(psid*)malloc(sizeof(psid)*1);
			if(NULL == psid_array->u.permissions_list.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				psid_array->u.permissions_list.buf=(psid*)realloc(
						psid_array->u.permissions_list.buf,sizeof(psid)*(i+1));
				decode_len = psid_decoding(mbuf,psid_array->u.permissions_list.buf + i);
				if(decode_len < 0)
					return decode_len;
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			psid_array->u.permissions_list.len = i;
			size -= data_length;

			return len-size;

		case ARRAY_TYPE_FROM_ISSUER:
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			psid_array->u.other_permissions.len=variablelength_data_num(mbuf,bitnum);
			if(size<psid_array->u.other_permissions.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			psid_array->u.other_permissions.buf=(u8*)malloc(sizeof(u8)*psid_array->u.other_permissions.len);
			if(NULL == psid_array->u.other_permissions.buf){
				return -1;
			}
			fill_buf8(psid_array->u.other_permissions.buf,mbuf, psid_array->u.other_permissions.len);
			mbuf+=psid_array->u.other_permissions.len*sizeof(u8);
			size-=psid_array->u.other_permissions.len*sizeof(u8);
			return len-size;
   }
}

  
//buf_2 16

static u32 buf_2_psid_ssp(  u8* buf,u32 len,psid_ssp* psid_ssp){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 decode_len;

	if(size<2){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	decode_len = psid_decoding(mbuf,&psid_ssp->psid);
	if(decode_len < 0)
		return decode_len;
	mbuf += decode_len;
	size -= decode_len;

	bitnum=head_bit_num(mbuf);
	psid_ssp->service_specific_permissions.len=variablelength_data_num(mbuf,bitnum);
	if(size<psid_ssp->service_specific_permissions.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	psid_ssp->service_specific_permissions.buf=(u8*)malloc(sizeof(u8)*psid_ssp->service_specific_permissions.len);
	if(NULL == psid_ssp->service_specific_permissions.buf){
		return -1;
	}
	fill_buf8(  psid_ssp->service_specific_permissions.buf,mbuf,  psid_ssp->service_specific_permissions.len);
	mbuf+=psid_ssp->service_specific_permissions.len*sizeof(u8);
	size-=psid_ssp->service_specific_permissions.len*sizeof(u8);
	return len-size;
}


//buf_2 17
static u32 buf_2_psid_ssp_array(  u8* buf,const u32 len,psid_ssp_array* psid_ssp_array){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size<1){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	psid_ssp_array->type=get8(mbuf);
	mbuf++;
	size--;
  
	switch(psid_ssp_array->type){
		case ARRAY_TYPE_SPECIFIED:
			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			psid_ssp_array->u.permissions_list.buf=(psid_ssp*)malloc(sizeof(psid_ssp)*1);
			if(NULL == psid_ssp_array->u.permissions_list.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				psid_ssp_array->u.permissions_list.buf=(psid_ssp*)realloc(
						psid_ssp_array->u.permissions_list.buf,sizeof(psid_ssp)*(i+1));
				decode_len = buf_2_psid_ssp(mbuf,data_length-decode_len_sum,
						psid_ssp_array->u.permissions_list.buf + i);
				if(decode_len < 0)
					return decode_len;
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			psid_ssp_array->u.permissions_list.len = i;

			size -= data_length;

			return len-size;

		case ARRAY_TYPE_FROM_ISSUER:
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			psid_ssp_array->u.other_permissions.len=variablelength_data_num(mbuf,bitnum);
			if(size<psid_ssp_array->u.other_permissions.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			psid_ssp_array->u.other_permissions.buf=(u8*)malloc(sizeof(u8)*psid_ssp_array->u.other_permissions.len);
			if(NULL == psid_ssp_array->u.other_permissions.buf){
				return -1;
			}
			fill_buf8(  psid_ssp_array->u.other_permissions.buf,mbuf,  psid_ssp_array->u.other_permissions.len);
			mbuf+=psid_ssp_array->u.other_permissions.len*sizeof(u8);
			size-=psid_ssp_array->u.other_permissions.len*sizeof(u8);
			return len-size;
   }
}


//buf_2 18
static u32 buf_2_psid_priority_ssp(u8* buf, u32 len,psid_priority_ssp* psid_priority_ssp){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 decode_len;

    if(size<3){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	decode_len = psid_decoding(mbuf,&psid_priority_ssp->psid);
	if(decode_len < 0)
		return decode_len;
	mbuf += decode_len;
	size -= decode_len;

	psid_priority_ssp->max_priority=get8(mbuf);
	mbuf++;
	size--;

    bitnum=head_bit_num(mbuf);
	psid_priority_ssp->service_specific_permissions.len=variablelength_data_num(mbuf,bitnum);
	if(size<psid_priority_ssp->service_specific_permissions.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	psid_priority_ssp->service_specific_permissions.buf=(u8*)malloc(sizeof(u8)*psid_priority_ssp->service_specific_permissions.len);
	if(NULL == psid_priority_ssp->service_specific_permissions.buf){
		return -1;
	}
	fill_buf8( psid_priority_ssp->service_specific_permissions.buf,mbuf, psid_priority_ssp->service_specific_permissions.len);
	mbuf+=psid_priority_ssp->service_specific_permissions.len*sizeof(u8);
	size-=psid_priority_ssp->service_specific_permissions.len*sizeof(u8);

	return len-size;
}

//buf_2 19

static u32 buf_2_psid_priority_ssp_array(  u8* buf,const u32 len,psid_priority_ssp_array* psid_priority_ssp_array){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size<1){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
  
	psid_priority_ssp_array->type=get8(mbuf);
	mbuf++;
	size--;
   
	switch(psid_priority_ssp_array->type){
		case ARRAY_TYPE_SPECIFIED:
			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			psid_priority_ssp_array->u.permissions_list.buf=(psid_priority_ssp*)malloc(sizeof(psid_priority_ssp)*1);
			if(NULL == psid_priority_ssp_array->u.permissions_list.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				psid_priority_ssp_array->u.permissions_list.buf=(psid_priority_ssp*)realloc(
						psid_priority_ssp_array->u.permissions_list.buf,sizeof(psid_priority_ssp)*(i+1));
				decode_len = buf_2_psid_priority_ssp(mbuf,data_length-decode_len_sum,
						psid_priority_ssp_array->u.permissions_list.buf + i);
				if(decode_len < 0)
					return decode_len;
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			psid_priority_ssp_array->u.permissions_list.len = i;

			size -= data_length;

			return len-size;

		case ARRAY_TYPE_FROM_ISSUER:
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			psid_priority_ssp_array->u.other_permissions.len=variablelength_data_num(mbuf,bitnum);
			if(size<psid_priority_ssp_array->u.other_permissions.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			psid_priority_ssp_array->u.other_permissions.buf=(u8*)malloc(sizeof(u8)*psid_priority_ssp_array->u.other_permissions.len);
			if(NULL == psid_priority_ssp_array->u.other_permissions.buf){
				return -1;
			}
			fill_buf8( psid_priority_ssp_array->u.other_permissions.buf,mbuf, psid_priority_ssp_array->u.other_permissions.len);
			mbuf+=psid_priority_ssp_array->u.other_permissions.len*sizeof(u8);
			size-=psid_priority_ssp_array->u.other_permissions.len*sizeof(u8);

			return len-size;
   }
}


//buf_to 20

static u32 buf_2_wsa_scope(  u8* buf,  u32 len,wsa_scope* wsa_scope){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 geographic_length;
	u32 psid_priority_ssp_array_length;

	if(size<3 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;          //	u8* name
	}

	bitnum=head_bit_num(mbuf);
	wsa_scope->name.len=variablelength_data_num(mbuf,bitnum);
	if(size<wsa_scope->name.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	wsa_scope->name.buf=(u8*)malloc(sizeof(u8)*wsa_scope->name.len);
	if(NULL == wsa_scope->name.buf){
		return -1;
	}
	fill_buf8(  wsa_scope->name.buf,mbuf,  wsa_scope->name.len);
	mbuf+=wsa_scope->name.len*sizeof(u8);
	size-=wsa_scope->name.len*sizeof(u8);

	psid_priority_ssp_array_length=buf_2_psid_priority_ssp_array(mbuf,size,&wsa_scope->permissions);
    if(0>psid_priority_ssp_array_length)
		return -1;
	mbuf+=psid_priority_ssp_array_length;
	size-=psid_priority_ssp_array_length;

	geographic_length=buf_2_geographic_region(mbuf,size,&wsa_scope->region);
    if(0>geographic_length)
		return -1;
	mbuf+=geographic_length;
	size-=geographic_length;

	return len-size;
}

//buf_2 21
static u32 buf_2_anonymous_scope(  u8* buf,const u32 len,anonymous_scope* anonymous_scope){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 geographic_length;
	u32 psid_ssp_array_length;

	if(size<5)  {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

    bitnum=head_bit_num(mbuf);
	anonymous_scope->additionla_data.len=variablelength_data_num(mbuf,bitnum);
	if(size<anonymous_scope->additionla_data.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	anonymous_scope->additionla_data.buf=(u8*)malloc(sizeof(u8)*anonymous_scope->additionla_data.len);	
	if(NULL==anonymous_scope->additionla_data.buf){
		return -1;
	}
	fill_buf8(  anonymous_scope->additionla_data.buf,mbuf,  anonymous_scope->additionla_data.len);
	mbuf+=anonymous_scope->additionla_data.len*sizeof(u8);
	size-=anonymous_scope->additionla_data.len*sizeof(u8);

	psid_ssp_array_length=buf_2_psid_ssp_array(mbuf,size,&anonymous_scope->permissions);
    if(0>psid_ssp_array_length)
		return -1;
	mbuf+=psid_ssp_array_length;
	size-=psid_ssp_array_length;

	geographic_length=buf_2_geographic_region(mbuf,size,&anonymous_scope->region);
    if(0>geographic_length)
		return -1;
	mbuf+=geographic_length;
	size-=geographic_length;
	  
	return len-size;
}

//buf_2 22
static u32 buf_2_identified_scope(  u8* buf,  u32 len,identified_scope* identified_scope){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 geographic_length;
	u32 psid_ssp_array_length;

	if(size<3 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	bitnum=head_bit_num(mbuf);
	identified_scope->name.len=variablelength_data_num(mbuf,bitnum);
	if(size<identified_scope->name.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	identified_scope->name.buf=(u8*)malloc(sizeof(u8)*identified_scope->name.len);
	if(NULL==identified_scope->name.buf){
		return -1;
	}
	fill_buf8(  identified_scope->name.buf,mbuf,identified_scope->name.len);
	mbuf+=identified_scope->name.len*sizeof(u8);
	size-=identified_scope->name.len*sizeof(u8);


	psid_ssp_array_length=buf_2_psid_ssp_array(mbuf,size,&identified_scope->permissions);
    if(0>psid_ssp_array_length)
		return -1;
	mbuf+=psid_ssp_array_length;
	size-=psid_ssp_array_length;
	  

	geographic_length=buf_2_geographic_region(mbuf,size,&identified_scope->region);
    if(0>geographic_length)
		return -1;
	mbuf+=geographic_length;
	size-=geographic_length;
	  
	return len-size;
}

//buf_2 23

static u32 buf_2_identified_not_localized_scope(  u8* buf,const u32 len,identified_not_localized_scope* identified_not_localized_scope){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 psid_ssp_array_length;

	if(size<2 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	bitnum=head_bit_num(mbuf);
	identified_not_localized_scope->name.len=variablelength_data_num(mbuf,bitnum);
	if(size<identified_not_localized_scope->name.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	identified_not_localized_scope->name.buf=(u8*)malloc(sizeof(u8)*identified_not_localized_scope->name.len);	
	if(NULL==identified_not_localized_scope->name.buf){
		return -1;
	}
	fill_buf8(  identified_not_localized_scope->name.buf,mbuf,identified_not_localized_scope->name.len);
	mbuf+=identified_not_localized_scope->name.len*sizeof(u8);
	size-=identified_not_localized_scope->name.len*sizeof(u8);


	psid_ssp_array_length=buf_2_psid_ssp_array(mbuf,size,&identified_not_localized_scope->permissions);
    if(0>psid_ssp_array_length)
		return -1;
	mbuf+=psid_ssp_array_length;
	size-=psid_ssp_array_length;
	  
	return len-size;
}

//buf_2 24
static u32 buf_2_wsa_ca_scope(  u8* buf,  u32 len,wsa_ca_scope* wsa_ca_scope){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 geographic_length;
	u32 psid_priority_array_length;

	if(size<3){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

    bitnum=head_bit_num(mbuf);
	wsa_ca_scope->name.len=variablelength_data_num(mbuf,bitnum);
	if(size<wsa_ca_scope->name.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
	    return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	wsa_ca_scope->name.buf=(u8*)malloc(sizeof(u8)*wsa_ca_scope->name.len);	
	if(NULL==wsa_ca_scope->name.buf){
	    return -1;
	}
	fill_buf8(  wsa_ca_scope->name.buf,mbuf,  wsa_ca_scope->name.len);
	mbuf+=wsa_ca_scope->name.len*sizeof(u8);
	size-=wsa_ca_scope->name.len*sizeof(u8);

	psid_priority_array_length=buf_2_psid_priority_array(mbuf,size,&wsa_ca_scope->permissions);
    if(0>psid_priority_array_length)
	    return -1;
	mbuf+=psid_priority_array_length;
	size-=psid_priority_array_length;
	  

	geographic_length=buf_2_geographic_region(mbuf,size,&wsa_ca_scope->region);
    if(0>geographic_length)
	    return -1;
	mbuf+=geographic_length;
	size-=geographic_length;
	return len-size;
}


//buf_2 25
static u32 buf_2_sec_data_exch_ca_scope(  u8* buf,  u32 len,sec_data_exch_ca_scope* sec_data_exch_ca_scope){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 geographic_length;
	u32 psid_array_length;

	if(size<4){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
       
	bitnum=head_bit_num(mbuf);
	sec_data_exch_ca_scope ->name.len=variablelength_data_num(mbuf,bitnum);
	if(size<sec_data_exch_ca_scope->name.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
	    return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	sec_data_exch_ca_scope->name.buf=(u8*)malloc(sizeof(u8)*sec_data_exch_ca_scope->name.len);	
	if(NULL==sec_data_exch_ca_scope->name.buf){
	    return -1;
	}
	fill_buf8(   sec_data_exch_ca_scope->name.buf,mbuf,sec_data_exch_ca_scope->name.len);
	mbuf+=sec_data_exch_ca_scope->name.len*sizeof(u8);
	size-=sec_data_exch_ca_scope->name.len*sizeof(u8);
	  
	if(get8(mbuf) < 0x80){
		sec_data_exch_ca_scope->permitted_holder_types = get8(mbuf);
		mbuf++;
		size--;
	}else{
		sec_data_exch_ca_scope->permitted_holder_types = get16(mbuf) & 0x7fff;
		mbuf += 2;
		size -= 2;
	}

	psid_array_length=buf_2_psid_array(mbuf,size,&sec_data_exch_ca_scope->permissions);
	if(0>psid_array_length)
		return -1;
	mbuf+=psid_array_length;
	size-=psid_array_length;
	

	geographic_length=buf_2_geographic_region(mbuf,size,&sec_data_exch_ca_scope->region);
    if(0>geographic_length)
		return -1;
	mbuf+=geographic_length;
	size-=geographic_length;
	return len-size;
}


//buf_2 26
static u32 buf_2_root_ca_scope(  u8* buf,  u32 len,root_ca_scope* root_ca_scope){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 geographic_length;
	u32 psid_array_length;
	u32 psid_priority_array_length;

	if(size<4){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

    bitnum=head_bit_num(mbuf);
	root_ca_scope->name.len=variablelength_data_num(mbuf,bitnum);
	if(size<root_ca_scope->name.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
	    return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	root_ca_scope->name.buf=(u8*)malloc(sizeof(u8)*root_ca_scope->name.len);	
	if(NULL==root_ca_scope->name.buf){
	    return -1;
	}
	fill_buf8(  root_ca_scope->name.buf,mbuf,root_ca_scope->name.len);
	mbuf+=root_ca_scope->name.len*sizeof(u8);
	size-=root_ca_scope->name.len*sizeof(u8);

	if(get8(mbuf) < 0x80){
		root_ca_scope->permitted_holder_types = get8(mbuf);
		mbuf++;
		size--;
	}else{
		root_ca_scope->permitted_holder_types = get16(mbuf) & 0x7fff;
		mbuf += 2;
		size -= 2;
	}

	if( (root_ca_scope->permitted_holder_types & 1<<0)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<1)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<2)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<3)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<6)!=0){
		psid_array_length=buf_2_psid_array(mbuf,size,&root_ca_scope->flags_content.secure_data_permissions);
		if(0>psid_array_length)
			return -1;
		mbuf+=psid_array_length;
		size-=psid_array_length;
	}
	
	if( (root_ca_scope->permitted_holder_types & 1<<4)!=0 ||
		(root_ca_scope->permitted_holder_types & 1<<5)!=0 ||
		((root_ca_scope->permitted_holder_types > 1<<6) && (root_ca_scope->permitted_holder_types & 1<<7)!=0)){
		psid_priority_array_length=buf_2_psid_priority_array(mbuf,size,
				&root_ca_scope->flags_content.wsa_permissions);
		if(0>psid_priority_array_length)
			return -1;
		mbuf+=psid_priority_array_length;
		size-=psid_priority_array_length;
	}
	
	if((root_ca_scope->permitted_holder_types > 1<<6) && (root_ca_scope->permitted_holder_types & 1<<8)!=0){
		bitnum=head_bit_num(mbuf);
		root_ca_scope->flags_content.other_permissions.len=variablelength_data_num(mbuf,bitnum);
		if(size<root_ca_scope->name.len*sizeof(u8)+bitnum){
			wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		    return -1;
		}
		mbuf+=bitnum;
		size-=bitnum;
		root_ca_scope->flags_content.other_permissions.buf=(u8*)malloc(sizeof(u8)*root_ca_scope->flags_content.other_permissions.len);	
		if(NULL==root_ca_scope->flags_content.other_permissions.buf){
		    return -1;
		}
		fill_buf8(root_ca_scope->flags_content.other_permissions.buf,mbuf,root_ca_scope->flags_content.other_permissions.len);
		mbuf+=root_ca_scope->flags_content.other_permissions.len*sizeof(u8);
		size-=root_ca_scope->flags_content.other_permissions.len*sizeof(u8);
	}

	geographic_length=buf_2_geographic_region(mbuf,size,&root_ca_scope->region);
    if(0>geographic_length)
	    return -1;
	mbuf+=geographic_length;
	size-=geographic_length;
	return len-size;
}


//buf_2 27
static u32 buf_2_cert_specific_data(  u8* buf,  u32 len,cert_specific_data* cert_specific_data, holder_type holder_type ){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 root_ca_scope_length;
	u32 sec_data_exch_ca_scope_length;
	u32 wsa_ca_scope_length;
	u32 identified_not_localized_scope_length;
	u32 identified_scope_length;
	u32 anonymous_scope_length;
    u32 wsa_scope_length;
	u32 data_length;
	u32 decode_len_sum;
	int i;

	if(size<1 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	
	switch(holder_type){
		case ROOT_CA:
			root_ca_scope_length=buf_2_root_ca_scope(mbuf,size,&cert_specific_data->u.root_ca_scope);
			if(0>root_ca_scope_length)
				return -1;
			mbuf+=root_ca_scope_length;
			size-=root_ca_scope_length;
			return len-size;

		case SDE_CA:
	    case SDE_ENROLMENT:
			sec_data_exch_ca_scope_length=buf_2_sec_data_exch_ca_scope(mbuf,size,&cert_specific_data ->u.sde_ca_scope);
			if(0>sec_data_exch_ca_scope_length)
				return -1;
			mbuf+=sec_data_exch_ca_scope_length;
			size-=sec_data_exch_ca_scope_length;
			return len-size;

		case WSA_CA:
	    case WSA_ENROLMENT:
			wsa_ca_scope_length=buf_2_wsa_ca_scope(mbuf,size,&cert_specific_data->u.wsa_ca_scope);
			if(0>wsa_ca_scope_length)
				return -1;
			mbuf+=wsa_ca_scope_length;
			size-=wsa_ca_scope_length;
			return len-size;

		case CRL_SIGNER:
			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);
			cert_specific_data->u.responsible_series.len = data_length/4;

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			cert_specific_data->u.responsible_series.buf=(crl_series*)malloc(sizeof(crl_series)*1);
			if(NULL == cert_specific_data->u.responsible_series.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				cert_specific_data->u.responsible_series.buf=(crl_series*)realloc(
						cert_specific_data->u.responsible_series.buf,sizeof(crl_series)*(i+1));
				*(cert_specific_data->u.responsible_series.buf + i)= get32(mbuf);
				*(cert_specific_data->u.responsible_series.buf + i)= be_to_host32(*(cert_specific_data->u.responsible_series.buf + i));

				mbuf += 4;
				decode_len_sum += 4;
			}
			size -= data_length;
			return len - size;

		case SDE_IDENTIFIED_NOT_LOCALIZED:
			identified_not_localized_scope_length= buf_2_identified_not_localized_scope(mbuf,size,&cert_specific_data->u.id_non_loc_scope);
			if(0>identified_not_localized_scope_length)
				return -1;
			mbuf+=identified_not_localized_scope_length;
			size-=identified_not_localized_scope_length;
			return len-size;

		case SDE_IDENTIFIED_LOCALIZED:
			identified_scope_length=buf_2_identified_scope(mbuf,size,&cert_specific_data->u.id_scope);
			if(0>identified_scope_length)
				return -1;
			mbuf+=identified_scope_length;
			size-=identified_scope_length;
			return len-size;

		case SDE_ANONYMOUS:
			anonymous_scope_length=buf_2_anonymous_scope(mbuf,size,&cert_specific_data->u.anonymous_scope);
			if(0>anonymous_scope_length)
				return -1;
			mbuf+=anonymous_scope_length;
			size-=anonymous_scope_length;
			return len-size;

		case WSA:
			wsa_scope_length=buf_2_wsa_scope(mbuf,size,&cert_specific_data->u.wsa_scope);
			if(0>wsa_scope_length)
				return -1;
			mbuf+=wsa_scope_length;
			size-=wsa_scope_length;
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			cert_specific_data->u.other_scope.len=variablelength_data_num(mbuf,bitnum);
			if(size<cert_specific_data->u.other_scope.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			cert_specific_data->u.other_scope.buf=(u8*)malloc(sizeof(u8)*cert_specific_data->u.other_scope.len);	
			if(NULL==cert_specific_data->u.other_scope.buf){
				return -1;
			}
			fill_buf8(  cert_specific_data->u.other_scope.buf,mbuf,  cert_specific_data->u.other_scope.len);
			mbuf+=cert_specific_data->u.other_scope.len*sizeof(u8);
			size-=cert_specific_data->u.other_scope.len*sizeof(u8);
			return len-size;
	}
}


//buf_2 28
static u32 buf_2_tobesigned_certificate(  u8* buf,  u32 len,tobesigned_certificate* tobesigned_certificate,u8 version_and_type ){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 cert_specific_data_length;
	u32 public_key_length;
	u32 public_key_length2;
	u32 hashed_length;
	int i;

	if(size<12)  {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	tobesigned_certificate->holder_type=get8(mbuf);
	mbuf++;
	size--;

    tobesigned_certificate->cf = get8(mbuf);
	mbuf++;
	size--;

	switch(tobesigned_certificate->holder_type){
		case ROOT_CA:
			break;
	    default:
			hashed_length=buf_2_hashedid8(mbuf,size,&tobesigned_certificate->u.no_root_ca.signer_id);
			if(0>hashed_length)
				return -1;
			mbuf+=hashed_length;
			size-=hashed_length;

			tobesigned_certificate->u.no_root_ca.signature_alg=get8(mbuf);
			mbuf++;
			size--;
			break;
	}

	cert_specific_data_length=buf_2_cert_specific_data(mbuf,size,&tobesigned_certificate->scope,tobesigned_certificate->holder_type);
    if(0>cert_specific_data_length)
	    return -1;
	mbuf+=cert_specific_data_length;
	size-=cert_specific_data_length;
	
	tobesigned_certificate->expiration=get32(mbuf);
    tobesigned_certificate->expiration=be_to_host32(tobesigned_certificate->expiration);
    mbuf+=4;
    size-=4;
    
	tobesigned_certificate->crl_series=get32(mbuf);
    tobesigned_certificate->crl_series=be_to_host32(tobesigned_certificate->crl_series);
    mbuf+=4;
    size-=4;

	switch(version_and_type){
		case 2:
			public_key_length=buf_2_public_key(mbuf,size,&tobesigned_certificate->version_and_type.verification_key);
			if(0>public_key_length)
				return -1;
			mbuf+=public_key_length;
			size-=public_key_length;
			break;
	  
		case 3:
			break;

		default:
			bitnum=head_bit_num(mbuf);
			tobesigned_certificate->version_and_type.other_key_material.len=variablelength_data_num(mbuf,bitnum);
			if(size< tobesigned_certificate->version_and_type.other_key_material.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobesigned_certificate->version_and_type.other_key_material.buf=(u8*)malloc(sizeof(u8)* tobesigned_certificate->version_and_type.other_key_material.len);	
			if(NULL==tobesigned_certificate->version_and_type.other_key_material.buf){
				return -1;
			}
			fill_buf8(tobesigned_certificate->version_and_type.other_key_material.buf,mbuf,
					tobesigned_certificate->version_and_type.other_key_material.len);
			mbuf+= tobesigned_certificate->version_and_type.other_key_material.len*sizeof(u8);
			size-= tobesigned_certificate->version_and_type.other_key_material.len*sizeof(u8);
			break;
	}
	 
	if((tobesigned_certificate->cf & 1<<0)!=0){
		if((tobesigned_certificate->cf & 1<<1)!=0){
			tobesigned_certificate->flags_content.lifetime=get16(mbuf);
			tobesigned_certificate->flags_content.lifetime=be_to_host16(tobesigned_certificate->flags_content.lifetime);
			mbuf+=2;
			size-=2;
		}else{
			tobesigned_certificate->flags_content.start_validity=get32(mbuf);
			tobesigned_certificate->flags_content.start_validity=be_to_host32(tobesigned_certificate->flags_content.start_validity);
			mbuf+=4;
			size-=4;
		}
	}

	if((tobesigned_certificate->cf & 1<<2)!= 0){
		public_key_length2=buf_2_public_key(mbuf,size,&tobesigned_certificate->flags_content.encryption_key);
		if(0>public_key_length2)
			return -1;
		mbuf+=public_key_length2;
		size-=public_key_length2;
	}
	  
	if((tobesigned_certificate->cf & 0xf8)!=0){
		bitnum=head_bit_num(mbuf);
		tobesigned_certificate->flags_content.other_cert_content.len=variablelength_data_num(mbuf,bitnum);
		if(size< tobesigned_certificate->flags_content.other_cert_content.len*sizeof(u8)+bitnum){
			wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
			return -1;
		}
		mbuf+=bitnum;
		size-=bitnum;
	    tobesigned_certificate->flags_content.other_cert_content.buf=(u8*)malloc(sizeof(u8)* tobesigned_certificate->flags_content.other_cert_content.len);	
		if(NULL==tobesigned_certificate->flags_content.other_cert_content.buf){
			return -1;
		}
		fill_buf8(tobesigned_certificate->flags_content.other_cert_content.buf,mbuf,
				tobesigned_certificate->flags_content.other_cert_content.len);
		mbuf+= tobesigned_certificate->flags_content.other_cert_content.len*sizeof(u8);
		size-= tobesigned_certificate->flags_content.other_cert_content.len*sizeof(u8);
	}
	return len-size;
}


//buf_2 29
u32 buf_2_certificate(  u8* buf,  u32 len,certificate* certificate){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 tobesigned_certificate_length;
    u32 signature_length;
	u32 elliptic_curve_point_length;

	if(size<14 ) {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	certificate->version_and_type=get8(mbuf);
	mbuf++;
	size--;
  
	tobesigned_certificate_length=buf_2_tobesigned_certificate(mbuf,size,
			&certificate->unsigned_certificate,certificate->version_and_type);
    if(0>tobesigned_certificate_length)
	    return -1;
	mbuf+=tobesigned_certificate_length;
	size-=tobesigned_certificate_length;

	switch(certificate->version_and_type){
		case 2:
			if(certificate->unsigned_certificate.holder_type == ROOT_CA){
				signature_length= buf_2_signature(mbuf,size,&certificate->u.signature,
				certificate->unsigned_certificate.version_and_type.verification_key.algorithm);
			}else{
				signature_length=buf_2_signature(mbuf,size,&certificate->u.signature,
				certificate->unsigned_certificate.u.no_root_ca.signature_alg);
			}
			if(0>signature_length)
				return -1;
			mbuf+=signature_length;
			size-=signature_length;
			return len-size;
 
		case 3:
			elliptic_curve_point_length=buf_2_elliptic_curve_point(mbuf,size,&certificate->u.reconstruction_value,
					certificate->unsigned_certificate.u.no_root_ca.signature_alg);
			if(0>elliptic_curve_point_length)
				return -1;
			mbuf+=elliptic_curve_point_length;
			size-=elliptic_curve_point_length;
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			certificate->u.signature_material.len=variablelength_data_num(mbuf,bitnum);
			if(size< certificate->u.signature_material.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			certificate->u.signature_material.buf=(u8*)malloc(sizeof(u8)*certificate->u.signature_material.len);	
			if(NULL==certificate->u.signature_material.buf){
				return -1;
			}
			fill_buf8(  certificate->u.signature_material.buf,mbuf,  certificate->u.signature_material.len);
			mbuf+=certificate->u.signature_material.len*sizeof(u8);
			size-=certificate->u.signature_material.len*sizeof(u8);
			return len-size;
	}
}


//buf_2 30
static u32 buf_2_signer_identifier(u8* buf, u32 len,signer_identifier* signer_identifier){
	u8* mbuf=buf;
	u16 bitnum;
	u32 size=len;
	u32 certificate_length;
	u32 hashed_length;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;
    
	if(size<1 )  {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	signer_identifier->type=get8(mbuf);
	mbuf++;
	size--;

	switch(signer_identifier->type){
		case SELF:
			return len-size;
	
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			hashed_length=buf_2_hashedid8(mbuf,size,&signer_identifier->u.digest);
			if(0>hashed_length)
				return -1;
			mbuf+=hashed_length;
			size-=hashed_length;
			return len-size;

		case CERTIFICATE:
			certificate_length=buf_2_certificate(mbuf,size,&signer_identifier->u.certificate);
			if(0>certificate_length)
				return -1;
			mbuf+=certificate_length;
			size-=certificate_length;
			return len-size;

		case CERTIFICATE_CHAIN:
			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			signer_identifier->u.certificates.buf=(certificate*)malloc(sizeof(certificate)*1);
			if(NULL == signer_identifier->u.certificates.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				signer_identifier->u.certificates.buf=(certificate*)realloc(
						signer_identifier->u.certificates.buf,sizeof(certificate)*(i+1));
				decode_len = buf_2_certificate(mbuf,data_length-decode_len_sum,
						signer_identifier->u.certificates.buf + i);
				if(decode_len < 0)
					return decode_len;
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			signer_identifier->u.certificates.len = i;
			size -= data_length;
			return len-size;

		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			signer_identifier->u.other_algorithm.algorithm=get8(mbuf);
			mbuf++;
			size--;
		
			hashed_length=buf_2_hashedid8(mbuf,size,&signer_identifier->u.other_algorithm.digest);
			if(0>hashed_length)
				return -1;
			mbuf+=hashed_length;
			size-=hashed_length;
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			signer_identifier->u.id.len=variablelength_data_num(mbuf,bitnum);
			if(size< signer_identifier->u.id.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			signer_identifier->u.id.buf=(u8*)malloc(sizeof(u8)*signer_identifier->u.id.len);
			if(NULL==signer_identifier->u.id.buf){
				return -1;
			}
			fill_buf8(signer_identifier->u.id.buf,mbuf,signer_identifier->u.id.len);
			mbuf+=signer_identifier->u.id.len*sizeof(u8);
			size-=signer_identifier->u.id.len*sizeof(u8);
			return len-size;
	}
}


// buf_2 31
static u32 buf_2_crl_request(  u8* buf,  u32 len,crl_request* crl_request){
	u8* mbuf=buf;
	u32 size=len;
	u32 hashed_length;
	
	if(size<16 ) {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	hashed_length=buf_2_hashedid8(mbuf,size,&crl_request->issuer);
    if(0>hashed_length)
		return -1;
	mbuf+=hashed_length;
	size-=hashed_length;

	crl_request->crl_series= get32(mbuf);
	crl_request->crl_series= be_to_host32(crl_request->crl_series);
	mbuf+=4;
	size-=4;

	crl_request->issue_date= get32(mbuf);
	crl_request->issue_date= be_to_host32(crl_request->issue_date);
	mbuf+=4;
	size-=4;

	return len-size;
}


// buf_2 32
static u32 buf_2_certid10(  u8* buf, const u32 len, certid10* certid10){
	u8* mbuf = buf; 
	u32 size = len;
	int i;

	if (size < 10){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	for(i = 0; i < 10; i++ ){
	    certid10->certid10[i] = get8(mbuf);
		mbuf++;
		size--;
	}

	return len-size;
}


//buf_2 33
static u32 buf_2_id_and_date(  u8* buf,   u32 len, id_and_date* id_and_date){
   	u8* mbuf = buf; 
	u32 size = len;
	u32 certid10_length;

	if(size<14){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

    certid10_length=buf_2_certid10(mbuf,size,&id_and_date->id);
    if(0>certid10_length)
	    return -1;
	mbuf+=certid10_length;
	size-=certid10_length;

	id_and_date->expiry= get32(mbuf);
	id_and_date->expiry= be_to_host32(id_and_date->expiry);
	mbuf+=4;
	size-=4;
    return len-size;
}


// buf_2 34
u32 buf_2_tobesigned_crl(  u8* buf, const u32 len, tobesigned_crl* tobesigned_crl){
   	u8* mbuf = buf; 
	u32 size = len;
    u16 bitnum;
	u32 hashed_length;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size<30 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	tobesigned_crl->type=get8(mbuf);
	mbuf++;
	size--;

	tobesigned_crl->crl_series= get32(mbuf);
	tobesigned_crl->crl_series= be_to_host32(tobesigned_crl->crl_series);
	mbuf+=4;
	size-=4;

	hashed_length=buf_2_hashedid8(mbuf,size,&tobesigned_crl->ca_id);
    if(0>hashed_length)
	    return -1;
	mbuf+=hashed_length;
	size-=hashed_length;

	tobesigned_crl->crl_serial= get32(mbuf);
	tobesigned_crl->crl_serial= be_to_host32(tobesigned_crl->crl_serial);
	mbuf+=4;
	size-=4;

	tobesigned_crl->start_period= get32(mbuf);
	tobesigned_crl->start_period= be_to_host32(tobesigned_crl->start_period);
	mbuf+=4;
	size-=4;

	tobesigned_crl->issue_date= get32(mbuf);
	tobesigned_crl->issue_date= be_to_host32(tobesigned_crl->issue_date);
	mbuf+=4;
	size-=4;

	tobesigned_crl->next_crl= get32(mbuf);
	tobesigned_crl->next_crl= be_to_host32(tobesigned_crl->next_crl);
	mbuf+=4;
	size-=4;

	switch(tobesigned_crl->type){
		case ID_ONLY:
			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);
			tobesigned_crl->u.entries.len = data_length/10;

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			tobesigned_crl->u.entries.buf=(certid10*)malloc(sizeof(certid10)*tobesigned_crl->u.entries.len);
			if(NULL == tobesigned_crl->u.entries.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				decode_len = buf_2_certid10(mbuf,data_length-decode_len_sum,
						tobesigned_crl->u.entries.buf + i);
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			size -= data_length;
			return len-size;

		case ID_AND_EXPIRY:
			bitnum=head_bit_num(mbuf);
			data_length = variablelength_data_num(mbuf,bitnum);
			tobesigned_crl->u.expiring_entries.len = data_length/14;

			if(size < data_length + bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;

			tobesigned_crl->u.expiring_entries.buf=(id_and_date*)malloc(sizeof(id_and_date)*tobesigned_crl->u.expiring_entries.len);
			if(NULL == tobesigned_crl->u.expiring_entries.buf){
				return -1;
			}

			for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
				decode_len = buf_2_id_and_date(mbuf,data_length-decode_len_sum,
						tobesigned_crl->u.expiring_entries.buf + i);
				mbuf += decode_len;
				decode_len_sum += decode_len;
			}

			size -= data_length;
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			tobesigned_crl->u.other_entries.len=variablelength_data_num(mbuf,bitnum);
			if(size<tobesigned_crl->u.other_entries.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobesigned_crl->u.other_entries.buf=(u8*)malloc(sizeof(u8)*tobesigned_crl->u.other_entries.len);	
			if(NULL== tobesigned_crl->u.other_entries.buf){
				return -1;
			}
			fill_buf8( tobesigned_crl->u.other_entries.buf,mbuf, tobesigned_crl->u.other_entries.len);
			mbuf+= tobesigned_crl->u.other_entries.len*sizeof(u8);
			size-= tobesigned_crl->u.other_entries.len*sizeof(u8);
			return len-size;
	 }
}


//buf_2 35
u32 buf_2_crl(  u8* buf,   u32 len, crl* crl){
   	u8* mbuf = buf; 
	u32 size = len;
    u32 signer_length;
	u32 tobesigned_length;
	u32 signature_length;
	int n;

	if(size < 33){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	
	crl->version=get8(mbuf);
	mbuf++;
	size--;

    signer_length=buf_2_signer_identifier(mbuf,size,&crl->signer);
    if(0>signer_length)
	    return -1;
	mbuf+=signer_length;
	size-=signer_length;

    tobesigned_length=buf_2_tobesigned_crl(mbuf,size,&crl->unsigned_crl);
    if(0>tobesigned_length)
	    return -1;
	mbuf+=tobesigned_length;
	size-=tobesigned_length;

	switch(crl->signer.type){
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
			signature_length=buf_2_signature(mbuf,size, &crl->signature,ECDSA_NISTP224_WITH_SHA224);
			if(0>signature_length)
				return -1;
			mbuf+=signature_length;
			size-=signature_length;
			return len-size;

		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			signature_length=buf_2_signature(mbuf,size, &crl->signature,ECDSA_NISTP256_WITH_SHA256);
			if(0>signature_length)
				return -1;
			mbuf+=signature_length;
			size-=signature_length;
			return len-size;

		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			signature_length=buf_2_signature(mbuf,size, &crl->signature,crl->signer.u.other_algorithm.algorithm);
			if(0>signature_length)
				return -1;
			mbuf+=signature_length;
			size-=signature_length;
			return len-size;

		case CERTIFICATE:
			if(crl->signer.u.certificate.version_and_type == 2){
				signature_length= buf_2_signature(mbuf,size,&crl->signature,
						crl->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
				if(0>signature_length)
				return -1;
				mbuf+=signature_length;
				size-=signature_length;
				return len-size;
			}
			else if(crl->signer.u.certificate.version_and_type == 3){
				signature_length=buf_2_signature(mbuf,size,&crl->signature,
				crl->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
				if(0>signature_length)
					return -1;
				mbuf+=signature_length;
				size-=signature_length;
				return len-size;
			}

		case CERTIFICATE_CHAIN:
			n = crl->signer.u.certificates.len - 1;
			if((crl->signer.u.certificates.buf + n)->version_and_type == 2){
				signature_length = buf_2_signature(mbuf,size,&crl->signature,
						(crl->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
				mbuf+=signature_length;
				size-=signature_length;
			}
			else if((crl->signer.u.certificates.buf + n)->version_and_type == 3){
				signature_length= buf_2_signature(mbuf,size,&crl->signature,
						(crl->signer.u.certificates.buf + n)->unsigned_certificate.u.no_root_ca.signature_alg);
				mbuf+=signature_length;
				size-=signature_length;
			}
			return len-size;
		default:
			wave_error_printf("signer.type不符 %s %d",__FILE__,__LINE__);
			return -1;
	}  
 }

//buf_2 36
static u32 buf_2_tobe_encrypted_certificate_response_acknowledgment(u8* buf,u32 len,
		tobe_encrypted_certificate_response_acknowledgment* tobe_encrypted_certificate_response_acknowledgment){
	u8* mbuf = buf; 
	u32 size = len;
	int i;

	if (size < 10){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	for(i = 0; i < 10; i++ ){
	    tobe_encrypted_certificate_response_acknowledgment->response_hash[i] = get8(mbuf);
		mbuf++;
		size--;
	};
	return len-size;
}

//buf_2 37
u32 buf_2_tobe_encrypted_certificate_request_error(u8* buf,u32 len,
		tobe_encrypted_certificate_request_error* tobe_encrypted_certificate_request_error){
	u8* mbuf = buf; 
	u32 size = len;
	u32 signer_length;
	u32 certificate_length;
	u32 signature_length;
	int i;

	if(size<13){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

    signer_length=buf_2_signer_identifier(mbuf,size,&tobe_encrypted_certificate_request_error->signer);
    if(0>signer_length)
	    return -1;
	mbuf+=signer_length;
	size-=signer_length;

	for(i = 0; i < 10; i++ ){
	    tobe_encrypted_certificate_request_error->request_hash[i] = get8(mbuf);
		mbuf++;
		size--;
	}

    tobe_encrypted_certificate_request_error->reason=get8(mbuf);
	mbuf++;
	size--;

    switch(tobe_encrypted_certificate_request_error->signer.u.certificate.version_and_type){
		case 2:
			signature_length= buf_2_signature(mbuf,size,&tobe_encrypted_certificate_request_error->signature,
			tobe_encrypted_certificate_request_error->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
			if(signature_length< 0)
				return -1;
			mbuf+=signature_length;
			size-=signature_length;
			return len-size;

		case 3:
			signature_length= buf_2_signature(mbuf,size,&tobe_encrypted_certificate_request_error->signature,
			tobe_encrypted_certificate_request_error->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
			if(signature_length<0)
				return -1;
			mbuf+=signature_length;
			size-=signature_length;
			return len-size;
		default:
			wave_error_printf("version_and_type不符 %s %d",__FILE__,__LINE__);
			return -1;
	}
}

//buf_2 38

u32 buf_2_tobe_encrypted_certificate_response(  u8* buf, u32 len, tobe_encrypted_certificate_response* tobe_encrypted_certificate_response){
   	u8* mbuf = buf; 
	u32 size = len;
	u16 bitnum;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;
	int n;

	if(size<3) {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	tobe_encrypted_certificate_response->f=get8(mbuf);
	mbuf++;
	size--;

	bitnum=head_bit_num(mbuf);
	data_length = variablelength_data_num(mbuf,bitnum);

	if(size < data_length + bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;

	tobe_encrypted_certificate_response->certificate_chain.buf=(certificate*)malloc(sizeof(certificate)*1);
	if(NULL == tobe_encrypted_certificate_response->certificate_chain.buf){
		return -1;
	}

	for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
		tobe_encrypted_certificate_response->certificate_chain.buf=(certificate*)realloc(
				tobe_encrypted_certificate_response->certificate_chain.buf,sizeof(certificate)*(i+1));
		decode_len = buf_2_certificate(mbuf,data_length-decode_len_sum,
				tobe_encrypted_certificate_response->certificate_chain.buf + i);
		if(decode_len < 0)
			return decode_len;
		mbuf += decode_len;
		decode_len_sum += decode_len;
	}

	tobe_encrypted_certificate_response->certificate_chain.len = i;
	size -= data_length;
  
	n =  tobe_encrypted_certificate_response->certificate_chain.len - 1;
	switch((tobe_encrypted_certificate_response->certificate_chain.buf + n)->version_and_type){
		case 2:
			break;

		case 3:
			bitnum=head_bit_num(mbuf);
			tobe_encrypted_certificate_response->u.recon_priv.len=variablelength_data_num(mbuf,bitnum);
			if(size < tobe_encrypted_certificate_response->u.recon_priv.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobe_encrypted_certificate_response->u.recon_priv.buf=(u8*)malloc(sizeof(u8)*tobe_encrypted_certificate_response->u.recon_priv.len);	
			if(NULL== tobe_encrypted_certificate_response->u.recon_priv.buf){
				return -1;
			}
			fill_buf8( tobe_encrypted_certificate_response->u.recon_priv.buf,mbuf,
					tobe_encrypted_certificate_response->u.recon_priv.len);
			mbuf+= tobe_encrypted_certificate_response->u.recon_priv.len*sizeof(u8);
			size-= tobe_encrypted_certificate_response->u.recon_priv.len*sizeof(u8);
			break;

		default:
			bitnum=head_bit_num(mbuf);
			tobe_encrypted_certificate_response->u.other_material.len=variablelength_data_num(mbuf,bitnum);
			if(size < tobe_encrypted_certificate_response->u.other_material.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobe_encrypted_certificate_response->u.other_material.buf=(u8*)malloc(sizeof(u8)*tobe_encrypted_certificate_response->u.other_material.len);	
			if(NULL== tobe_encrypted_certificate_response->u.other_material.buf){
				return -1;
			}
			fill_buf8( tobe_encrypted_certificate_response->u.other_material.buf,mbuf,
					tobe_encrypted_certificate_response->u.other_material.len);
			mbuf+= tobe_encrypted_certificate_response->u.other_material.len*sizeof(u8);
			size-= tobe_encrypted_certificate_response->u.other_material.len*sizeof(u8);
			break;
	}

	bitnum=head_bit_num(mbuf);
	data_length = variablelength_data_num(mbuf,bitnum);

	if(size < data_length + bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;

	tobe_encrypted_certificate_response->crl_path.buf=(crl*)malloc(sizeof(crl)*1);
	if(NULL == tobe_encrypted_certificate_response->crl_path.buf){
		return -1;
	}

	for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
		tobe_encrypted_certificate_response->crl_path.buf=(crl*)realloc(
				tobe_encrypted_certificate_response->crl_path.buf,sizeof(crl)*(i+1));
		decode_len = buf_2_crl(mbuf,data_length-decode_len_sum,
				tobe_encrypted_certificate_response->crl_path.buf + i);
		if(decode_len < 0)
			return decode_len;
		mbuf += decode_len;
		decode_len_sum += decode_len;
	}

	tobe_encrypted_certificate_response->crl_path.len = i;
	size -= data_length;
	return len-size;
}


//buf_2 39
static u32 buf_2_tobesigned_certificate_request(  u8* buf,   u32 len, tobesigned_certificate_request* tobesigned_certificate_request){
   	u8* mbuf = buf; 
	u32 size = len;
	u32 cert_specific_data_length;
	u32 public_key_length1;
	u32 public_key_length2;
	u32 public_key_length3;
	u16 bitnum;

    if(size<17){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	tobesigned_certificate_request->version_and_type=get8(mbuf);
	mbuf++;
	size--;

	tobesigned_certificate_request->request_time= get32(mbuf);
	tobesigned_certificate_request->request_time= be_to_host32(tobesigned_certificate_request->request_time);
	mbuf+=4;
	size-=4;
    
	tobesigned_certificate_request->holder_type=get8(mbuf);
	mbuf++;
	size--;
    
	tobesigned_certificate_request->cf=get8(mbuf);
	mbuf++;
	size--;

	cert_specific_data_length=buf_2_cert_specific_data(mbuf,size,
			&tobesigned_certificate_request->type_specific_data,tobesigned_certificate_request->holder_type);
    if(0>cert_specific_data_length)
	    return -1;
	mbuf+=cert_specific_data_length;
	size-=cert_specific_data_length;

	tobesigned_certificate_request->expiration= get32(mbuf);
	tobesigned_certificate_request->expiration= be_to_host32(tobesigned_certificate_request->expiration);
	mbuf+=4;
	size-=4;

	if((tobesigned_certificate_request->cf & 1<<0)!= 0){
		if((tobesigned_certificate_request->cf & 1<<1)!=0){
			tobesigned_certificate_request->flags_content.lifetime= get16(mbuf);
			tobesigned_certificate_request->flags_content.lifetime= be_to_host16(tobesigned_certificate_request->flags_content.lifetime);
			mbuf+=2;
			size-=2;
		}else{
			tobesigned_certificate_request->flags_content.start_validity= get32(mbuf);
			tobesigned_certificate_request->flags_content.start_validity= be_to_host32(tobesigned_certificate_request->flags_content.start_validity);
			mbuf+=4;
			size-=4;
		}
	}

	if((tobesigned_certificate_request->cf & 1<<2)!=0){
		public_key_length1=buf_2_public_key(mbuf,size,&tobesigned_certificate_request->flags_content.encryption_key);
		if(0>public_key_length1)
			return -1;
		mbuf+=public_key_length1;
		size-=public_key_length1;
	}

	if((tobesigned_certificate_request->cf & 0xf8)!=0){
		bitnum=head_bit_num(mbuf);
		tobesigned_certificate_request->flags_content.other_cert.len=variablelength_data_num(mbuf,bitnum);
		if( size < tobesigned_certificate_request->flags_content.other_cert.len*sizeof(u8)+bitnum){
			wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
			return -1;
		}
		mbuf+=bitnum;
		size-=bitnum;
	     
		tobesigned_certificate_request->flags_content.other_cert.buf=(u8*)malloc(sizeof(u8)* tobesigned_certificate_request->flags_content.other_cert.len);	
		if(NULL== tobesigned_certificate_request->flags_content.other_cert.buf){
			return -1;
		}
		fill_buf8(tobesigned_certificate_request->flags_content.other_cert.buf,mbuf,
				tobesigned_certificate_request->flags_content.other_cert.len);
		tobesigned_certificate_request->flags_content.other_cert.len*sizeof(u8);
		tobesigned_certificate_request->flags_content.other_cert.len*sizeof(u8);
	}

	public_key_length2=buf_2_public_key(mbuf,size,&tobesigned_certificate_request->verification_key);
    if(0>public_key_length2)
	    return -1;
	mbuf+=public_key_length2;
	size-=public_key_length2;

	public_key_length3=buf_2_public_key(mbuf,size,&tobesigned_certificate_request->response_encryption_key);
    if(0>public_key_length3)
	    return -1;
	mbuf+=public_key_length3;
	size-=public_key_length3;

	return len-size;
}

//buf_2 40

static u32 buf_2_certificate_request(  u8* buf,   u32 len, certificate_request* certificate_request){
   	u8* mbuf = buf; 
	u32 size = len;	  
	u32 signer_length;
	u32 tobesigned_length;
	u32 signature_length;

	if(size<28){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

    signer_length=buf_2_signer_identifier(mbuf,size,&certificate_request->signer);
    if(0>signer_length)
		return -1;
	mbuf+=signer_length;
	size-=signer_length;

	tobesigned_length=buf_2_tobesigned_certificate_request(mbuf,size,&certificate_request->unsigned_csr);
    if(0>tobesigned_length)
		return -1;
	mbuf+=tobesigned_length;
	size-=tobesigned_length;

    switch(certificate_request->signer.type){
		case SELF:
			signature_length=buf_2_signature(mbuf,size,&certificate_request->signature,
					certificate_request->unsigned_csr.verification_key.algorithm);
			if(signature_length< 0)
				return -1;
			mbuf+=signature_length;
			size-=signature_length;
			return len-size;

		case CERTIFICATE:
			if(certificate_request->signer.u.certificate.version_and_type == 2){
				signature_length=buf_2_signature(mbuf,size,&certificate_request->signature,
						certificate_request->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm);
				if(signature_length<0)
					return -1;
				mbuf+=signature_length;
				size-=signature_length;
				return len-size;
			}
			else if(certificate_request->signer.u.certificate.version_and_type == 3){
				signature_length=buf_2_signature(mbuf,size,&certificate_request->signature,
						certificate_request->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
				if(signature_length< 0)
					return -1;
				mbuf+=signature_length;
				size-=signature_length;
				return len - size;
			}
		default:
			wave_error_printf("signer.type不符 %s %d",__FILE__,__LINE__);
			return -1;
	}
}

//buf_2 41

static u32 buf_2_tobesigned_data(  u8* buf,   u32 len, tobesigned_data* tobesigned_data,content_type type){
   	u8* mbuf = buf; 
	u32 size = len;	  
    u16 bitnum;
	u32 time64_length;
	u32 three_length;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size<28 ){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	tobesigned_data->tf = get8(mbuf);
	mbuf++;
	size--;
  

	switch(type){
		case SIGNED:
			decode_len = psid_decoding(mbuf,&tobesigned_data->u.type_signed.psid);
			if(decode_len < 0)
				return decode_len;
			mbuf += decode_len;
			size -= decode_len;

			bitnum=head_bit_num(mbuf);
			tobesigned_data->u.type_signed.data.len=variablelength_data_num(mbuf,bitnum);
			if(size<tobesigned_data->u.type_signed.data.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobesigned_data->u.type_signed.data.buf=(u8*)malloc(sizeof(u8)*tobesigned_data->u.type_signed.data.len);	
			if(NULL== tobesigned_data->u.type_signed.data.buf){
				return -1;
			}
			fill_buf8(tobesigned_data->u.type_signed.data.buf,mbuf,  tobesigned_data->u.type_signed.data.len);
			mbuf+= tobesigned_data->u.type_signed.data.len*sizeof(u8);
			size-= tobesigned_data->u.type_signed.data.len*sizeof(u8);
			break;

		case SIGNED_PARTIAL_PAYLOAD:
			decode_len = psid_decoding(mbuf,&tobesigned_data->u.type_signed_partical.psid);
			if(decode_len < 0)
				return decode_len;
			mbuf += decode_len;
			size -= decode_len;

			bitnum=head_bit_num(mbuf);
			tobesigned_data->u.type_signed_partical.ext_data.len=variablelength_data_num(mbuf,bitnum);
			if(size<tobesigned_data->u.type_signed_partical.ext_data.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobesigned_data->u.type_signed_partical.ext_data.buf=(u8*)malloc(sizeof(u8)*tobesigned_data->u.type_signed_partical.ext_data.len);	
			if(NULL== tobesigned_data->u.type_signed_partical.ext_data.buf){
				return -1;
			}
			fill_buf8(tobesigned_data->u.type_signed_partical.ext_data.buf,mbuf,  tobesigned_data->u.type_signed_partical.ext_data.len);
			mbuf+= tobesigned_data->u.type_signed_partical.ext_data.len*sizeof(u8);
			size-= tobesigned_data->u.type_signed_partical.ext_data.len*sizeof(u8);

			bitnum=head_bit_num(mbuf);
			tobesigned_data->u.type_signed_partical.data.len=variablelength_data_num(mbuf,bitnum);
			if(size<tobesigned_data->u.type_signed_partical.data.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobesigned_data->u.type_signed_partical.data.buf=(u8*)malloc(sizeof(u8)*tobesigned_data->u.type_signed_partical.data.len);	
			if(NULL== tobesigned_data->u.type_signed_partical.data.buf){
				return -1;
			}
			fill_buf8(tobesigned_data->u.type_signed_partical.data.buf,mbuf,  tobesigned_data->u.type_signed_partical.data.len);
			mbuf+= tobesigned_data->u.type_signed_partical.data.len*sizeof(u8);
			size-= tobesigned_data->u.type_signed_partical.data.len*sizeof(u8);
			break;

		case SIGNED_EXTERNAL_PAYLOAD:
			decode_len = psid_decoding(mbuf,&tobesigned_data->u.type_signed_external.psid);
			if(decode_len < 0)
				return decode_len;
			mbuf += decode_len;
			size -= decode_len;

			bitnum=head_bit_num(mbuf);
			tobesigned_data->u.type_signed_external.ext_data.len=variablelength_data_num(mbuf,bitnum);
			if(size<tobesigned_data->u.type_signed_external.ext_data.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobesigned_data->u.type_signed_external.ext_data.buf=(u8*)malloc(sizeof(u8)*tobesigned_data->u.type_signed_external.ext_data.len);	
			if(NULL== tobesigned_data->u.type_signed_external.ext_data.buf){
				return -1;
			}
			fill_buf8(tobesigned_data->u.type_signed_external.ext_data.buf,mbuf,  tobesigned_data->u.type_signed_external.ext_data.len);
			mbuf+= tobesigned_data->u.type_signed_external.ext_data.len*sizeof(u8);
			size-= tobesigned_data->u.type_signed_external.ext_data.len*sizeof(u8);
			break;

		default:
			bitnum=head_bit_num(mbuf);
			tobesigned_data->u.data.len=variablelength_data_num(mbuf,bitnum);
			if(size<tobesigned_data->u.data.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobesigned_data->u.data.buf=(u8*)malloc(sizeof(u8)*tobesigned_data->u.data.len);	
			if(NULL== tobesigned_data->u.data.buf){
				return -1;
			}
			fill_buf8( tobesigned_data->u.data.buf,mbuf, tobesigned_data->u.data.len);
			mbuf+= tobesigned_data->u.data.len*sizeof(u8);
			size-= tobesigned_data->u.data.len*sizeof(u8);
			break;
	}
  
	if((tobesigned_data->tf & 1<<0)!=0){
		time64_length=buf_2_time64_with_standard_deviation(mbuf,size,&tobesigned_data->flags_content.generation_time);
		if(0>time64_length)
			return -1;
		mbuf+=time64_length;
		size-=time64_length;
	}

	if((tobesigned_data->tf & 1<<1)!=0){
		tobesigned_data->flags_content.exipir_time= get64(mbuf);
		tobesigned_data->flags_content.exipir_time= be_to_host64(tobesigned_data->flags_content.exipir_time);
		mbuf+=8;
		size-=8;
	}

	if((tobesigned_data->tf & 1<<2)!=0){
		three_length=buf_2_three_d_location(mbuf,size,&tobesigned_data->flags_content.generation_location);
		if(0>three_length)
			return -1;
		mbuf+=three_length;
		size-=three_length;
	}

	if((tobesigned_data->tf & 1<<3)!=0){
		bitnum=head_bit_num(mbuf);
		data_length = variablelength_data_num(mbuf,bitnum);

		if(size < data_length + bitnum){
			wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
			return -1;
		}
		mbuf+=bitnum;
		size-=bitnum;

		tobesigned_data->flags_content.extensions.buf=(tbsdata_extension*)malloc(sizeof(tbsdata_extension)*1);
		if(NULL == tobesigned_data->flags_content.extensions.buf){
			return -1;
		}

		for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
			tobesigned_data->flags_content.extensions.buf=(tbsdata_extension*)realloc(
					tobesigned_data->flags_content.extensions.buf,sizeof(tbsdata_extension)*(i+1));
			decode_len = buf_2_tbsdata_extension(mbuf,data_length-decode_len_sum,
					tobesigned_data->flags_content.extensions.buf + i);
			if(decode_len < 0)
				return decode_len;
			mbuf += decode_len;
			decode_len_sum += decode_len;
		}

	   tobesigned_data->flags_content.extensions.len = i;
	   size -= data_length;
	}

	if((tobesigned_data->tf & 0xf0)!=0){
		bitnum=head_bit_num(mbuf);
		tobesigned_data->flags_content.other_data.len=variablelength_data_num(mbuf,bitnum);
		if(size < tobesigned_data->flags_content.other_data.len*sizeof(u8)+bitnum){
			wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
			return -1;
		}
		mbuf+=bitnum;
		size-=bitnum;
		tobesigned_data->flags_content.other_data.buf=(u8*)malloc(sizeof(u8)*tobesigned_data->flags_content.other_data.len);	
		if(NULL== tobesigned_data->flags_content.other_data.buf){
			return -1;
		}
		fill_buf8( tobesigned_data->flags_content.other_data.buf,mbuf, tobesigned_data->flags_content.other_data.len);
		mbuf+= tobesigned_data->flags_content.other_data.len*sizeof(u8);
		size-= tobesigned_data->flags_content.other_data.len*sizeof(u8);
	}
	return len-size;
}

/**
 *	将buf中的字节流转换成一个signed_data结构体，同样可以认为这个结构体指针指向了
 *	 一个分配好了的内存
 * @buf:装有字节流的buf
 * @len:字节流的长度
 * @signed_data 需要填充的数据结构指针
 * @type 外部传入参数
 *  返回值：0 失败; 大于零 成功返回占用了多少字节
 */
//buf_2 42
u32 buf_2_signed_data(  u8* buf,   u32 len, signed_data* signed_data, content_type type) {
	u8* mbuf = buf;
	u32 size = len;						
	u32 length_signed_data;//signed_data的字节长度
	u32 tobesigned_length;
	u32  signature_length;
	int n;

	if(size<30){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	length_signed_data = buf_2_signer_identifier(mbuf, size, &signed_data->signer);
	if(0 > length_signed_data)
			return -1;
	mbuf += length_signed_data;
	size -= length_signed_data;

	tobesigned_length = buf_2_tobesigned_data(mbuf, size, &signed_data->unsigned_data,type);
	if(0 > tobesigned_length)
			return -1;
	mbuf += tobesigned_length;
	size -= tobesigned_length;

	switch(signed_data->signer.type){
		case CERTIFICATE_DIGEST_WITH_ECDSAP224:
			signature_length=buf_2_signature(mbuf,size, &signed_data->signature,ECDSA_NISTP224_WITH_SHA224);
			if(0 > signature_length)
				return -1;
			mbuf +=signature_length;
			size -=signature_length;
			return len-size;

		case CERTIFICATE_DIGEST_WITH_ECDSAP256:
			signature_length=buf_2_signature(mbuf,size, &signed_data->signature,ECDSA_NISTP256_WITH_SHA256);
			if(0 > signature_length)
				return -1;
			mbuf +=signature_length;
			size -=signature_length;
			return len-size;

		case CERTIFICATE_DIGETS_WITH_OTHER_ALGORITHM:
			signature_length=buf_2_signature(mbuf,size, &signed_data->signature, signed_data->signer.u.other_algorithm.algorithm);
			if(0 > signature_length)
				return -1;
			mbuf +=signature_length;
			size -=signature_length;
			return len-size;

		case CERTIFICATE:
			if(signed_data->signer.u.certificate.version_and_type == 2){
				signature_length=buf_2_signature(mbuf,size, &signed_data->signature,
						signed_data->signer.u.certificate.unsigned_certificate.version_and_type.verification_key.algorithm );
				if(0 > signature_length)
					return -1;
				mbuf +=signature_length;
				size -=signature_length;
				return len-size;
			}
			else if(signed_data->signer.u.certificate.version_and_type == 3){
				signature_length=buf_2_signature(mbuf,size, &signed_data->signature,
						signed_data->signer.u.certificate.unsigned_certificate.u.no_root_ca.signature_alg);
				if(0 > signature_length)
					return -1;
				mbuf +=signature_length;
				size -=signature_length;
				return len-size;
			}

		case CERTIFICATE_CHAIN:
			n =  signed_data->signer.u.certificates.len - 1;
			if((signed_data->signer.u.certificates.buf + n)->version_and_type == 2){
				signature_length=buf_2_signature(mbuf,size,&signed_data->signature,
						(signed_data->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
				if(0 > signature_length)
					return -1;
				mbuf +=signature_length;
				size -=signature_length;
				return len-size;
			}
			else if((signed_data->signer.u.certificates.buf + n)->version_and_type == 3){
				signature_length=buf_2_signature(mbuf,size, &signed_data->signature,
						(signed_data->signer.u.certificates.buf + n)->unsigned_certificate.u.no_root_ca.signature_alg);
				if(0 > signature_length)
					return -1;
				mbuf +=signature_length;
				size -=signature_length;
				return len-size;
			}
		default:
			wave_error_printf("signer.type不符 %s %d",__FILE__,__LINE__);
	}
}

//buf_2 43
u32 buf_2_tobe_encrypted(  u8* buf,   u32 len, tobe_encrypted* tobe_encrypted) {
	u8* mbuf = buf;
	u32 size = len;
	u16 bitnum;
	u32  signed_length;
	u32  response_length;
	u32  anon_response_length;
	u32 request_length;
	u32 crl_request_length;
	u32 crl_length;
	u32 tobe_encrypted_length;

	if(size<2 ) {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	tobe_encrypted->type=get8(mbuf);
	mbuf++;
	size--;

	switch(tobe_encrypted->type){
		case UNSECURED:
			bitnum=head_bit_num(mbuf);
			tobe_encrypted->u.plain_text.len=variablelength_data_num(mbuf,bitnum);
			if( size < tobe_encrypted->u.plain_text.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobe_encrypted->u.plain_text.buf=(u8*)malloc(sizeof(u8)*tobe_encrypted->u.plain_text.len);	
			if(NULL==tobe_encrypted->u.plain_text.buf){
				return -1;
			}
			fill_buf8( tobe_encrypted->u.plain_text.buf,mbuf, tobe_encrypted->u.plain_text.len);
			mbuf+=tobe_encrypted->u.plain_text.len*sizeof(u8);
			size-=tobe_encrypted->u.plain_text.len*sizeof(u8);
			return len-size;

		case SIGNED:
		case SIGNED_EXTERNAL_PAYLOAD:
		case SIGNED_PARTIAL_PAYLOAD:  
			signed_length=buf_2_signed_data(mbuf,size,&tobe_encrypted->u.signed_data,tobe_encrypted->type);
			if(0>signed_length)
				return -1;
			mbuf+=signed_length;
			size-=signed_length;
			return len-size;
		
		case CERTIFICATE_REQUEST:
			request_length=buf_2_certificate_request(mbuf,size,&tobe_encrypted->u.request);
			if(0>request_length)
				return -1;
			mbuf+=request_length;
			size-=request_length;
			return len-size;
		
		case CERTIFICATE_RESPONSE:
			response_length=buf_2_tobe_encrypted_certificate_response(mbuf,size,&tobe_encrypted->u.response);
			if(0>response_length)
				return -1;
			mbuf+=response_length;
			size-=response_length;
			return len-size;
           
		case ANOYMOUS_CERTIFICATE_RESPONSE:
			tobe_encrypted->u.anon_response = get8(mbuf);
			mbuf++;
			size--;
			return len-size;

		case CERTIFICATE_REQUSET_ERROR:
			request_length=buf_2_tobe_encrypted_certificate_request_error(mbuf,size,&tobe_encrypted->u.request_error);
			if(0>request_length)
				return -1;
			mbuf+=request_length;
			size-=request_length;
			return len-size;

		case CONTENT_TYPE_CRL_REQUEST:
			crl_request_length=buf_2_crl_request(mbuf,size,&tobe_encrypted->u.crl_request);
			if(0>crl_request_length)
				return -1;
			mbuf+=crl_request_length;
			size-=crl_request_length;
			return len-size;

		case CRL:
			crl_length=buf_2_crl(mbuf,size,&tobe_encrypted->u.crl);
			if(0>crl_length)
				return -1;
			mbuf+=crl_length;
			size-=crl_length;
			return len-size;

		case CERTIFACATE_RESPONSE_ACKNOWLEDGMENT:
			tobe_encrypted_length=buf_2_tobe_encrypted_certificate_response_acknowledgment(mbuf,size,
					&tobe_encrypted->u.ack);
			if(0>tobe_encrypted_length)
				return -1;
			mbuf+=tobe_encrypted_length;
			size-=tobe_encrypted_length;
			return len-size;

        default:
			bitnum=head_bit_num(mbuf);
			tobe_encrypted->u.data.len=variablelength_data_num(mbuf,bitnum);
			if(size < tobe_encrypted->u.data.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			tobe_encrypted->u.data.buf=(u8*)malloc(sizeof(u8)*tobe_encrypted->u.data.len);	
			if(NULL==tobe_encrypted->u.data.buf){
				return -1;
			}
			fill_buf8( tobe_encrypted->u.data.buf,mbuf, tobe_encrypted->u.data.len);
			mbuf+=tobe_encrypted->u.data.len*sizeof(u8);
			size-=tobe_encrypted->u.data.len*sizeof(u8);
			return len-size;
	}
}

//buf_2 44
static u32 buf_2_aes_ccm_ciphertext(  u8* buf,   u32 len, aes_ccm_ciphertext* aes_ccm_ciphertext) {
	u8* mbuf = buf;
	u32 size = len;
	u16  bitnum;
	int i;

	if(size<13 )  {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	for(i = 0; i < 12; i++ ){
	    aes_ccm_ciphertext->nonce[i] = get8(mbuf);
		mbuf++;
		size--;
	}
      
	bitnum=head_bit_num(mbuf);
	aes_ccm_ciphertext->ccm_ciphertext.len=variablelength_data_num(mbuf,bitnum);
	if(size < aes_ccm_ciphertext->ccm_ciphertext.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
	    return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	aes_ccm_ciphertext->ccm_ciphertext.buf=(u8*)malloc(sizeof(u8)*aes_ccm_ciphertext->ccm_ciphertext.len);	
	if(NULL==aes_ccm_ciphertext->ccm_ciphertext.buf){
	    return -1;
	}
	fill_buf8(aes_ccm_ciphertext->ccm_ciphertext.buf,mbuf,aes_ccm_ciphertext->ccm_ciphertext.len);
	mbuf+=aes_ccm_ciphertext->ccm_ciphertext.len*sizeof(u8);
	size-=aes_ccm_ciphertext->ccm_ciphertext.len*sizeof(u8);
	return len-size;
}

//buf_2 45
static u32 buf_2_ecies_nist_p256_encrypted_key(  u8* buf,   u32 len, ecies_nist_p256_encrypted_key* ecies_nist_p256_encrypted_key) {
	u8* mbuf = buf;
	u32 size = len;
	u16  bitnum;
    u32 elliptic_length;
	int i;

	if(size<50 ) {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

    elliptic_length=buf_2_elliptic_curve_point(mbuf,size,&ecies_nist_p256_encrypted_key->v,ECIES_NISTP256);
    if(0>elliptic_length)
		return -1;
	mbuf+=elliptic_length;
	size-=elliptic_length;

	bitnum=head_bit_num(mbuf);
	ecies_nist_p256_encrypted_key->c.len=variablelength_data_num(mbuf,bitnum);
	if(size < ecies_nist_p256_encrypted_key->c.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	ecies_nist_p256_encrypted_key->c.buf=(u8*)malloc(sizeof(u8)*ecies_nist_p256_encrypted_key->c.len);	
	if(NULL==ecies_nist_p256_encrypted_key->c.buf){
		return -1;
	}
	fill_buf8(ecies_nist_p256_encrypted_key->c.buf,mbuf,ecies_nist_p256_encrypted_key->c.len);
	mbuf+= ecies_nist_p256_encrypted_key->c.len*sizeof(u8);
	size-= ecies_nist_p256_encrypted_key->c.len*sizeof(u8);

	for(i = 0; i < 20; i++ ){
	    ecies_nist_p256_encrypted_key->t[i] = get8(mbuf);
		mbuf++;
		size--;
	}
	return len-size;
}

//buf_2 46
static u32 buf_2_recipient_info(  u8* buf,   u32 len, recipient_info* recipient_info ,pk_algorithm pk_algorithm ) {
	u8* mbuf = buf;
	u32 size = len;
	u16  bitnum;
	u32  ecies_length;
	int i;
	u32  hashed_length;

	if(size<9 ) {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	
	hashed_length=buf_2_hashedid8(mbuf,size,&recipient_info->cert_id);
    if(0>hashed_length)
	    return -1;
	mbuf+=hashed_length;
	size-=hashed_length;


	switch(pk_algorithm){
		case ECIES_NISTP256:
			ecies_length=buf_2_ecies_nist_p256_encrypted_key(mbuf,size,&recipient_info->u.enc_key);
			if(0>ecies_length)
				return -1;
			mbuf+=ecies_length;
			size-=ecies_length;
			return len-size;

		default:
			bitnum=head_bit_num(mbuf);
			recipient_info->u.other_enc_key.len=variablelength_data_num(mbuf,bitnum);
			if(size < recipient_info->u.other_enc_key.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			recipient_info->u.other_enc_key.buf=(u8*)malloc(sizeof(u8)*recipient_info->u.other_enc_key.len);	
			if(NULL==recipient_info->u.other_enc_key.buf){
				return -1;
			}
			fill_buf8(recipient_info->u.other_enc_key.buf,mbuf,recipient_info->u.other_enc_key.len);
			mbuf+=recipient_info->u.other_enc_key.len*sizeof(u8);
			size-=recipient_info->u.other_enc_key.len*sizeof(u8);
			return len-size;
	}
}

//buf_2 47
//  
u32 buf_2_encrypted_data(  u8* buf,   u32 len, encrypted_data* encrypted_data) {
	u8* mbuf = buf;
	u32 size = len;
	u16 bitnum;
	u32 aes_length;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size<3 ) {
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	encrypted_data->symm_algorithm= get8(mbuf);
	mbuf++;
	size--;

	bitnum = head_bit_num(mbuf);
	data_length = variablelength_data_num(mbuf,bitnum);

	if(size < data_length + bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;

	encrypted_data->recipients.buf=(recipient_info*)malloc(sizeof(recipient_info)*1);
	if(NULL == encrypted_data->recipients.buf){
		return -1;
	}

	for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
		encrypted_data->recipients.buf=(recipient_info*)realloc(
				encrypted_data->recipients.buf,sizeof(recipient_info)*(i+1));
		decode_len = buf_2_recipient_info(mbuf,data_length-decode_len_sum,
				encrypted_data->recipients.buf + i,ECIES_NISTP256);
		if(decode_len < 0)
			return decode_len;
		mbuf += decode_len;
		decode_len_sum += decode_len;
	}

	encrypted_data->recipients.len = i;
	size -= data_length;


    
	switch(encrypted_data->symm_algorithm){
		case AES_128_CCM:
			aes_length=buf_2_aes_ccm_ciphertext(mbuf,size,&encrypted_data->u.ciphertext);
			if(0>aes_length)
				return -1;
			mbuf+=aes_length;
			size-=aes_length;
			return len-size;
		   
		default:
			bitnum=head_bit_num(mbuf);
			encrypted_data->u.other_ciphertext.len=variablelength_data_num(mbuf,bitnum);
			if(size < encrypted_data->u.other_ciphertext.len*sizeof(u8)+bitnum){
				wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
				return -1;
			}
			mbuf+=bitnum;
			size-=bitnum;
			encrypted_data->u.other_ciphertext.buf=(u8*)malloc(sizeof(u8)* encrypted_data->u.other_ciphertext.len);	
			if(NULL==encrypted_data->u.other_ciphertext.buf){
				return -1;
			}
			fill_buf8(encrypted_data->u.other_ciphertext.buf,mbuf,encrypted_data->u.other_ciphertext.len);
			mbuf+=encrypted_data->u.other_ciphertext.len*sizeof(u8);
			size-=encrypted_data->u.other_ciphertext.len*sizeof(u8);
			return len-size;
	}
}
  
// buf_2 48

static  u32 buf_2_tobesigned_wsa(  u8* buf,u32 len,tobesigned_wsa *tobesigned_wsa){
	u8* mbuf = buf;
	u32 size = len;
	u32 time64_length;
	u16 bitnum;
	u32 data_length;
	u32 decode_len;
	u32 decode_len_sum;
	int i;

	if(size < 30){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	bitnum = head_bit_num(mbuf);
	tobesigned_wsa->permission_indices.len = variablelength_data_num(mbuf,bitnum);
	if(size < tobesigned_wsa->permission_indices.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	tobesigned_wsa->permission_indices.buf=(u8*)malloc(sizeof(u8)*tobesigned_wsa->permission_indices.len);	
	if(NULL== tobesigned_wsa->permission_indices.buf){
		return -1;
	}
	fill_buf8( tobesigned_wsa->permission_indices.buf,mbuf,tobesigned_wsa->permission_indices.len);
	mbuf+= tobesigned_wsa->permission_indices.len*sizeof(u8);
	size-= tobesigned_wsa->permission_indices.len*sizeof(u8);

	tobesigned_wsa->tf= get8(mbuf);
	mbuf++;
	size--;

	bitnum = head_bit_num(mbuf);
	tobesigned_wsa->data.len=variablelength_data_num(mbuf,bitnum);
	if(size<tobesigned_wsa->data.len*sizeof(u8)+bitnum){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}
	mbuf+=bitnum;
	size-=bitnum;
	tobesigned_wsa->data.buf=(u8*)malloc(sizeof(u8)*tobesigned_wsa->data.len);	
	if(NULL== tobesigned_wsa->data.buf){
		return -1;
	}
	fill_buf8( tobesigned_wsa->data.buf,mbuf, tobesigned_wsa->data.len);
	mbuf+= tobesigned_wsa->data.len*sizeof(u8);
	size-= tobesigned_wsa->data.len*sizeof(u8);


	time64_length = buf_2_time64_with_standard_deviation(mbuf,size,&tobesigned_wsa->generation_time);
	if(0 > time64_length)
	   return -1;
    mbuf += time64_length;
	size -= time64_length;

	tobesigned_wsa->expire_time = get64(mbuf);
	tobesigned_wsa->expire_time = be_to_host64(tobesigned_wsa->expire_time);
	mbuf += 8;
	size -= 8;

 	u32 three_length = buf_2_three_d_location(mbuf,size,&tobesigned_wsa->generation_location);
	if(0 > three_length)
		return -1;
	mbuf += three_length;
    size -= three_length;

	if((tobesigned_wsa->tf & 1<<3)!=0){

		bitnum = head_bit_num(mbuf);
		data_length = variablelength_data_num(mbuf,bitnum);

		if(size < data_length + bitnum){
			wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
			return -1;
		}
		mbuf+=bitnum;
		size-=bitnum;

		tobesigned_wsa->flags_content.extension.buf=(tbsdata_extension*)malloc(sizeof(tbsdata_extension)*1);
		if(NULL == tobesigned_wsa->flags_content.extension.buf){
			return -1;
		}

		for(decode_len_sum=0,i=0;decode_len_sum < data_length;i++){
			tobesigned_wsa->flags_content.extension.buf=(tbsdata_extension*)realloc(
					tobesigned_wsa->flags_content.extension.buf,sizeof(tbsdata_extension)*(i+1));
			decode_len = buf_2_tbsdata_extension(mbuf,data_length-decode_len_sum,
					tobesigned_wsa->flags_content.extension.buf + i);
			if(decode_len < 0)
				return decode_len;
			mbuf += decode_len;
			decode_len_sum += decode_len;
		}

	   tobesigned_wsa->flags_content.extension.len = i;
	   size -= data_length;
	  }

	if((tobesigned_wsa->tf & 0xf0)!=0){
		bitnum = head_bit_num(mbuf);
		tobesigned_wsa->flags_content.other_data.len=variablelength_data_num(mbuf,bitnum);
		if(size<tobesigned_wsa->flags_content.other_data.len*sizeof(u8)+bitnum){
			wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
			return -1;
		}
		mbuf+=bitnum;
		size-=bitnum;
		tobesigned_wsa->flags_content.other_data.buf=(u8*)malloc(sizeof(u8)*tobesigned_wsa->flags_content.other_data.len);
		if(NULL== tobesigned_wsa->flags_content.other_data.buf){
			return -1;
		}
		fill_buf8( 	tobesigned_wsa->flags_content.other_data.buf,mbuf, tobesigned_wsa->flags_content.other_data.len);	
		mbuf+= tobesigned_wsa->flags_content.other_data.len*sizeof(u8);
		size-= tobesigned_wsa->flags_content.other_data.len*sizeof(u8);
	}

	return len-size;
}




//buf_2_49
u32 buf_2_signed_wsa(  u8* buf,  u32 len,signed_wsa *signed_wsa){
	u8* mbuf = buf;
	u32 size = len;
	u32 signer_len;
	u32 unsigned_wsa_len;
	u32 signature_len;
	int n;

	if(size < 32){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
		return -1;
	}

	signer_len = buf_2_signer_identifier(mbuf,size,&signed_wsa->signer);
	if(0 > signer_len)
		return -1;
	mbuf += signer_len;
	size -+ signer_len;

	unsigned_wsa_len = buf_2_tobesigned_wsa(mbuf,size,&signed_wsa->unsigned_wsa);
	if(0 > unsigned_wsa_len)
		return -1;
	mbuf += unsigned_wsa_len;
	size -= unsigned_wsa_len;

	n = signed_wsa->signer.u.certificates.len - 1;
	if((signed_wsa->signer.type == CERTIFICATE_CHAIN) &&
			((signed_wsa->signer.u.certificates.buf + n)->version_and_type == 2)){
		signature_len = buf_2_signature(mbuf,size,&signed_wsa->signature,
			(signed_wsa->signer.u.certificates.buf + n)->unsigned_certificate.version_and_type.verification_key.algorithm);
	}else{
		signature_len = buf_2_signature(mbuf,size,&signed_wsa->signature,ECDSA_NISTP256_WITH_SHA256);
	}
	if(0 > signature_len)
		return -1;
	return len-size;
}

/**
 *	将buf里面的字节流，转化成一个sec_data结构体，对于这个结构体指针，
 *	 这个接口可以认为这个指针指向了一个分配好的内存
 *  @buf:装有字节流的buf
 *  @len:字节流的长度
 *  @sec:需要填充的数据结构
 *  return: -1：转换失败；0 ：转换成功
 */

u32 buf_2_sec_data(  u8* buf,  u32 len, sec_data* sec_data){
    u8* mbuf = buf;
    u32 size = len;
    //检查长度是否满足最低要求
    if(size < 3){
		wave_error_printf("填充数据不足 %s %d",__FILE__,__LINE__);
        return -1;
	}
	//
    sec_data->protocol_version = get8(mbuf);   //填充协议版本
    mbuf = mbuf + 1;
    size = size - 1;
    if(sec_data->protocol_version != CURRETN_VERSION ){
		wave_error_printf("填充协议版本不符 %s %d",__FILE__,__LINE__);
        return -1;
	}
  
    sec_data->type = get8(mbuf);              //填充content_type
    mbuf = mbuf + 1;
    size = size - 1;
    
    switch(sec_data->type){
        case UNSECURED:
			//应该先用一字节编码,表明所用数据的字节长度，然后再分配内存
			sec_data->u.data.len = get8(mbuf);
			mbuf += 1;
            sec_data->u.data.buf = (u8*)malloc(sizeof(u8)*sec_data->u.data.len);//填充opaque
            if(sec_data->u.data.buf == NULL){
                return -1;
			}

            sec_data->u.data.buf = mbuf;//单个数据的大小位u8，所以不需要大小端转换函数
            mbuf += sec_data->u.data.len;			//已经结束了，mbuf指针没有必要再移位了
            return 0;
        case SIGNED:
        case SIGNED_PARTIAL_PAYLOAD:
        case SIGNED_EXTERNAL_PAYLOAD:
            if(buf_2_signed_data(mbuf,size,&sec_data->u.signed_data, sec_data->type) < 0)//需要完成signdata函数填充，同样内存结构体内存已经分配好了
				return -1;
            return 0;
        case SIGNED_WSA:
            if(buf_2_signed_wsa(mbuf,size,&sec_data->u.signed_wsa) < 0)//同上
                return -1;
            return 0;
        case ENCRYPTED:
            if(buf_2_encrypted_data(mbuf,size,&sec_data->u.encrypted_data) < 0)//
				return -1;
            return 0;
        case CONTENT_TYPE_CRL_REQUEST:
            if(buf_2_crl_request(mbuf,size,&sec_data->u.crl_request) < 0)//
				return -1;
            return 0;
        case CRL:
            if(buf_2_crl(mbuf,size,&sec_data->u.crl) < 0)//
				return -1;
            return 0;
        default:
            sec_data->u.other_data.len = get8(mbuf);
			mbuf++;
			sec_data->u.other_data.buf = (u8*)malloc(sizeof(u8)*sec_data->u.other_data.len);//
            if(sec_data->u.other_data.buf == NULL){
				return -1;
			}
            sec_data->u.other_data.buf = mbuf;
			mbuf += sec_data->u.other_data.len;
			return 0;
	}
}

