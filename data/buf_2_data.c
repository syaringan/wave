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
#include"data.h"
#include<stdlib.h>
#include<stddef.h>

#define get8(addr)  *( (u8*)addr  )
#define get16(addr) *( (u16*)addr )
#define get32(addr) *( (u32*)addr )
#define get64(addr) *( (u64*)addr )

#define CURRETN_VERSION 2

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
		return 3
	else if(ll <= 0xef)
		return 4;
	else if(ll <= 0xf7)
		return 5; 
	else if(ll <= 0xfb)
		return 6;
	else if(ll <= 0xfd)
		return 7;
	else(ll <= 0xfe)
		return 8;
}
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
		case 2;
			full_encoding_length16 = get16(mbuf);
			full_encoding_length16 = be_to_host16(full_encoding_length16);
			return full_encoding_length16 & 0x3fff;
		case 3;
			full_encoding_length32 = get32(mbuf);
			full_encoding_length32 = be_to_host32(full_encoding_length32;)
			full_encoding_length32 = full_encoding_length32>>8;
			full_encoding_length32 = full_encoding_length32 & 0x003fffff;
			return (u16)full_encoding_lenth32;
		case 4;
			full_encoding_length32 = get32(mbuf);
			full_encoding_length32 = be_to_host32(full_encoding_length32);
			full_encoding_length32 = full_encoding_length32;
			full_encoding_length32 = full_encoding_length32 & 0x0fffffff;
			return (u16)full_encoding_length32;
		case 5;
			full_encoding_length64 = get64(mbuf);
			full_encoding_length64 = be_to_host64(full_encoding_length64);
			full_encoding_length64 = full_encoding_length64 >> 24;
			full_encoding_length64 = full_encoding_length64 & 0x00000007ffffffff;
			return (u16)full_encoding_length64
		case 6:
			full_encoding_length64 = get64(mbuf);
			full_encoding_length64 = be_to_host64(full_encoding_length64);
			full_encoding_length64 = full_encoding_length64 >> 16;
			full_encoding_length64 = full_encoding_length64 & 0x000003ffffffffff;
			return (u16)full_encoding_length64;
		case 7:
			full_encoding_length64 = get64(mbuf);
			full_encoding_length64 = be_to_host64(full_encoding_length64);
			full_encoding_length64 = full_encoding_length64 >> 8;
			full_encoding_length64 = full_encoding_length64 & 0x0001ffffffffffff;
			return (u16)full_encoding_length64;
		case 8:
			full_encoding_length64 = get64(mbuf);
			full_encoding_length64 = be_to_host64(full_encoding_length64);
			full_encoding_length64 = full_encoding_length64 & 0x00ffffffffffffff;
			return (u16)full_encoding_length64;
}
/**
 * buf_to 1
 */
static u32 buf_2_time64_with_standard_deviation(const u8* buf, const u32 len, 
				time64_with_standard_deviation* time64_with_standard_deviation){
	u8* mbuf = buf;
	u32 size = len;
	//u32 used_length = 0;
	
	if(size < 9)
		return 0;
	
	time64_with_standard_deviation->time = get64(mbuf);
	time64_with_standard_deviation->time = be_to_host64(time64_with_standard_deviation->time);  //定义在wave/utils/common.h中
	mbuf += 4;
	size -= 4;
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

static u32 buf_2_tbsdata_extension(const u8* buf, const u32 len, tbsdata_extion* tbsdata_extion){
	u8* mbuf = buf;
	u32 size = len;
	u16 bitnum;//代表头部编码长度
	
	if(size < 2)
		return 0;
	tbsdata_extension->type = get8(mbuf);
	mbuf += 1;
	size -= 1;
			

	bitnum = head_bit_num(mbuf);
	tbsdata_extension->value.len = variablelength_data_num(mbuf, bitnum);
	if(size < tbsdata_extension->value.len*sizeof(u8)+bitnum)
		return 0;
		
	mbuf += bitnum;
	size -= bitnum;
	tbsdata_extension->value.buf = (u8*)malloc(sizeof(u8)*tbsdata_extension->value.len);
	if(NULL == tbsdata_extension->value.buf )
		return 0;
	fill_buf8(buf, mbuf, tbsdata_extension->value.len);
	mbuf+= tbsdata_extension->value.len *sizeof(u8);
	size -= tbsdata_extension->value.len * sizeof(u8);
	return len - size;
}
/**
 *	buf_to 3
 */
static u32 buf_2_three_d_location(const u8* buf, const u32 len, three_d_location* three_d_location){
	u8* mbuf = buf;
	u32 size = len;
	//u32 used_length = 0;

	if(size >= 4 ){
		three_d_location->latitude	= get32(mbuf);
		be_to_host32(three_d_location->latitude)
		mbuf += 4;
		size -= 4;
	//	used_lenth += 4;
	}
	if(size >= 4){
		three_d_location->longitude = get32(mbuf);
		be_to_host32(three_d_location->longitude);
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
		return len - size;
	}
	return 0;
}

/**
 *	buf_to 4
 */
static u32 buf_2_hashedid8(const u8* buf, const u32 len, hashedid8* hashedid8){
	u8* mbuf = buf; 
	u32 size = len;
	int i;
	if (size < 8)
		return 0;
	for(i = 0; i < 8; i++ ){
		hashedid8->hashedid[i] = get8(mbuf);
		mbuf++;
	}
	return 8;
}

/**
 *	buf_to 5
 *	@pk_algorithm 外部传入参数
 *	@field_size 外部传入参数，注意在填充结构体时，外部传入参数是不需要真正填充进结构体的
 *	因为结构体定义中，并没有extern数据，而且编码中，extern也没有编在buf所指像的网络流中
 */
static u32 buf_2_elliptic_curve_point(const u8* buf, const u32 len, 
				elliptic_curve_point* elliptic_curve_point, pk_algorithm pk_algorithm){
	u8 mbuf = buf;
	u32 size = len;
	u16 bitnum;

	if(size < 2)
		return 0;
	elliptic_curve_point->type = get8(mbuf);
	mbuf++;
	size--;

	bitnum = head_bit_num(mbuf);
	elliptic_curve_point->x.len = variablelength_data_num(mbuf, bitnum);
	mbuf += bitnum;
	if(size < bitnum + elliptic_curve_point->x.len*sizeof(u8))
		return 0;
	elliptic_curve_point->x.buf = (u8*)malloc(sizeof(u8)* elliptic_curve_point->x.len);
	fill_buf8(elliptic_curve_point->x.buf, mbuf, elliptic_curve_point->x.len);
	mbuff += elliptic_curve_point->x.len * sizeof(u8);
	size -= elliptic_curve_point->x.len * sizeof(u8);

	if(elliptic_curve_point->type == UNCOMPRESSED){
		bitnum = head_bit_num(mbuf);
		elliptic_curve_point->u.y.len = variablelength_data_num(mbuf, bitnum);
		mbuf += bitnum;
		if(size < bitnum + elliptic_curve_point->u.y.len*sizeof(u8))
			return 0;
		elliptic_curve_point->u.y.buf = (u8*)malloc(sizeof(u8)* elliptic_curve_point->u.y.len);
		fill_buf8(elliptic_curve_point->u.y.buf, mbuf, elliptic_curve_point->u.y.len);
		mbuff += elliptic_curve_point->u.y.len * sizeof(u8);
		size -= elliptic_curve_point->u.y.len * sizeof(u8);
	}
	return len - size;
}
/**
 *	buf_to 6
 *
 */
static u32 buf_2_ecdsa_signature(const u8* buf,const u32 len,ecdsa_signature* ecdsa_signature, 
		pk_algorithm pk_algorithm){
	u8* mbuf = buf;
	u16 bitnum ;

	u32 size = len;
	u32 elliptic_length;
	elliptic_length = buf_2_elliptic_curve_point(mbuf,len, &ecdsa_signature->elliptic_curve_point, pk_algorithm);
	if(0 == elliptic_length)
		return 0;
	mbuf += elliptic_length;
	size -= elliptic_length;
	
	if(size < 2)
		return 0;
	bitnum = head_bit_num(mbuf);
	mbuf += bitnum;
	size -= bitnum;
	ecdsa_signature->s.len = variablelength_data_num(mbuf, bitnum);

	if(size < ecdsa_signature->s.len*sizeof(u8))
		return 0;
	ecdsa_signature->s.buf = (u8*)malloc(sizeof(u8)*ecdsa_signature->s.len);
	fill_buf8(ecdsa_signature->s.buf, mbuf, ecdsa_signature->s.len);//填充buff
	mbuf += ecdsa_signature->s.len;
	size -= ecdsa_signature->s.len;
	
	return len - size;
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
static u32 buf_2_signed_data(const u8* buf, const u32 len, signed_data* signed_data, content_type type) {
	u8* mbuf = buf;
	u32 size = len;
							
	u32 lenth_signed_data;//signed_data的字节长度
	length_signed_data = buf_2_signer_identifier(mbuf, size, &signed_data->signer);
	if(NULL == length_signed_data)
			return 0;
	mbuf += length_signed_data;
	size -= length_signed_data;// 还没有写完哈
}
/**
 *	将buf里面的字节流，转化成一个sec_data结构体，对于这个结构体指针，
 *	 这个接口可以认为这个指针指向了一个分配好的内存
 *  @buf:装有字节流的buf
 *  @len:字节流的长度
 *  @sec:需要填充的数据结构
 *  return: -1：转换失败；0 ：转换成功
 */
u32 buf_2_sec_data(const u8* buf,const u32 len, sec_data* sec_data){
    u8* mbuf = buf;
    u32 size = len;
    //检查长度是否满足最低要求
    if(size < 4)
        return -1;
	//
    sec_data->protocol_version = get8(mbuf);   //填充协议版本
    mbuf = mbuf + 1;
    size = size - 1;
    if(sec_data->protocol_version != CURRETN_VERSION )
        return -1;							   
  
    sec_data->type = get8(mbuf);              //填充content_type
    mbuf = mbuf + 1;
    size = size - 1;
    
    switch(sec_data->type){
        case UNSECURED:
			//应该先用一字节编码,表明所用数据的字节长度，然后再分配内存
			sec_data->u.data.len = get8(mbuf);
			mbuf += 1;
            sec_data->u.data.buf = (u8*)malloc(sizeof(u8)*sec_data->u.data.len);//填充opaque
            if(sec_data->u.data.buf == NULL)
                return -1;

            sec_data->u.data.buf = mbuf;//单个数据的大小位u8，所以不需要大小端转换函数
            mbuf += u.data.len;			//已经结束了，mbuf指针没有必要再移位了
            return 0;
        case SIGNED:
        case SIGNED_PARTIAL_PAYLOAD:
        case SIGNED_EXTERNAL_PAYLOAD:
            if(!buf_2_signed_data(mbuf,size,&sec_data->u.signed_data, sec_data->type))//需要完成signdata函数填充，同样内存结构体内存已经分配好了
                return -1;
            return 0;
        case SIGNED_WSA:
            if(!buf_2_signed_wsa(mbuf,size,&sec_data->u.signed_wsa))//同上
                return -1;
            return 0;
        case ENCRYPTED:
            if(!buf_2_encrypted_data(mbuf,size,&sec_data->u.encrypted_data))//
                 return -1;
            return 0;
        case CONTENT_TYPE_CRL_REQUEST:
            if(!buf_2_crl_request(mbuf,size,&sec_data->u.crl_request))//
                 return -1;
            return 0;
        case CRL:
            if(!buf_2_crl(mbuf,size,&sec_data->u.crl))//
                 return -1;
            return 0;
        default:
            sec_data->u.other_data.len = get8(mbuf);
			mbuf++;
			sec_data->u.other_data.buf = (u8*)malloc(sizeof(u8)*sec_data->u.other_data.len);//
            if(sec_data->u.other_data.buf == NULL)
                 return -1;
            sec_data->u.other_data.buf = mbuf;
			mbuf += sec_data->u.other_data.len;
            //sec_data->u.other_data.len = size;

    }
    return 0;
}

