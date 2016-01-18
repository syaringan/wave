/*************************************************************************
    > File Name: netlink.h
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2015年11月23日 星期一 14时54分46秒
 ************************************************************************/
#ifndef __NETLINK_H
#define __NETLINK_H

#include "common.h"
#include <linux/netlink.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_PAYLOAD 1024
#define TYPE_UNSECURED 0
#define TYPE_SIGNED_WSA 11
enum serv_type{
    DOT2_PID = 14,
};

enum serv_operation{
    SET_MIB = 1,
};

typedef enum{
	SIGN = 1,
	VERIFY = 2,
}dot3_req_type;

typedef enum{
	DOT2_SIGN_SUCCESS,
	DOT2_SIGN_FAILURE
}dot2_wsa_sign_result_code;

typedef enum{
	// these two indicate success cases
	DOT2_SUCCESS,
	DOT2_UNSECURED,
	// failure cases
	DOT2_INVALID_INPUT,
	DOT2_UNDEFINED,
	DOT2_NOT_MOST_RECENT_WSA,
	DOT2_FUTURE_CERT_AT_GENTIME,
	DOT2_EXPIRED_CERT_AT_GENTIME,
	DOT2_EXPIRE_DATE_TOO_EARLY,
	DOT2_EXPIRE_DATA_TOO_LATE,
	DOT2_OTHER_FALURE,
}dot2_user_avail_result_code;

typedef enum result_code{
	RES_ACCPTED = 0,
	RES_RJ_INVAL,
	RES_RJ_UNSPEC,
}result_code;

struct confirm_content{
	unsigned short local_index;
	result_code result;
};

struct wme_dot2_pid_request{
    enum serv_type type;
    enum serv_operation operat;

    u32 pid;
};

struct wme_generic_service_request{
    enum serv_type type;
    enum serv_operation operat;

    char pad[1020];
};

/*
 * Used to get wsa message version and type from 
 * a 1609Dot2Message reveived.
 *
 * 1609Dot2Message format:
 * +------------------+--------+---------------------------------+
 * | protocol version |  type  | WSA or SignedMessage per 1609.2 |
 * +------------------+--------+---------------------------------+
 */
struct dot2_wsa_message {
	u8 version;
    u8 type;		
	// received wsa
}__attribute__((packed));

/* 
 * WSA wraped by WME:
 *                                                			|<-------------------------------- wsa_len -------------------------------->|
 * +---------+-----------+--------------+---------+---------+--------------+-----------------------+-----------------------+------------+----------------+
 * | wsa_len | broadcast | change count | channel |lifetime |  WSA header  | array of service info | array of channel info |    wra     |   permissions  |
 * +---------+-----------+--------------+---------+---------+--------------+-----------------------+-----------------------+------------+----------------+
 *
 * |<----------------------------------- permission one --------------------------------->|<--------- subsequent permissions ---...     
 * |                                          |<- psid_len ->|<- ssp_len ->|<- pssi_len ->|
 * +----------+----------+---------+----------+--------------+-------------+--------------+----------+----------+---
 * | priority | psid_len | ssp_len | pssi_len |     psid     |     ssp     |     pssi     | priority | psid_len |   ... ...
 * +----------+----------+---------+----------+--------------+-------------+--------------+----------+----------+---
 */
struct permission{
	u8 priority;
	u8 psid_len;
	u8 ssp_len;
	u8 pssi_len;
	// psid content
	// ssp content
	// pssi content
}__attribute__((packed));

struct wme_tobe_signed_wsa {
    dot3_req_type type;
	u32 wsa_len;
	u32 broadcast;
	u8  change_count;
	u8  channel;
	u32 lifetime;
	// To be signed wsa content;
	// Array of permissions;
}__attribute__((packed));

/* 
 * Signed wsa:
 * 			 									  			    |<------------------------ wsa_len ------------------------->|
 * +---------+-----------+--------------+---------+-------------+------------------+--------+--------------------------------+
 * | wsa_len | broadcast | change count | channel | result code | protocol version |  type  |    SignedMessage per 1609.2    |
 * +---------+-----------+--------------+---------+-------------+------------------+--------+--------------------------------+
 */
struct dot3_signed_wsa {
	u32 wsa_len;
	u32 broadcast;
	u8  change_count;
	u8  channel;
	u8  result_code;
	// signed wsa content
}__attribute__((packed));

/*
 * Received signed wsa, need to be verified. It is sent to
 * 1609.2 together will its cource mac address and rcpi.
 *
 * To be verified wsa:
 *										   |<----- wsa_len ----->|
 * +--------------------+--------+---------+---------------------+
 * | source mac address |  rcpi  | wsa_len | Signed wsa Received |
 * +--------------------+--------+---------+---------------------+
 */
struct dot2_tobe_verified_wsa {
    dot3_req_type type;
	u8  src_mac[6];
	s8  rcpi;
	
	u32 wsa_len;
	// wsa content
}__attribute__((packed));

/* Wsa verified with no dot2 header. 
 * Parameters from 1609.4 and 1609.2
 * 
 * Verified wsa format:
 *												                                        
 * +-----+--------------------+------+-------------+---------+-----------------+-------------+---------+-----------------+ 
 * | pid | source mac address | rcpi | result code | wsa_len | generation time | expire time | ssp_len |next_crl_time_len| ----->
 * +-----+--------------------+------+-------------+---------+-----------------+-------------+---------+-----------------+ 
 *												 |<-- wsa_len -->|<---- ssp_len ---->|<- next_crl_time_len ->|
 * 												 +---------------+-------------------+-----------------------+
 *					                        ---> | validated wsa |   array of ssp    |   array of crl time   |
 *												 +---------------+-------------------+-----------------------+
 */
struct verified_wsa {
	// 1609.2 have no need to fill in this element
	u32  pid;     
	u8   src_mac[6];
	s8   rcpi;
	dot2_user_avail_result_code 
	     result_code[2];
	u32  wsa_len;
	u64  gen_time;
	u64  expire_time; // life time
	u32  ssp_len;
	u32  next_crl_time_len;
	// validated wsa
	// array of ssp
	// array of expected crl time
}__attribute__((packed));

/* Unsecured wsa with dot2 header repaced by a header defined in our implementation.
 * Parameters from 1609.4
 *
 * Translated unsecured wsa format:
 * 												             |<- wsa_len ->|
 * +-----+--------------------+------+-------------+---------+-------------+
 * | pid | source mac address | rcpi | result code | wsa_len | wsa content |
 * +-----+--------------------+------+-------------+---------+-------------+
 *
 * unsecured_wsa and verified wsa header have the same leading part.
*/
struct unsecured_wsa {
    u32 pid;  // always zero
    u8  src_mac[6];
    s8  rcpi;
    dot2_user_avail_result_code 
        result_code;
	u32 wsa_len;
}__attribute__((packed));


int dot2_init_netlink(struct nlmsghdr *nlh, struct msghdr *msg);
int create_netlink(struct msghdr *msg, struct nlmsghdr *nlh);

#endif
