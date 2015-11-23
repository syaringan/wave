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
#include <stdio.h>

#define MAX_PAYLOAD 1024
enum serv_type{
    DOT2_PID = 14;
};

enum serv_operation{
    SET_MIB = 1,
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

void dot2_init_netlink(struct nlmsghdr *nlh, struct msghdr *msg);
int create_netlink(struct msghdr *msg, struct nlmsghdr *nlh);
