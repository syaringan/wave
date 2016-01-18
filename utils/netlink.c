/*************************************************************************
    > File Name: netlink.c
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2015年11月23日 星期一 15时20分19秒
 ************************************************************************/

#include "netlink.h"
#include "debug.h"
#include <sys/types.h>
#include <unistd.h>

#define NETLINK_WAVE 21
int errno;
int create_netlink(struct msghdr *msg, struct nlmsghdr *nlh)
{
    int fd;
    struct sockaddr_nl src_addr, *dest_addr;
    struct iovec *iov = NULL;
	iov = (struct iovec *)malloc(sizeof(*iov));
	dest_addr = (struct sockaddr_nl*)malloc(sizeof(struct sockaddr_nl));
	if(!dest_addr || !iov){
		wave_malloc_error();
		return -1;
	}
    //NETLINK_WAVE是需要和.3的模块统一的，需要在linux/netlink.h中添加一个新的协议类型 21
    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_WAVE);
    if(fd < 0){
        wave_error_printf("创建fd失败");
        return -1;
    }
    memset(&src_addr, 0, sizeof(struct sockaddr_nl));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */
    src_addr.nl_groups = 0; /* not in mcast groups */
    if(bind(fd, (struct sockaddr*)&src_addr, sizeof(struct sockaddr_nl)) < 0){
        wave_error_printf("绑定失败");
        return -1;
    }
    memset(dest_addr, 0, sizeof(struct sockaddr_nl));
    dest_addr->nl_family = AF_NETLINK;
    dest_addr->nl_pid = 0; /* For Linux Kernel */
    dest_addr->nl_groups = 0; /* unicast */
    /* Fill the netlink message header */
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid(); /* self pid */
    nlh->nlmsg_flags = 0;
    /* Fill in the netlink message payload */
	memset(iov, 0, sizeof(*iov));
    iov->iov_base = (void *)nlh;
    iov->iov_len = nlh->nlmsg_len;
    msg->msg_name = (void *)dest_addr;
    msg->msg_namelen = sizeof(struct sockaddr_nl);
    msg->msg_iov = iov;
    msg->msg_iovlen = 1;
    return fd;
}

int dot2_init_netlink(struct nlmsghdr *nlh, struct msghdr *msg){
    int ret =0;
	struct confirm_content *confirm;
    struct wme_dot2_pid_request req;

    req.type = DOT2_PID;
    req.operat = SET_MIB;
    req.pid = getpid();

    int fd = create_netlink(msg, nlh);
    if(fd < 0){
        wave_error_printf("fd创建失败");
        return -1;
    }
    memcpy(NLMSG_DATA(nlh), &req, sizeof(struct wme_generic_service_request));
    ret = sendmsg(fd, msg, 0);
	perror(strerror(errno));
    if(ret < 0){
        wave_error_printf("netlink发送消息失败");
        return -1;
    }
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	ret = recvmsg(fd, msg, 0);
	if(ret < 0){
		wave_error_printf("netlink recvmsg error");
		return -1;
	}
	confirm = (struct confirm_content*)NLMSG_DATA(nlh);
	if(confirm->result != RES_ACCPTED){
		wave_error_printf("zhu ce fail!");
		return -1;
	}
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    return fd;
}

