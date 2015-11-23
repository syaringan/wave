/*************************************************************************
    > File Name: netlink.c
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2015年11月23日 星期一 15时20分19秒
 ************************************************************************/

#include "netlink.h"

int create_netlink(struct msghdr *msg, struct nlmsghdr *nlh)
{
    int fd;
    struct sockaddr_nl src_addr, dest_addr;
    struct iovec iov;
    fd = socket(PF_NETLINK, SOCK_RAW, 21);
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
    memset(&dest_addr, 0, sizeof(struct sockaddr_nl));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */
    /* Fill the netlink message header */
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid(); /* self pid */
    nlh->nlmsg_flags = 0;
    /* Fill in the netlink message payload */
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg->msg_name = (void *)&dest_addr;
    msg->msg_namelen = sizeof(struct sockaddr_nl);
    msg->msg_iov = &iov;
    msg->msg_iovlen = 1;
    return fd;
}

int dot2_init_netlink(struct nlmsghdr *nlh, struct msghdr *msg){
    int ret = 0;
    struct wme_dot2_pid_request req;

    req.type = DOT2_PID;
    req.operat = SET_MIB;
    req.pid = get_pid();

    int fd = create_netlink(msg, nlh);
    if(fd < 0){
        wave_error_printf("fd创建失败");
        return -1;
    }
    memcpy(NLMSG_DATA(nlh), &req, sizeof(struct wme_generic_service_request));
    ret = sendmsg(fd, msg, 0);
    if(ret < 0){
        wave_error_printf("netlink发送消息失败");
        return -1;
    }
    return fd;
}


