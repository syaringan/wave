#include "wave.h"
#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>
#include"utils/netlink.h"
#include "sec/sec.h"
#include "cmp/cmp.h"
#include "cme/cme.h"
#include "pssme/pssme.h"
#include <signal.h>
#define SERVICE "/var/tmp/wave_sec.socket"
#define CME_DB_CONFIG "./cme_db.config"
#define PSSME_DB_CONFIG "./pssme_db.config"
#define INIT(m) memset(&m, 0, sizeof(m));
#define error() printf("error %s %d\n", __FILE__, __LINE__);

static struct sec_db sec_db;

u32 psidn_2_h(unsigned char *psid, unsigned int len){
    int i = 0;
    u32 num = 0;
    for(i = 0; i < len; i++){
        num = num*256+(*psid);
        psid++;
    }
    return num;
}

static void get_cert_and_key(string *cert, string *pri){
	FILE *fd;
	fd = fopen("./cert/issued_cert/wsa1.cert", "r");
	if(fd == NULL){
		perror("fd");
		error();
		return;
	}
	cert->len = 400;
	cert->buf = (char*)malloc(cert->len);
	if(cert->buf == NULL){
		error();
		return;
	}
	cert->len = fread(cert->buf, 1, cert->len, fd);
	if(cert->len <= 0){
		error();
		return;
	}
	fclose(fd);

	fd = fopen("./cert/issued_cert/wsa1.veri.pri", "r");
	if(fd == NULL){
		error();
		return;
	}
	pri->len = 100;
	pri->buf = (char *)malloc(pri->len);
	if(pri->buf == NULL){
		error();
		return;
	}
	pri->len = fread(pri->buf, 1, pri->len, fd);
	if(pri->len <= 0){
		error();
		return;
	}
	fclose(fd);
}
static result generate_and_store_sign_wsa_cert(){
	result ret = FAILURE;
	cmh cmh;
	pssme_lsis lsis1;
	pssme_lsis lsis2;
	struct pssme_lsis_array lsis_array;
	certificate cert;
	string cert_encoded;
	string pri;

	INIT(cmh);
	INIT(lsis1);
	INIT(lsis2);
	INIT(lsis_array);
	INIT(cert);
	INIT(cert_encoded);
	INIT(pri);

	lsis_array.len = 2;
	lsis_array.lsis = (pssme_lsis*)malloc(sizeof(pssme_lsis)*2);
	if(!lsis_array.lsis){
		wave_malloc_error();
		goto fail;
	}

	ret = cme_cmh_request(&sec_db, &cmh);
	if(ret != SUCCESS){
		wave_error_printf("get cmh failed!\n");
		goto fail;
	}
	get_cert_and_key(&cert_encoded, &pri);
	string_2_certificate(&cert_encoded, &cert);
	ret = cme_store_cert_key(&sec_db, cmh, &cert, &pri);
	if(ret != SUCCESS){
		wave_error_printf("store cert fail!\n");
		error();
		goto fail;
	}

	ret = pssme_lsis_request(&sec_db, &lsis1);
	if(ret != SUCCESS){
		wave_error_printf("lsis request fail!\n");
		goto fail;
	}
	ret = pssme_lsis_request(&sec_db, &lsis2);
	if(ret != SUCCESS){
		wave_error_printf("lsis request fail!\n");
		goto fail;
	}
	lsis_array.lsis[0] = lsis1;
	printf("lsis1:%d\n", lsis1);
	lsis_array.lsis[1] = lsis2;
	printf("lsis2:%d\n", lsis2);

	string ssp;
	ssp.len = 4;
	ssp.buf = malloc(4);
	ssp.buf[0] = 'l';
	ssp.buf[1] = 'j';
	ssp.buf[2] = 'h';
	ssp.buf[3] = '\0';

	ret = pssme_secure_provider_serviceinfo(&sec_db, lsis1, ADD, 0x20, 0x1f, &ssp);
	if(ret != SUCCESS){
		wave_error_printf("register sps fail!\n");
		goto fail;
	}
	ret = pssme_secure_provider_serviceinfo(&sec_db, lsis2, ADD, 0x23, 0x1f, &ssp);
	if(ret != SUCCESS){
		wave_error_printf("register sps fail!\n");
		goto fail;
	}
	ret = pssme_cryptomaterial_handle_storage(&sec_db, cmh, &lsis_array);
	if(ret != SUCCESS){
		wave_error_printf("store cmh and lsis array fail\n");
		goto fail;
	}
fail:
	certificate_free(&cert);
	string_free(&cert_encoded);
	string_free(&pri);
	string_free(&ssp);
	pssme_lsis_array_free(&lsis_array);
	return ret;
}
static void* wme_loop(void* sdb){
    //启动netlink，
    int i = 0;
    int recv_data_len = 0;//接收到的整个数据报文的长度
    //char sbuf[MAX_PAYLOAD*4];//发送报文缓冲区
    //char rbuf[MAX_PAYLOAD*4];//接收报文缓冲区
    struct nlmsghdr *nlh = NULL;
    struct msghdr *msg = NULL;
	msg = (struct msghdr *)malloc(sizeof(*msg));
	nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD*4));
	if(!msg || !nlh){
		wave_malloc_error();
		return ;
	}
	memset(msg, 0, sizeof(*msg));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD*4));

    result ret;
    /*
     * 签名请求需要用到的参数
     * */
    struct wme_tobe_signed_wsa s_head;//接收到的需要签名报文头部
    struct dot3_signed_wsa s_wsa;
    int permission_len = 0;//permission部分报文的长度
    struct permission per;
    string unsigned_wsa;//接收到的wsa数据部分
    serviceinfo_array permissions;//需要填充的permission数组
    time32 life_time;

    string signed_wsa;
    /*
     * 验证请求需要用到的参数
     * */
    struct dot2_tobe_verified_wsa v_head;//接收到的需要验证的报文头部
    struct verified_wsa v_wsa;//验证成功需要发送给内核的报文头部
    string unverified_wsa;

    result_array results;
    string wsa_data;
    ssp_array ssp_array;
    time64_with_standard_deviation generation_time;
    time64 expiry_time;
    three_d_location location;
    struct time32_array last_crl_time;
    struct time32_array next_crl_time;
	certificate cert;

	int fd = dot2_init_netlink(nlh, msg);
	if(fd < 0){
		wave_error_printf("netlink初始化失败");
		return;
	}
	//generate cert for signing wsa ..test
	ret = generate_and_store_sign_wsa_cert();
	if(ret != SUCCESS){
		wave_error_printf("generate and store cert fail!\n");
		return;
	}
	wave_printf(MSG_INFO, "dot2 netlink init successful");
	while(1){
		ret = recvmsg(fd, msg, 0);
		if(ret < 0){
			wave_error_printf("接收netlink消息失败");
			goto out_fail;
		}
		recv_data_len = NLMSG_PAYLOAD(nlh, 0);
		//memcpy(rbuf, NLMSG_DATA(nlh), recv_data_len);
		nlh->nlmsg_pid = getpid();
		nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD*4);

		//解析报文
		char *shift = NLMSG_DATA(nlh);
		//1为签名
		if(*shift = 1){
			INIT(permissions);
			INIT(unsigned_wsa);
			INIT(signed_wsa);
			INIT(s_head);
			INIT(s_wsa);

			memcpy(&s_head, shift, sizeof(struct wme_tobe_signed_wsa));
			life_time = s_head.lifetime;
			shift += sizeof(struct wme_tobe_signed_wsa);

			unsigned_wsa.len = s_head.wsa_len;
			unsigned_wsa.buf = malloc(unsigned_wsa.len);
			if(!unsigned_wsa.buf){
				wave_malloc_error();
				goto out_fail;
			}
			memcpy(unsigned_wsa.buf, shift, unsigned_wsa.len);
			shift += unsigned_wsa.len;
			permission_len = recv_data_len - sizeof(struct wme_tobe_signed_wsa) - unsigned_wsa.len;
			permissions.len = 0;
			permissions.serviceinfos = malloc(sizeof(serviceinfo)*32);//分配32个为最大的长度
			while(permission_len > 0){
				memcpy(&per, shift, sizeof(struct permission));
				shift += sizeof(struct permission);

				memcpy(&permissions.serviceinfos[permissions.len].max_priority, &per.priority, 1);

				permissions.serviceinfos[permissions.len].psid = psidn_2_h(shift, per.psid_len);
				shift += per.psid_len;
				if(per.ssp_len > 0){
					DEBUG_MARK;
					printf("ssp len:%d\n", per.ssp_len);
					permissions.serviceinfos[permissions.len].ssp.len = per.ssp_len;
					permissions.serviceinfos[permissions.len].ssp.buf = malloc(per.ssp_len);
					if(!permissions.serviceinfos[permissions.len].ssp.buf){
						wave_malloc_error();
						goto out_fail;
					}
					memcpy(permissions.serviceinfos[permissions.len].ssp.buf, shift, per.ssp_len);
				}
				else{
					permissions.serviceinfos[permissions.len].ssp.len = 0;
					permissions.serviceinfos[permissions.len].ssp.buf = NULL;
				}
				shift += per.ssp_len;

				permissions.serviceinfos[permissions.len].lsis = 0;
				for(i = per.pssi_len-1; i >= 0; i--){
					permissions.serviceinfos[permissions.len].lsis = permissions.serviceinfos[permissions.len].lsis*256+
						(*((unsigned char*)shift+i));
				}
				shift+=per.pssi_len;
				permissions.len++;
				permission_len = permission_len - per.psid_len - per.ssp_len - per.pssi_len - sizeof(struct permission);
			}
			if(permission_len != 0){
				wave_error_printf("jiexi cuo wu!\n");
				return;
			}
			ret = sec_signed_wsa(&sec_db, &unsigned_wsa, &permissions, life_time, &signed_wsa);
			// memset((char*)NLMSG_DATA(nlh), 0, MAX_PAYLOAD);
			if(ret == SUCCESS){
				struct wme_signed_wsa_request *swsa = (struct wme_signed_wsa_request*)NLMSG_DATA(nlh);
				wave_printf(MSG_INFO, "signe wsa successful\n");
				swsa->type = DOT2_WSA;
				swsa->operat = SET_MIB;
				swsa->swsa.wsa_len = signed_wsa.len;
				swsa->swsa.broadcast = s_head.broadcast;
				swsa->swsa.change_count = s_head.change_count;
				swsa->swsa.channel = s_head.channel;
				swsa->swsa.result_code = DOT2_SIGN_SUCCESS;
				memcpy((char*)swsa+sizeof(*swsa), signed_wsa.buf, signed_wsa.len);
			}
			else{
				struct wme_signed_wsa_request *swsa = (struct wme_signed_wsa_request*)NLMSG_DATA(nlh);
				wave_error_printf("签名失败");
				swsa->type = DOT2_WSA;
				swsa->operat = SET_MIB;
				swsa->swsa.wsa_len = 0;
				swsa->swsa.broadcast = s_head.broadcast;
				swsa->swsa.change_count = s_head.change_count;
				swsa->swsa.channel = s_head.channel;
				swsa->swsa.result_code = DOT2_SIGN_FAILURE;
			}
			if(sendmsg(fd, msg, 0) < 0){
				wave_error_printf("发送消息给内核失败了");
				goto out_fail;
			}
		}
		//验证
		else if(*shift == 2){
			memcpy(&v_head, shift, sizeof(struct dot2_tobe_verified_wsa));
			shift += sizeof(struct dot2_tobe_verified_wsa);

			INIT(unverified_wsa);
			INIT(results);
			INIT(wsa_data);
			INIT(ssp_array);
			INIT(generation_time);
			INIT(expiry_time);
			INIT(location);
			INIT(last_crl_time);
			INIT(next_crl_time);
			INIT(cert);

			unverified_wsa.len = v_head.wsa_len;
			unverified_wsa.buf = malloc(v_head.wsa_len);
			if(!unverified_wsa.buf){
				wave_malloc_error();
				goto out_fail;
			}
			memcpy(unverified_wsa.buf, shift, v_head.wsa_len);

			//memset((char*)NLMSG_DATA(nlh), 0, MAX_PAYLOAD);
			ret = sec_signed_wsa_verification(&sec_db, &unverified_wsa, &results, &wsa_data, &ssp_array, &generation_time,
					&expiry_time, &location, &last_crl_time, &next_crl_time, &cert);
			if(ret == SUCCESS){
				struct wme_verified_wsa_request *vwsa = (struct wme_verified_wsa_request*)NLMSG_DATA(nlh);
				wave_printf(MSG_INFO,"verify success!\n");
				vwsa->type = DOT2_WSA;
				vwsa->operat = GET_ATTR;
				vwsa->rwsa.pid = getpid();
				memcpy(vwsa->rwsa.src_mac, v_head.src_mac, 6);
				vwsa->rwsa.rcpi = v_head.rcpi;
				vwsa->rwsa.result_code[0] = DOT2_SUCCESS;
				vwsa->rwsa.result_code[1] = DOT2_SUCCESS;
				for(i = 0; i < results.len; i++){
					if(results.result[i] == UNSECURED){
						vwsa->rwsa.result_code[1] = DOT2_UNSECURED;
						break;
					}
				}
				vwsa->rwsa.wsa_len = wsa_data.len; 
				vwsa->rwsa.gen_time = generation_time.time;
				vwsa->rwsa.expire_time = expiry_time;
				vwsa->rwsa.ssp_len = 0;
				vwsa->rwsa.next_crl_time_len = next_crl_time.len*sizeof(time32);

				//memcpy(sbuf, &v_wsa, sizeof(struct verified_wsa));
				memcpy((char*)vwsa+sizeof(*vwsa), wsa_data.buf, wsa_data.len);

				char *ssp_shift = (char*)vwsa + sizeof(*vwsa) + wsa_data.len;
				for(i = 0; i < ssp_array.len; i++){
					if(ssp_array.ssps[i].len != 0){
						memcpy(ssp_shift, ssp_array.ssps[i].buf, ssp_array.ssps[i].len);
						ssp_shift += ssp_array.ssps[i].len;
						vwsa->rwsa.ssp_len += ssp_array.ssps[i].len;
					}
					else{
						*ssp_shift = '\0';
						ssp_shift++;
						vwsa->rwsa.ssp_len++;
					}
				}

				memcpy(ssp_shift, next_crl_time.times, sizeof(time32)*next_crl_time.len);
				//memcpy(NLMSG_DATA(nlh), sbuf, sizeof(struct verified_wsa)+v_wsa.wsa_len+v_wsa.ssp_len+v_wsa.next_crl_time_len);
			}
			else if(ret == INVALID_INPUT){
				struct wme_verified_wsa_request *vwsa = (struct wme_verified_wsa_request*)NLMSG_DATA(nlh);
				wave_printf(MSG_INFO,"verify fail, invalid input!\n");
				vwsa->type = DOT2_WSA;
				vwsa->operat = GET_ATTR;
				vwsa->rwsa.pid = getpid();
				memcpy(vwsa->rwsa.src_mac, v_head.src_mac, 6);
				vwsa->rwsa.rcpi = v_head.rcpi;
				vwsa->rwsa.result_code[0] = DOT2_INVALID_INPUT;
				vwsa->rwsa.result_code[1] = DOT2_INVALID_INPUT;
				vwsa->rwsa.wsa_len = 0; 
				vwsa->rwsa.gen_time = 0;
				vwsa->rwsa.expire_time = 0;
				vwsa->rwsa.ssp_len = 0;
				vwsa->rwsa.next_crl_time_len = 0;

				//memcpy(sbuf, &v_wsa, sizeof(struct verified_wsa));
				//memcpy(NLMSG_DATA(nlh), sbuf, sizeof(struct verified_wsa));
			}
			else{
				struct wme_verified_wsa_request *vwsa = (struct wme_verified_wsa_request*)NLMSG_DATA(nlh);
				wave_printf(MSG_INFO,"verify fail, other failure\n");
				vwsa->type = DOT2_WSA;
				vwsa->operat = GET_ATTR;

				vwsa->rwsa.pid = getpid();
				memcpy(vwsa->rwsa.src_mac, v_head.src_mac, 6);
				vwsa->rwsa.rcpi = v_head.rcpi;
				vwsa->rwsa.result_code[0] = DOT2_OTHER_FALURE;
				vwsa->rwsa.result_code[1] = DOT2_OTHER_FALURE;
				for(i = 0; i < results.len; i++){
					if(results.result[i] == UNSECURED){
						vwsa->rwsa.result_code[1] = DOT2_UNSECURED;
						break;
					}
				}
				vwsa->rwsa.wsa_len = wsa_data.len; 
				vwsa->rwsa.gen_time = generation_time.time;
				vwsa->rwsa.expire_time = expiry_time;
				vwsa->rwsa.ssp_len = 0;
				vwsa->rwsa.next_crl_time_len = next_crl_time.len*sizeof(time32);

				memcpy((char*)vwsa+sizeof(*vwsa), wsa_data.buf, wsa_data.len);
			}
			if(sendmsg(fd, msg, 0) < 0){
				wave_error_printf("发送消息给内核失败了");
				goto out_fail;
			}
		}
		else{
			wave_error_printf("不支持的dot3请求类型");
			goto out_fail;
		}

out_fail:
		string_free(&unsigned_wsa);
		string_free(&signed_wsa);
		serviceinfo_array_free(&permissions);
		string_free(&unverified_wsa);
		string_free(&wsa_data);
		ssp_array_free(&ssp_array);
		result_array_free(&results);
		time32_array_free(&last_crl_time);
		time32_array_free(&next_crl_time);
		certificate_free(&cert);
	}
}
static void* app_do_request(void *ptr){
	int fd = *((int*)ptr);
	struct sec_db* sdb = &sec_db;

	do_client_request(sdb,fd);

	return NULL;
};
static int app_start(struct sec_db* sdb){
	int fd,serve_fd;
	pthread_t tid;
	pthread_attr_t attr;
	if( (serve_fd = serv_listen(SERVICE)) < 0){
		return -1;
	}
	while(1){
		if( (fd = serv_accept(serve_fd,NULL)) < 0){
			return -1;
		}
		if(pthread_attr_init(&attr))
			return -1;
		if(pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED))
			return -1;
		if( pthread_create(&tid,&attr,app_do_request,(void*)&fd))
			return -1;
		pthread_attr_destroy(&attr);
	};
}
static int inline init_phtread_attr_t(pthread_attr_t* attr){
	if(pthread_attr_init(attr))
		return -1;
	if(pthread_attr_setdetachstate(attr,PTHREAD_CREATE_DETACHED))
		return -1;
	if( pthread_attr_setschedpolicy(attr,SCHED_FIFO))
		return -1;
	struct sched_param param;
	param.sched_priority = 60;
	if( pthread_attr_setschedparam(attr,&param))
		return -1;
	return 0;
}
static int inline init_wme_pthread_attr_t(pthread_attr_t* attr){
	if(pthread_attr_init(attr))
		return -1;
	if(pthread_attr_setdetachstate(attr,PTHREAD_CREATE_DETACHED))
		return -1;
	if( pthread_attr_setschedpolicy(attr,SCHED_RR))
		return -1;
	struct sched_param param;
	param.sched_priority = 60;
	if( pthread_attr_setschedparam(attr,&param))
		return -1;
	return 0;
}
struct sec_db* init_sec_db(){
	if( pssme_db_init(&sec_db.pssme_db)){
		wave_error_printf("pssme_db init 失败  %s %d",__FILE__,__LINE__);
		return NULL;
	}
	if( file_2_pdb(&sec_db.pssme_db,PSSME_DB_CONFIG)){
		wave_printf(MSG_WARNING,"没有配置文件,或者配置文件格式不对，这里我们生成一个空的pssme_db");
		pssme_db_free(&sec_db.pssme_db);
		if( pssme_db_empty_init(&sec_db.pssme_db)){
			wave_error_printf("pssme_db_empty init 失败  %s %d",__FILE__,__LINE__);
			return NULL;
		}
	}
	wave_printf(MSG_INFO,"初始化完成 pssme_db");
	if( cme_db_init(&sec_db.cme_db) ){
		wave_error_printf("cme_db_init 失败  %s %d",__FILE__,__LINE__);
		return NULL;
	}
	wave_printf(MSG_DEBUG,"完成cme_db init");
	if( file_2_cme_db(&sec_db.cme_db,CME_DB_CONFIG)){
		wave_printf(MSG_WARNING,"没有配置文件，或者配置文件格式部队  这里我们生成一个空的cme_db");
		cme_db_free(&sec_db.cme_db);
		if( cme_db_empty_init(&sec_db.cme_db)){
			wave_error_printf("cme_db_empty init 失败  %s %d",__FILE__,__LINE__);
			return NULL;
		}
	}
	wave_printf(MSG_INFO,"初始化完成 cme_db");
	return &sec_db;
}

int wme_serv_start(struct sec_db* sdb){
	pthread_t wmes;
	pthread_attr_t attr;
	if(init_wme_pthread_attr_t(&attr))
		return -1;
	if(pthread_create(&wmes,&attr,wme_loop,(void*)sdb))
		return -1;
	pthread_attr_destroy(&attr);
	return 0;
}
void* cmp_loop(void *ptr){
	struct sec_db* sdb = (struct sec_db*)ptr;
	cmp_run(sdb);
	return 0;
}
int wave_cmp_start(struct sec_db* sdb){
	pthread_t cmp_pt;
	if(pthread_create(&cmp_pt,NULL,cmp_loop,(void*)sdb))
		return -1;
	return 0;
}
void wave_exit_fun(){
	wave_printf(MSG_INFO,"正在写入文件");
	pdb_2_file(&sec_db.pssme_db,PSSME_DB_CONFIG);
	wave_printf(MSG_INFO,"pssme_db 完成");
	cme_db_2_file(&sec_db.cme_db,CME_DB_CONFIG);
	wave_printf(MSG_INFO,"cme_db 完成");
	cmp_end();
	wave_printf(MSG_INFO,"cmp_db 完成");
}
static void kill_handle(int signo){
	exit(0);
}
int wave_start(){
	struct sec_db* sdb;
	int res;
	sdb = init_sec_db();
	if(sdb == NULL){
		wave_error_printf("初始化sec_db失败 ");
		return -1;
	}
	wave_printf(MSG_INFO,"初始化sec_db 完成 **************");

	if(atexit(wave_exit_fun)){
		wave_error_printf("注册退出程序失败");
		return -1;
	}
	if(signal(SIGTERM,kill_handle) == SIG_ERR){
		wave_error_printf("kill信号处理注册失败");
		return -1;
	}
	wave_printf(MSG_INFO,"kill处理函数 和 退出函数 完成");

	if(wme_serv_start(sdb)){
		wave_error_printf("wme_serv_start 失败");
		return -1;
	}
	wave_error_printf("wme_serv_start 成功");

	if(wave_cmp_start(sdb)){
		wave_error_printf("wave_cmp 启动失败");
		return -1;
	}
	wave_error_printf("wave_cmp 启动成功");

	wave_error_printf("wave_app 启动");
	if( app_start(sdb)){
		wave_error_printf("wave_app 启动失败");
		return -1;
	}
	return 0;
}

