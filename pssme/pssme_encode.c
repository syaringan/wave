/*************************************************************************
    > File Name: pssme_encode.c
    > Author: 付鹏飞
 ************************************************************************/

#include <fcntl.h>
#include <unistd.h>
#include <string.h>            //为了使用memset
#include <stdlib.h>
#include "pssme_db.h"

#define MAX_BUFFER 4096
u32 position = 0;             //记录文件偏移量的全局变量，其实只用在对文件的读操作。因为写文件的策略是每次都写入文件的尾部。

//正确0 错误-1
int pdb_2_file(struct pssme_db* pdb,char* name)
{
	int fd = open(name, O_RDWR | O_APPEND | O_CREAT | O_TRUNC);    //O_TRUNC参数使每次写文件前都将文件清空
	if(fd == -1)
	{
		printf("Open File Error!\n");
		return -1;
	}


	struct pssme_cert_db *pcdb;
	pcdb = &(pdb->cert_db);
	struct pssme_lsis_db *pldb;
	pldb = &(pdb->lsis_db);

	if( cert_db_2_file(pcdb, fd) == -1 )
	{
		printf("in pdb_2_file : cert_db_2_file Error!\n");
	    return -1;
	}

    if( lsis_db_2_file(pldb, fd) == -1 )
	{
		printf("in pdb_2_file : lsis_db_2_file Error!\n");
        return -1;
	}

    if( close(fd) == -1 )
    {
        printf("Close File Error!\n");
        return -1;
    }

    return 0;
}


int cert_db_2_file(struct pssme_cert_db *pcdb, int fd)
{
    if(fd == -1)
    {
        printf("cert_db_2_file Error!\n");
        return -1;
    }

    struct pssme_local_cert *plc;
	plc = &(pcdb->local_cert);

	if( plc_2_file(plc, fd) == -1 )
	{
		printf("in cert_db_2_file : plc_2_file Error!\n");
	    return -1;
	}

    struct pssme_receive_cert *prc;
	prc = &(pcdb->receive_cert);

	if( prc_2_file(prc, fd) == -1 )
	{
		printf("in cert_db_2_file ; prc_2_file Error!\n");
	    return -1;
	}

    return 0;
}


int plc_2_file(struct pssme_local_cert *plc, int fd)
{
    if(fd == -1)
    {
        printf("plc_2_file Error!\n");
        return -1;
    }

    struct list_head *pos;
    u8 buf[MAX_BUFFER] = {0};

    u32 length = 0;               //length是32位的，是用来缓存各种链表的长度的。
	list_for_each(pos, &(plc->list))
		length++;

	u8 *p_u8 = (u8 *)(&length);      //将指向length的指针强制转换成u8型指针。
	u32 i = 0;
	for(i=0; i<4; i++)      //写文件第一步，将local_cert的长度先写入文件中。且其长度以 4 字节位单位。
		buf[i] = *(p_u8 ++);

    u32 j = 4;             //j用来记录缓存数组buf接着往下写的数组下标。
	struct pssme_local_cert *pos_plc;
	list_for_each(pos, &(plc->list))
	{
	          //从此行开始，开始在文件中写入pssme_local_cert local_cert结构体
			  //写cmh:
        pos_plc = list_entry(pos, struct pssme_local_cert, list);
	    p_u8 = (u8 *)( &(pos_plc->cmh) );
	    for(i=j; i<j+4; i++)
		    buf[i] = *(p_u8 ++);
		j = j + 4;

		     //写lsis_array:
	    length = (pos_plc->lsis_array).len ;
	    p_u8 = (u8 *)(&length);
	    for(i=j; i<j+4; i++)
		    buf[i] = *(p_u8 ++);     //将lsis_array的长度len写入文件.
		j = j + 4;
	    p_u8 = (u8 *)( (pos_plc->lsis_array)->lsis );
	    for(i=j; i<(j + 4*length ); i++)
		    buf[i] = *(p_u8 ++);
		j = j + 4*length ;
	}

	if( write(fd, buf, j) == -1 )        
	{
	    printf("plc_2_file Write Error!\n");
	    return -1;
	}

	return 0;
}


int prc_2_file(struct pssme_receive_cert *prc, int fd)
{
    if(fd == -1)
    {
        printf("prc_2_file Error!\n");
        return -1;
    }

    struct list_head *pos;
    u8 buf[MAX_BUFFER] = {0};

    u32 length = 0;               //length是32位的，是用来缓存各种链表的长度的。
	list_for_each(pos, &(plc->list))
		length++;

	u8 *p_u8 = (u8 *)(&length);      //将指向length的指针强制转换成u8型指针。
	u32 i = 0;
	for(i=0; i<4; i++)      //将receive_cert的长度先写入文件中。且其长度以 4 字节位单位。
		buf[i] = *(p_u8 ++);

	u32 j = 4;             //j用来记录缓存数组buf接着往下写的数组下标。

    struct pssme_receive_cert *pos_prc;
	certificate *cert;
	string data;

	list_for_each(pos, &(prc->list))
	{
        memset(&data, 0, sizeof(data) );

		pos_prc = list_entry(pos, struct pssme_receive_cert, list);
	    cert = &(pos_prc->certificate);

	    certificate_2_string(cert, &data);    
		
		        //把证书转换成string后，先将长度string.len写入文件，以便读操作时使用
		p_u8 = (u8 *)(&(data.len));
		buf[j] = *(p_u8);
		p_u8++;
		buf[j+1] = *(p_u8);
		j = j + 2;

		for(i=j; i<(j+(data.len)); i++)
			buf[i] = *( (data.buf)++ );

		j = j + (data.len);

		p_u8 = (u8 *)(&(pos_prc->recent_time));

		for(i=j; i<(j+8); i++)
			buf[i] = *(p_u8 ++);
		j = j + 8;
	}

	if( write(fd, buf, j) == -1 )
	{
	    printf("plc_2_file Write Error!\n");
	    return -1;
	}

	return 0;
}


int lsis_db_2_file(struct pssme_lsis_db *pldb, int fd)
{
	if( fd == -1 )
	{
		printf("lsis_db_2_file Error!\n");
		return -1;
	}

	struct pssme_alloc_lsis *pal;
	pal = &(pldb->alloc_lsis);
	struct pssme_lsis_chain *plchain;    //这个不缩写成plc是为了区别之前的 pssme_local_cert 缩写的 plc，以免看起来混淆
	plchain = &(pldb->lsises);

	if( pal_2_file(pal, fd) == -1 )
	{
		printf("in lsis_db_2_file : pal_2_file Error!\n");
		return -1;
	}

	if( plchain_2_file(plchain, fd) == -1 )
	{
		printf("in lsis_db_2_file ; plchain_2_file Error!\n");
		return -1;
	}

	return 0;
}


int pal_2_file(struct pssme_alloc_lsis *pal, int fd)
{
	if( fd == -1 )
	{
		printtf("pal_2_file Error!\n");
		return -1;
	}

	struct list_head *pos;
	struct list_head *pos1;
	u8 buf[MAX_BUFFER] = {0};

	u32 length = 0;
	list_for_each(pos, &(pal->list))
		length++;

	u8 *p_u8 = (u8 *)(&length);
	u32 i = 0;
	for(i=0; i<4; i++)
		buf[i] = *(p_u8 ++);

	u32 j = 4;
	struct pssme_alloc_lsis *pos_pal;
	struct pssme_psid_priority_ssp_chain *pppsc;
	struct pssme_psid_priority_ssp_chain *pos_pppsc;
	struct pssme_psid_priority_ssp *pms;     //pms缩写自permission,若缩写为ppps的话与之前的pppsc容易混淆
	string pos_psid;
	string pos_ssp;

	list_for_each(pos, &(pal->list))
	{

		pos_pal = list_entry(pos, struct pssme_alloc_lsis, list);

		p_u8 = (u8 *)(&(pos_pal->lsis));     //将u32的lsis写入文件
		for(i=j; i<(j+4); i++)
			buf[i] = *(p_u8 ++);
		j = j + 4;

		pppsc = &(pos_pal->permissions);

		length = 0;                        //将permissions的长度写入文件，先将length清零
		list_for_each(pos1, &(pppsc->list))
			length++;
		p_u8 = (u8 *)(&length);
		for(i=j; i<(j+4); i++)
			buf[i] = *(p_u8 ++);
		j = j + 4;

		list_for_each(pos1, &(pppsc->list))            //将permission chain写入文件
		{
			memset(&pos_psid, 0, sizeof(pos_psid));
			memset(&pos_ssp, 0, sizeof(pos_ssp));

			pos_pppsc = list_entry(pos1, struct pssme_psid_priority_ssp_chain, list);


			pms = &(pos_pppsc->permission);            //将permission写入文件

            pos_psid = pms->psid;
			pos_ssp = pms->ssp;

			p_u8 = (u8 *)(&(pos_psid.len));                     //将psid的长度写入文件
			buf[j] = *(p_u8++);
			buf[j+1] = *(p_u8);
			j = j + 2;

			for(i=j; i<(j+pos_psid.len); i++)                   //将字符串psid写入文件
				buf[i] = *( (pos_psid.buf) ++ );
			j = j + pos_psid.len;

			buf[j++] = pos_psid.priority;              //将priority写入文件

			p_u8 = (u8 *)(&(pos_ssp.len));                     //将ssp的长度写入文件
			buf[j] = *(p_u8++);
			buf[j+1] = *(p_u8);
			j = j + 2;

			for(i=j; i<(j+pos_ssp.len); i++)                  //将字符串ssp写入文件
				buf[i] = *( (pos_ssp.buf) ++ );
			j = j + pos_ssp.len;
		}
	}

	if( write(fd, buf, j) == -1 )
	{
		printf("pal_2_file Write Error!\n");
		return -1;
	}

	return 0;
}


int plchain_2_file(struct pssme_lsis_chain *plchain, int fd)
{
	if( fd == -1 )
	{
		printf("plchain_2_fd Error!\n");
		return -1;
	}

	struct list_head *pos;
	struct pssme_lsis_chain *pos_plchain;
	pssme_lsis p_lsis = 0;
	u8 buf[MAX_BUFFER] = {0};

    u32 length = 0;
	list_for_each(pos, &(plchain->list))
	    length++;

	u8 *p_u8 = (u8 *)(&length);
	u32 i = 0;
	for(i=0; i<4; i++)
	    buf[i] = *(p_u8  ++);
	u32 j = 4;

	list_for_each(pos, &(plchain->list))
    {
        pos_plchain = list_entry(pos, struct pssme_lsis_chain, list);

		p_lsis = pos_plchain->lsis;
		p_u8 = (u8 *)(&p_lsis);

		for(i=j; i<(j+4); i++)
			buf[i] = *(p_u8 ++);
		j = j + 4;
    }

	if( write(fd, buf, j) == -1 )
	{
		printf("plchain_2_file Write Error!\n");
		return -1;
	}

	return 0;
}


/*下面是读文件操作
 * 将文件内容读入struct pssme_db 结构体
 */
int file_2_pdb(struct pssme_db *pdb, char *name)
{
	int fd = open(name, O_RDONLY);            //以只读方式打开

	if(fd == -1)
	{
		printf("file_2_db Open File Error!\n");
		return -1;
	}


	memset(pdb, 0, sizeof(pdb));
	struct pssme_cert_db pcdb = pdb->cert_db;
	struct pssme_lsis_db pldb = pdb->lsis_db;

	if( file_2_cert_db(&pcdb, fd) == -1 )
	{
		printf("in file_2_pdb : file_2_pcdb Error!\n");
		return -1;
	}

	if( file_2_lsis_db(&pldb, fd) == -1 )
	{
		printf("in file_2_db : file_2_pldb Error!\n");
		return -1;
	}

	if( close(fd) == -1 )
	{
		printf("Close File Error!\n");
		return -1;
	}

	return 0;
}


int file_2_cert_db(struct pssme_cert_db *pcdb, int fd)
{
	if(fd == -1)
	{
		printf("file_2_pcdb Error!\n");
		return -1;
	}

	
	struct pssme_local_cert plc = pcdb->local_cert;
	struct pssme_receive_cert prc = pcdb->receive_cert;

	if( file_2_plc(&plc, fd) == -1 )
	{
		printf("in file_2_cert_db : file_2_plc Error!\n");
		return -1;
	}

	if( file_2_prc(&prc, fd) == -1 )
	{
		printf("in file_2_cert_db : file_2_prc Error!\n");
		return -1;
	}

	return 0;
}


int file_2_plc(struct pssme_local_cert *plc, int fd)
{
	if( fd == -1 )
	{
		printf("file_2_plc Error!\n");
		return -1;
	}

	u32 length = 0;    //plc链表长度
	struct pssme_local_cert *pos_plc;
	struct pssme_lsis_array *pos_lsis_array;
	pssme_lsis *pos_lsis;

	INIT_LIST_HEAD(&(plc->list));          //初始头节点

	u8 buf[MAX_BUFFER] = {0};

	u32 i = 0;      //用于plc链表的for循环
	u32 i_array = 0;   //用于pssme_lsis_array数组的for循环

	if( read(fd, buf, MAX_BUFFER) == -1 )
	{
		printf ("in file_2_plc : Read File Error!\n");
		return -1;
	}

	u8 *p_u8 = buf;
	u32 *p_u32 = (u32 *)(p_u8);
	length = *(p_u32++);         //p_u32++后指向的buf数组中的值是local_cert链表中第一个有数据的节点的cmh成员

	position = 4;             //读出了plc链表长度length后，文件的偏移量为4

	for(i=0; i<length; i++)
	{
		pos_plc = (struct pssme_local_cert *)malloc(sizeof(struct pssme_local_cert));

		pos_plc->cmh = *(p_u32++);   //p_u32++后指向的buf中的数据是该节点中lsis_array数组长度

		pos_lsis_array = &(pos_plc->lsis_array);
		pos_lsis_array->len = *(p_u32 ++);        //p_u32++后指向了数组lsis_array的第一个成员pssme_lsis *lsis

		position = position + 8;         //又读出了32位的cmh和32位的lsis_array.len

		pos_lsis = (pssme_lsis *)malloc( sizeof(pssme_lsis) * (pos_lsis_array->len) );
		for(i_array=0; i<(pos_lsisi_array->len); i_array++)
		{
			pos_lsis[i_array] = *(p_u32 ++);
			position = position + 4;
		}
		pos_lsis_array->lsis = pos_lsis;

		list_add_tail(&(pos_plc->list), &(plc->list));    //因为写文件时是从头的下一节点开始写至尾节点的
	}

	if( lseek(fd, position, SEEK_SET) == -1 )        //为下一次读文件设置偏移量
	{
		printf("in file_2_plc : lseek Error!\n");
		return -1;
	}

	rerurn 0;
}


int file_2_prc(struct pssme_receive_cert *prc, int fd)
{
	if(fd == -1)
	{
		printf("file_2_prc Error!\n");
		return -1;
	}

	u32 length = 0;
	struct pssme_receive_cert *pos_prc;
	certificate *cert;
	string data;

	INIT_LIST_HEAD(&(prc->list));

	u8 buf[MAX_BUFFER] = {0};
	u32 i = 0;

	if( read(fd, buf, MAX_BUFFER) == -1 )
	{
		printf("in file_2_prc ; Read File Error!\n");
		return -1;
	}

	u8 *p_u8 = buf;
	u32 *p_u32 = (u32 *)p_u8;
	length = *p_u32;

	u16 *p_u16 = (u16 *)p_u32;      //用来暂存string的长度string.len(16位的数),现在p_u16指向cert转换的string类型的长度string.len
	u64 *p_u64;                     //用来指向u64型的recent_time

	position = position + 4;

	for(i=0; i<length; i++)
	{
		memset(&data, 0, sizeof(data));

		pos_prc = (struct pssme_receive_cert *)malloc(sizeof(struct pssme_receive_cert));
		cert = &(pos_prc->cert);

		data.len = *(p_u16 ++);
		p_u8 = (u8 *)p_u16;
		data.buf = p_u8;

		cert = (certificate *)malloc(sizeof(certificate));

		string_2_cert(cert, &data);

		p_u8 = p_u8 + (data.len);     //处理完证书后将p_u8指针指向buf中证书后recent_time成员
		p_u64 = (u64 *)p_u8;

		pos_prc->recent_time = *p_u64;

		list_add_tail(&(pos_prc->list), &(prc->list));

		position = position + 2 + (data.len) + 8;
	}

	if( lseek(fd, position, SEEK_SET) == -1 )
	{
		printf("in file_2_prc : lseek Error!\n");
		return -1;
	}

	return 0;
}


int file_2_lsis_db(struct pssme_lsis_db *pldb, int fd)
{
	if( fd == -1 )
	{
		printf("file_2_lsis_db Error!\n");
		return -1;
	}

	struct pssme_alloc_lsis *pal = &(pldb->alloc_lsis);
	struct pssme_lsis_chain *plchain = &(pldb->lsises);

	if( file_2_pal(pal, fd) == -1 )
	{
		printf("in file_2_lsis_db : file_2_pal Error!\n");
		return -1;
	}

	if( file_2_plchain(plchain, fd) == -1 )
	{
		printf("in file_2_lsis_db : file_2_plchain Error!\n");
		return -1;
	}

	return 0;
}


int file_2_pal(struct pssme_alloc_lsis *pal, int fd)
{
	if(fd == -1)
	{
		printf("file_2_pal Error!\n");
		return -1;
	}

	u32 length_of_pal = 0;
	u32 length_of_permissions = 0;
	struct pssme_alloc_lsis *pos_pal;
	struct pssme_psid_priority_ssp_chain *pppsc;
	struct pssme_psid_priority_ssp_chain *pos_pppsc;
	struct pssme_psid_priority_ssp *pms;                //缩写自permission

	u8 buf[MAX_BUFFER] = {0};
	u32 i = 0;
	u32 j = 0;
	u32 k = 0;       //i，j，k都用于for循环

	INIT_LIST_HEAD(&(pal->list));

	if( read(fd, buf, MAX_BUFFER) == -1 )
	{
		printf("in file_2_pal : Read File Error!\n");
		return -1;
	}

	u8 *p_u8 = buf;
	u32 *p_u32 = (u32 *)p_u8;
	length = *(p_u32 ++);       //p_u32++ 后指向pssme_alloc_lsis链表第一个有数据的节点的pssme_lsis 型的lsis成员
	position = position + 4;

	u16 *p_u16;
	u8 *p_u8_in_string;     //保存string中的buf

	for(i=0; i<length_of_pal; i++)
	{
		pos_pal = (struct pssme_alloc_lsis *)malloc(sizeof(struct pssme_alloc_lsis));

		pos_pal->lsis = *(p_u32 ++);
		position = position + 4;
		pppsc = &(pos_pal->permissions);
		length_of_permissions = *(p_u32 ++);       /* p_u32++后指向的buf[MAX_BUFFER]中的单元存的是
		                                            * struct pssme_psid_priority_ssp permission
													* 的成员string psid 的长度 u16型的 psid.len
													* 所以下一行再将p_u32转为p_u16指针
													*/
		p_u16 = (u16 *)p_u32;
		position = position + 4;

		INIT_LIST_HEAD(&(pppsc->list));

		for(j=0; j<length_of_permissions; j++)
		{
			pos_pppsc = (struct pssme_psid_priority_ssp *)malloc(struct pssme_psid_priority_ssp);

			pms = &(pos_pppsc->permission);

			(pms->psid).len = *(p_u16 ++);
			p_u8 = (u8 *)p_u16;
			position = position + 2;

			((pms->psid).buf) = (u8 *)malloc( sizeof(u8) * ((pms->psid).len) );
			p_u8_in_string = ((pms->psid).buf);

			for(k=0; k<((pms->psid).len); k++)
			{
				p_u8_in_string[k] = *(p_u8 ++);
				position++;
			}

			pms->priority = *(p_u8 ++);
			position++;
			p_u16 = (u16 *)p_u8;           //指向permission.ssp.len(u16)

			(pms->ssp).len = *(p_u16 ++);
			p_u8 = (u8 *)p_u16;
			position = position + 2;

			((pms->ssp).buf) = (u8 *)malloc( sizeof(u8) * ((pms->ssp).len) );
			p_u8_in_string = ((pms->ssp).buf);

			for(k=0; k<((pms->ssp).len); k++)
			{
				p_u8_in_string[k] = *(p_u8 ++);
				position++;
			}

			list_add_tail(&(pos_pppsc->list), &(pppsc->list));
		}

		list_add_tail(&(pos_pal->list), &(pal->list));
	}

	if( lseek(fd, position, SEEK_SET) == -1 )
	{
		printf("in file_2_pal : lseek Error!\n");
		return -1;
	}

	return 0;
}


int file_2_plchain(struct pssme_lsis_chain *plchain, int fd)
{
	if( fd == -1 )
	{
		printf("file_2_plchain Error!\n");
		return -1;
	}

	u32 length = 0;
	struct pssme_lsis_chain *pos_plchain;

	u32 i = 0;
	u8 buf[MAX_BUFFER] = {0};

	INIT_LIST_HEAD(&(plchain->list));

	if( read(fd, buf, MAX_BUFFER) == -1 )
	{
		printf("in file_2_plchain : Read File Error!\n");
		return -1;
	}

	u8 *p_u8 = buf;
	u32 *p_u32 = (u32 *)p_u8;
	length = *(p_u32 ++);
	position = position + 4;       //其实这个函数中似乎不用再对偏移量position处理了，因为这是最后一个读函数，保险起见，先写着吧

	for(i=0; i<length; i++)
	{
		pos_plchain = (struct pssme_lsis_chain *)malloc(sizeof(struct pssme_lsis_chain));

		pos_plchain->lsis = *(p_u32 ++);
		position = position + 4;

		list_add_tail(&(pos_plchain->list), &(plchain->list));
	}

	if( lseek(fd, position, SEEK_SET) == -1 )
	{
		printf("in file_2_plchain : lseek Error!\n");
		return -1;
	}

	return 0;
}
