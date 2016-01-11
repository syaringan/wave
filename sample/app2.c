#include<wave/wave_sec.h>
#include<stdio.h>
#include"msocket.h"

#define MY_PORT 2010
#define OPP_PORT 2000
#define error() printf("error %s %d\n",__FILE__,__LINE__);
int main(){
    cmh cmh;
    int fd;
    fd = getsocket(MY_PORT);
    if(fd <0 ){
        error();
        return -1;
    }
    mrecvfrom(fd,(char*)&cmh,sizeof(cmh),OPP_PORT);
    printf("cmh : %d\n",cmh);
}
