#include<wave/wave_sec.h>
#include<stdio.h>
int main(){
    cmh cmh;
    if(cme_cmh_request(&cmh)){
        return -1;
    }
    printf("cmh : %d\n",cmh);
}
