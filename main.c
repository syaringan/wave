#include"entry/wave.h"
#include"sec/sec.h"
#include<stddef.h>
#include"utils/debug.h"
struct region_type_array certificate_request_support_region_types;

int main(){
    struct sec_db *sdb;
    certificate_request_support_region_types.len = 3;
    certificate_request_support_region_types.types = (enum region_type*)malloc(sizeof(region_type) * 
            certificate_request_support_region_types.len);
    *certificate_request_support_region_types.types = RECTANGLE;
    *(certificate_request_support_region_types.types+1) = POLYGON;
    *(certificate_request_support_region_types.types + 2) = CIRCLE;
    wave_printf(MSG_INFO,"启动");

    wave_start();
    return 0;
}
