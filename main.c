#include"entry/wave.h"
#include"sec/sec.h"
#include<stddef.h>

struct region_type_array certificate_request_support_region_types;

void main(){
    certificate_request_support_region_types.len = 3;
    *certificate_request_support_region_types.types = RECTANGLE;
    *(certificate_request_support_region_types.types+1) = POLYGON;
    *(certificate_request_support_region_types.types + 2) = CIRCLE;
    wme_serv_start();
}
