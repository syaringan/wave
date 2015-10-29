#include"data_handle.h"

void elliptic_curve_dst_cpy(elliptic_curve_point* dst,elliptic_curve_point* src){ 
    dst->type = src->type;
    dst->x.len = src->x.len;
    dst->x.buf = (u8*)malloc(dst->x.len); 
    if(dst->x.buf == NULL){
        wave_error_printf("内存分配失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    memcpy(dst->x.buf,src->x.buf,src->x.len);
    if(src->type == UNCOMPRESSED){
        dst->u.y.len = src->u.y.len;
        dst->u.y.buf = (u8*)malloc(point->u.y.len); 
        if(dst->u.y.buf == NULL){
             wave_error_printf("内存分配失败 %s %d",__FILE__,__LINE__);
                return -1;
        }
        memcpy(dst->u.y.buf,src->u.y.buf,src->u.y.len);
    }   
}
