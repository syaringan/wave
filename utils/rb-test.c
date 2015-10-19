#include"rb.h"
#include<stdio.h>
#include<stdlib.h>
#include<stddef.h>
/***
 * 这里我实验出来不能写成struct rb_head* head;
 * 那我们必须面临初始化这个头的过程，应该有办法初始一个
 */
struct goal{
    struct rb_head head;
    int value;
};
int compare(struct rb_head* a,struct rb_head* b){
    struct goal *goal_a,*goal_b;
    goal_a = rb_entry(a,struct goal,head);
    goal_b = rb_entry(b,struct goal,head);
    //printf("%d %d\n",goal_a->value,goal_b->value);
    if(goal_a->value  < goal_b->value)
        return -1;
    if(goal_a->value == goal_b->value)
        return 0;
    return 1;
}
int equal(struct rb_head* a,void* value){
    int mvalue = *((int*)value);
    struct goal *goal_a = rb_entry(a,struct goal,head);
    if(goal_a->value < mvalue)
        return -1;
    if(goal_a->value > mvalue)
        return 1;
    return 0;
}

static int inline init_rb_head(struct goal* goal){
    rb_init(&goal->head,compare,equal); 
    return 0;
}
static inline struct goal* goal_insert(struct goal* root,struct goal* node){
    struct rb_head* rb;
    if(root != NULL)
        rb = rb_insert(&root->head,&node->head);
    else 
        rb = rb_insert(NULL,&node->head);
    return rb_entry( rb,struct goal,head);
}
static inline struct goal*  goal_find(struct goal* root,void* value){
    struct rb_head* rb;
    rb = rb_find(&root->head,value);
    if(rb == NULL)
        return NULL;
    return rb_entry( rb,struct goal,head);
}
static inline struct goal* goal_delete(struct goal* root,struct goal* node){
    struct rb_head* rb;
    rb = rb_delete(&root->head,&node->head);
    return rb_entry( rb,struct goal,head);
}
void main(){
    struct goal *root,*node;
    root = NULL;
    int i=100;
    for(i=0;i<20;i++){
        if( (node = (struct goal*)malloc(sizeof(struct goal))) == NULL){
            return ;
        }
        if( init_rb_head(node)){
            //printf("errror\n");
            return ;
        }
        node->value = i;
        root = goal_insert(root,node);
    }
    printf("%d \n",goal_find(root,&root->value)->value);
    for(i=0;i<20;i++){
        printf("%d  ",
                goal_find(root,&i) == NULL ?-5:goal_find(root,&i)->value);
    }
    printf("\n");
    for(i=0;i<10;i++){
        node = goal_find(root,&i);
        if(node == NULL){
            printf("delete %d",i);
            continue;
        }
        root = goal_delete(root,node);
    }
    for(i=0;i<20;i++){
        printf("%d  ",
                goal_find(root,&i) == NULL ?-5:goal_find(root,&i)->value);
    }
    printf("\n");
}
