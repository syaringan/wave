#include"rb.h"

struct goal{
    struct rb_head* head;
    int value;
};
void compare(struct rb_head* a,struct rb_head* b){
    struct goal *goal_a,*goal_b;
    goal_a = rb_entry(a,struct goal,head);
    goal_b = rb_entry(b,struct goal,head);
    if(goal_a.value  < goal_b.value)
        return -1;
    if(goal_a.value == goal_b.value)
        return 0;
    return 1;
}
void equal(struct rb_head* a,void* value){
    int mvalue = *((int*)value);
    struct goal_a = rb_entry(a,struct rb_head,head);
    if(goal_a.value < value)
        return -1;
    if(goal_a.value > value)
        return 1;
    return 0;
}

static int inline init_rb_head(struct* goal){
    goal->head = malloc(sizeof(struct rb_head));
    if(goal->head == NULL)
        return -1;
    rb_init(goal->head,compare,equal); 
    return 0;
}
static struct goal* inline goal_insert(struct goal* root,struct goal* node){
    if(root != NULL)
        return rb_entry(rb_insert(root->head,node->head) ,struct goal,head);
    return rb_entry( rb_insert(NULL,node->head),struct goal,head);
}

void main(){
    struct goal *root,*node;
    head = NULL;
    int i=100;
    for(int i=0;i<100;i++){
        if( node = malloc(sizeof(struct goal)) == NULL){
            return ;
        }
        inti_rb_head(goal);
        goal->value = i;
        root = goal_insert(root,node);
    }
}
