#ifndef RB_H
#define RB_H
enum color{
    RED,
    BLACK
};

struct rb_head{
    struct rb_head *father;
    struct rb_head *left;
    struct rb_head *right;
    enum color color;
    int (*compare)(struct rb_head*,struct rb_head*);
    int (*equal)(struct rb_head*,void* value);
};
#ifndef container_of
#define container_of(ptr,type,member) ({\
        const typeof(((type*)0)->member) *__mptr = ptr;\
        (type*)((char*)__mptr - offsetof(type,member) );})
#endif

#define rb_entry(ptr,type,member) \
        container_of(ptr,type,member)

static void  rb_init(struct rb_head *rb,
                int(*com)(struct rb_head*,struct rb_head*),
                int(*equal)(struct rb_head*,void* ));


struct rb_head* rb_find(struct rb_head *root,void *value);
struct rb_head* rb_insert(struct rb_head *tree,struct rb_head *x);

struct rb_head* tree_min(struct rb_head *tree,struct rb_head *node);


struct rb_head* rb_delete(struct rb_head *tree,struct rb_head *x);

#endif
