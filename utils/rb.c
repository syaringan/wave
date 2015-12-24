#include"rb.h"
#include<stddef.h>
#include<stdio.h>
struct rb_head mynil={
    .father = NULL,
    .left = NULL,
    .right = NULL,
    .color = BLACK,
    .compare = NULL,
    .equal = NULL,
};
 void  rb_init(struct rb_head *rb,
                int(*com)(struct rb_head*,struct rb_head*),
                int(*equal)(struct rb_head*,void* )){
    if(rb == NULL)
        return;
    rb->father = &mynil;
    rb->left = &mynil;
    rb->right = &mynil;
    rb->color = RED;
    rb->compare = com;
    rb->equal = equal;
}

static  struct rb_head* left_rotate(struct rb_head *root,struct rb_head *x)
{
	struct rb_head *y;
	y = x->right;
	x->right = y->left;
	if(y->left != &mynil)
		y->left->father = x;
	
	y->father = x->father;
	if(x->father == &mynil)
		root = y;
	else if(x->father->left == x)
		x->father->left = y;
	else 
		x->father->right = y;
	
	x->father = y;
	y->left	  = x;
	return root;
}

static  struct rb_head* right_rotate(struct rb_head *tree,struct rb_head *x)
{
	struct rb_head *y;
	y = x->left;

	x->left = y->right;
	if(y->right != &mynil)
		y->right->father = x;
	y->father = x->father ;
	if(x->father == &mynil)
		tree = y;
	else if (x->father->left == x)
		x->father->left = y;
	else 
		x->father->right = y;
	x->father = y ;
	y->left = x;
    return tree;
}

struct rb_head* rb_find(struct rb_head *root,void *value)
{
	struct rb_head *node;
	node = root;
	int compare ;
	while(node != &mynil ){
        compare = node->equal(node,value);
		if(compare > 0 )
			node = node ->left;
        else if(compare == 0)
            break;
		else 
			node = node->right;
	}
    if(&mynil == node)
            return NULL;
	return node;
}

struct rb_head* rb_insert_fixup(struct rb_head *tree,struct rb_head *x)
{
	struct rb_head *uncle;
	while(x->father->color == RED){
		if (x->father->father->left == x->father){
				uncle = x->father->father->right;
				if(uncle->color == RED){
						x->father->father->color = RED;
						uncle->color =	BLACK;	
						x->father->color =  BLACK;
						x = x->father->father;
				}
				else if(x->father->right == x){
					
					tree = left_rotate(tree,x->father);
					x = x->left;	
				}
				else {
					x->father->color = BLACK;
					x->father->father->color  = RED ;
					tree = right_rotate(tree,x->father->father);
				}

		}
		else {
			uncle = x->father->father->left;
			if(uncle->color == RED){
				uncle->color = BLACK;
				uncle->father->color = RED;
				x->father->color = BLACK;
				x = uncle->father;
			}

			else if(x->father->left == x){
				x=x->father;
				tree = right_rotate(tree,x);
			}
			else {
				x->father->color = BLACK;
				x->father->father->color = RED;
				tree = left_rotate(tree,x->father->father);
			}
		}
	}

	tree->color = BLACK;
    return tree;
}


struct rb_head* rb_insert(struct rb_head *tree,struct rb_head *x)
{   
    if(tree == NULL){
        x->color = BLACK;
        return x;
    }
	struct rb_head *node,*pre;
	node = tree;
	pre = &mynil;	
	while(node != &mynil){
		pre =  node;
        if(tree->compare(x,node) <0)
			node = node ->left;
		else 
			node = node ->right;
		}

	x->father = pre;
	if(pre == &mynil)
		tree = x;
    else if(tree->compare(x,pre) < 0)
		pre->left =  x;
	else 
		pre->right = x;
	return rb_insert_fixup(tree,x);
	
//	printf("x->father->value:%d\n",x->father->value);

}

struct rb_head* tree_min(struct rb_head *tree,struct rb_head *node)
{
	struct rb_head *pre;
	pre = &mynil;
	while(node != &mynil){
		pre = node;
		node = node ->left;
	}
	return pre;
}

struct rb_head* rb_delete_fixup(struct rb_head *tree , struct rb_head *fix )
{
	struct rb_head *brother;
	while (fix != tree && fix->color == BLACK ){
		if(fix->father->left == fix){
			brother = fix->father->right;

			if(brother->color == BLACK && brother->left->color == BLACK && brother->right->color == BLACK){
				brother->color = RED;
				fix = fix->father;
			}
			else if(brother->color == BLACK && brother->right->color == RED){
				brother->color = fix->father->color;
				fix->father->color = BLACK;
				brother->right->color = BLACK;
				tree = left_rotate(tree,fix->father);
				fix = tree;
			}
			else if(brother->color == BLACK ){
				brother->color = RED;
				brother->left->color = BLACK;
				tree = right_rotate(tree,brother);
				
			}
			else {
				brother->color = BLACK;
				brother->father->color = RED;
				tree = left_rotate(tree,fix->father);

			}
		}
		else{
			brother = fix->father->left;
			if(brother->color == BLACK && brother->left->color ==BLACK && brother->right->color == BLACK){
				brother->color = RED;
				fix = fix->father;
			}
			else if(brother->color ==BLACK && brother->left->color == RED){
				brother->color = fix->father->color;
				fix->father->color == BLACK;
				brother->left->color == BLACK;
				tree = right_rotate(tree,brother->father);
				fix = tree;
			}
			else if(brother->color == BLACK ){
				brother->color == RED;
				brother->right->color == BLACK;
				tree = left_rotate(tree,brother);
			}
			else {
				brother->color ==  BLACK;
				brother->father->color == RED;
				tree = right_rotate(tree,brother->father);
			}
		}

	}

	fix->color = BLACK;
    return tree;
}
struct rb_head* rb_delete(struct rb_head *tree,struct rb_head *x)
{
	enum color color;
	struct rb_head *repx,*fix;
	
	if(x->left == &mynil){
		repx = x->right;
		color = x->color;
		fix = repx;
		
		repx->father = x->father;
		if(x->father == &mynil)
			tree = repx;
		else if(x->father->left == x)
			x->father->left = repx;
		else 
			x->father->right = repx;
		
	}
	else if(x->right == &mynil){
		repx = x->left;
		color = x->color;
		fix  = repx;

		repx->father = x->father;
		if(x->father == &mynil)
			tree = repx;
		else if(x->father->left == x)
			x->father->left = repx;
		else 
			x->father->right = repx;
	}
	else {
		repx = tree_min(tree,x->right);
		color = repx->color;
		fix = repx->right;
	
		
		fix->father = repx->father;
		if(repx->father->left == repx)
			repx->father->left = fix;
		else
			repx->father->right = fix;
		

		repx->father =x->father;
		if(x->father == &mynil)
			tree = repx;
		else if(x->father->left == x)
			x->father->left = repx;
		else 
			x->father->right = repx;
	
		repx->left = x->left;
		x->left->father = repx;
		repx->right = x->right;
		x->right->father = repx;
		
		repx->color = x->color;

	
	}

    if (color == BLACK)
	    tree = rb_delete_fixup(tree,fix);
    return (tree == &mynil)?NULL:tree;
}
