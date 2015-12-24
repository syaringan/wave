#ifndef LOCK_H
#define LOCK_H
#include<pthread.h>
#include<stddef.h>

/**
 *定义成这样，方便我们以后换所。
 */
/**
 * 这里我们要做一个大的修改，以前我们用的是读写锁，但是读写锁不支持嵌套，主要是写的时候，而在我们写代码的时候
 * 我们原以为这个锁能够嵌套的，所以下面把这个读写锁，改成了互斥量，并默认互斥量为可以递归嵌套的
 */
typedef pthread_mutex_t lock;
static int inline lock_init(lock* lock){
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(lock,&attr);
    pthread_mutexattr_destroy(&attr);
    return 0;
}

static int inline lock_rdlock(lock* lock){
    return pthread_mutex_lock(lock);
}

static int inline lock_tryrdlock(lock* lock){
    return pthread_mutex_trylock(lock);
}
static int inline lock_wrlock(lock* lock){
    return pthread_mutex_lock(lock);
}
static int inline lock_trywrlock(lock* lock){
    return pthread_mutex_trylock(lock);
}
static int inline lock_unlock(lock* lock){
    return pthread_mutex_unlock(lock);
}
static int inline lock_destroy(lock* lock){
    return pthread_mutex_destroy(lock);
}
#endif
