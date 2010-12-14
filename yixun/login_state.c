/*
 *  get_login_state.c
 *  YiXun
 *
 *  Created by Summer Town on 9/25/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <pthread.h>
#include "login_state.h"

static enum login_state state;
static callback _callback;

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

enum login_state get_login_state()
{
    if (pthread_rwlock_tryrdlock(&rwlock)) pthread_rwlock_rdlock(&rwlock);
    enum login_state rvl = state;
    pthread_rwlock_unlock(&rwlock);
    return rvl;
}

void set_login_state(enum login_state s)
{
    if (pthread_rwlock_trywrlock(&rwlock)) pthread_rwlock_wrlock(&rwlock);
    state = s;
    pthread_rwlock_unlock(&rwlock);
    //if (_callback) _callback(s);
    //if (_callback) _callback(id, s, 1);
    return;
}

void set_state_changed_action(callback p)
{
    _callback = p;
}

void unset_state_changed_action()
{
    _callback = NULL;
}

void free_login_state_locks()
{
    pthread_rwlock_destroy(&rwlock);
}
