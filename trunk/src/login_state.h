/*
 *  login_state.h
 *  YiXun
 *
 *  Created by Summer Town on 9/25/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _GET_LOGIN_STATE_H
#define _GET_LOGIN_STATE_H

enum login_state {
	not_login,
	connecting,
	connected,
};

typedef void (*callback) (enum login_state s);

extern void set_login_state(enum login_state s);
extern enum login_state get_login_state();
//extern void set_state_changed_action(callback p);
//extern void unset_state_changed_action();
extern void free_login_state_locks();

#endif
