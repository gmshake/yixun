#ifndef _LISTEN_THREAD_H
#define _LISTEN_THREAD_H

extern int lanuch_listen_thread();
extern int stop_listen_thread();
extern int wait_listen_thread();


extern int lanuch_keep_alive_thread(size_t t);
extern int stop_keep_alive_thread();
extern int wait_keep_alive_thread();


#endif
