#include <stdio.h>
#include <stdint.h> // uint8_t
#include <strings.h> //bzeor();
#include <unistd.h> //sleep()
#include <pthread.h>

#include <sys/types.h>
#include <sys/time.h>

#include "yixun_config.h"
#include "radius.h"
#include "common_macro.h"
#include "common_logs.h"
#include "login_state.h"
#include "print_hex.h"

typedef void *(*start_routine)(void *);

static pthread_t tid_l, tid_k;

static void * listen_thread(void *p)
{
    while(1)
    {
        accept_client();
    }
    return NULL;
}


static void * keep_alive_thread(size_t t)  // sleep t seconds and then send the keep alive packagt
{
	while (1)
	{
		if (sleep((unsigned int)t) > 0) break;	// something happens to stop sleep
        pthread_testcancel();
		if (send_keep_alive() < 0) // error when sending keep-alive package
		{
			sleep(2);
            pthread_testcancel();
			if (send_keep_alive() < 0) break;
		}
	}
    set_login_state(not_login);
    return NULL;
}

 
int lanuch_listen_thread()
{
    int err = pthread_create(&tid_l, /*&attr,*/ NULL, (start_routine)listen_thread, NULL);
    if (err != 0)
    {
        dperror("Error creating listen thread");
		return -4;
    }
	
	return 0;
}

int stop_listen_thread()
{
	if (pthread_cancel(tid_l) < 0)
	{
		dprintf("Error stop listen thread\n");
		return -1;
	}
	return 0;
}

int wait_listen_thread()
{
    if (pthread_join(tid_l, NULL) < 0)
    {
        dprintf("Error pthread_join\n");
        return -1;
    }
    return 0;
}


int lanuch_keep_alive_thread(size_t t)
{
    if (t <= 0)
    {
        dprintf("Check keep-alive parameters:%u\n", (unsigned)t);
        return -1;
    }
    int err = pthread_create(&tid_k, NULL, (start_routine)keep_alive_thread, (void *)t);
    if (err != 0)
    {
        dperror("Error creating listen thread");
		return -2;
    }

	return 0;
}

 
int stop_keep_alive_thread()
{
    if (pthread_cancel(tid_k) != 0)
	{
		dprintf("Error stop keep alive thread\n");
		return -1;
	}
	return 0;
}

int wait_keep_alive_thread()
{
    if (pthread_join(tid_k, NULL) < 0)
    {
        dprintf("Error pthread_join\n");
        return -1;
    }
    return 0;
}
