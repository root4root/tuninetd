#include "main.h"
#include <pthread.h>

static pthread_t pcap_x_thread;
static pthread_t tun_x_thread;
static pthread_t nflog_x_thread;

static pthread_attr_t attr;
static pthread_mutex_t lock;

static int x, y;

void thread_init()
{
    if (pthread_mutex_init(&lock, NULL) != 0) {
        my_err("Mutex init failed. Abort.");
        exit(1);
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (globcfg.nf_group < 0) {
        my_info("Binding to interface %s", globcfg.dev_name);
        pthread_create(&pcap_x_thread, &attr, pcap_x, &x);
        pthread_create(&tun_x_thread, &attr, tun_x, &y);
    } else {
        my_info("Start listening nflog-group %i", globcfg.nf_group);
        pthread_create(&nflog_x_thread, &attr, nflog_x, &y);
    }
}

void switch_state(short action)
{
    if (status == action) {
        return;
    }

    ts = time(NULL);

    if (action == ON) {
        if (system(globcfg.cmd_path_start) != 0)
            my_err("Warning! Executable command doesn't return 0 (%s)", globcfg.cmd_path_start);

        status = ON;

    } else {
        if (system(globcfg.cmd_path_stop) != 0)
            my_err("Warning! Executable command doesn't return 0 (%s)", globcfg.cmd_path_stop);

        status = OFF;

        if (globcfg.nf_group < 0)
            pthread_create(&tun_x_thread, &attr, tun_x, &y);

    }
}

void switch_guard(short action)
{
    pthread_mutex_lock(&lock);
    switch_state(action);
    pthread_mutex_unlock(&lock);
}
