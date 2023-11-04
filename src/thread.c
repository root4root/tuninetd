#include <pthread.h>

#include "common.h"
#include "xnflog.h"
#include "xpcap.h"

static pthread_t pcap_x_thread;
static pthread_t nflog_x_thread;

static pthread_attr_t attr;
static pthread_mutex_t lock;

static int x, y;

void thread_init()
{
    if (pthread_mutex_init(&lock, NULL) != 0) {
        message(ERROR, "Mutex init failed. Abort.");
        exit(1);
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (globcfg.dev_name) {
        message(INFO, "Binding to interface %s", globcfg.dev_name);
        pthread_create(&pcap_x_thread, &attr, pcap_x, &x);
    }

    if (globcfg.nf_group >= 0) {
        message(INFO, "Start listening nflog-group %i", globcfg.nf_group);
        pthread_create(&nflog_x_thread, &attr, nflog_x, &y);
    }

}

void switch_state(short action)
{
    if (status == action) {
        message(INFO, "|- Event already fired, skipping... (multiple capture engines?)");
        return;
    }

    ts = time(NULL);

    if (action == ON) {

        if (system(globcfg.cmd_path_start) != 0) {
            message(WARNING, "Warning! Executable command doesn't return 0 code (%s)", globcfg.cmd_path_start);
        }

        status = ON;

    } else { //action == OFF

        if (system(globcfg.cmd_path_stop) != 0) {
            message(WARNING, "Warning! Executable command doesn't return 0 code (%s)", globcfg.cmd_path_stop);
        }

        status = OFF;

    }
}

void switch_guard(short action)
{
    pthread_mutex_lock(&lock);
    switch_state(action);
    pthread_mutex_unlock(&lock);
}
