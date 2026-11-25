/* logger.c - bounded log queue (mutex + condition variable) drained by a logger thread that adds timestamps */
#define _GNU_SOURCE
#include "logger.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define LOG_MAX_QUEUED 4096
#define LOG_LINE 256

struct log_entry {
    struct timespec when;
    char text[LOG_LINE];
    struct log_entry *next;
};

static struct log_entry *head;
static struct log_entry *tail;
static int queued;
static unsigned long lost;
static int stopping;
static int started;
static FILE *log_file;
static pthread_t log_tid;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t log_cond = PTHREAD_COND_INITIALIZER;

void log_msg(const char *fmt, ...)
{
    struct log_entry *e;
    va_list ap;

    e = malloc(sizeof *e);
    if (e == NULL)
        return;
    clock_gettime(CLOCK_REALTIME, &e->when);
    va_start(ap, fmt);
    vsnprintf(e->text, sizeof e->text, fmt, ap);
    va_end(ap);
    e->next = NULL;

    pthread_mutex_lock(&log_lock);
    if (!started || stopping || queued >= LOG_MAX_QUEUED) {
        lost++;
        pthread_mutex_unlock(&log_lock);
        free(e);
        return;
    }
    if (tail != NULL)
        tail->next = e;
    else
        head = e;
    tail = e;
    queued++;
    pthread_cond_signal(&log_cond);
    pthread_mutex_unlock(&log_lock);
}

static void write_entry(struct log_entry *e)
{
    struct tm tm;
    char stamp[32];

    localtime_r(&e->when.tv_sec, &tm);
    strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(log_file, "[%s.%03ld] %s\n", stamp, e->when.tv_nsec / 1000000, e->text);
    printf("[%s] %s\n", stamp, e->text);
}

static void *logger_thread(void *arg)
{
    (void)arg;

    pthread_mutex_lock(&log_lock);
    for (;;) {
        while (head == NULL && !stopping)
            pthread_cond_wait(&log_cond, &log_lock);
        if (head == NULL && stopping)
            break;

        struct log_entry *list = head;
        head = NULL;
        tail = NULL;
        queued = 0;
        pthread_mutex_unlock(&log_lock);

        while (list != NULL) {
            struct log_entry *next = list->next;
            write_entry(list);
            free(list);
            list = next;
        }
        fflush(log_file);
        fflush(stdout);

        pthread_mutex_lock(&log_lock);
    }
    pthread_mutex_unlock(&log_lock);
    return NULL;
}

int logger_start(const char *path)
{
    log_file = fopen(path, "a");
    if (log_file == NULL) {
        perror(path);
        return -1;
    }
    pthread_mutex_lock(&log_lock);
    started = 1;
    pthread_mutex_unlock(&log_lock);

    if (pthread_create(&log_tid, NULL, logger_thread, NULL) != 0) {
        fprintf(stderr, "cannot start logger thread\n");
        fclose(log_file);
        return -1;
    }
    return 0;
}

void logger_stop(void)
{
    unsigned long n;

    pthread_mutex_lock(&log_lock);
    stopping = 1;
    pthread_cond_signal(&log_cond);
    pthread_mutex_unlock(&log_lock);
    pthread_join(log_tid, NULL);

    pthread_mutex_lock(&log_lock);
    n = lost;
    pthread_mutex_unlock(&log_lock);
    if (n > 0)
        fprintf(log_file, "%lu log messages were lost (queue full)\n", n);
    fclose(log_file);
}
