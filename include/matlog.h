#ifndef _MATLOG_H
#define _MATLOG_H

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#define MAT_LOG_EMERG   LOG_EMERG
#define MAT_LOG_ALERT   LOG_ALERT
#define MAT_LOG_CRIT    LOG_CRIT
#define MAT_LOG_ERR     LOG_ERR
#define MAT_LOG_WARNING LOG_WARNING
#define MAT_LOG_NOTICE  LOG_NOTICE
#define MAT_LOG_INFO    LOG_INFO
#define MAT_LOG_DEBUG   LOG_DEBUG

#define MAT_LOG_UPTO(upto) LOG_UPTO((upto))

/* Remove, at compile-time, MAT_LOG messages above MAT_LOG_LEVEL */
#ifndef MAT_LOG_LEVEL
#define MAT_LOG_LEVEL MAT_LOG_DEBUG
#endif

/**
 * Macro for logging messages.
 *
 * The MAT_LOG macro is helpful to remove debug/log messages at
 * compile time. Messages with level below MAT_LOG_LEVEL are
 * never emitted, and when compiled with optimization, are not
 * present in the compiled output.
 */
#define MAT_LOG(level, ...)                                 \
do {                                                        \
	if (MAT_LOG_ ## level <= MAT_LOG_LEVEL)             \
		mat_syslog(MAT_LOG_ ## level, __VA_ARGS__); \
} while (0)

void mat_closelog(void);
void mat_openlog(const char *name);
void mat_syslog(int level, const char *format, ...);

/* typdefs to allow for overriding default functions */
typedef void (*mat_closelog_func_t)(void);
typedef void (*mat_openlog_func_t)(const char *name);
typedef void (*mat_syslog_func_t)(int level, const char *format, va_list args);

void mat_setlogmask(unsigned mask);
void mat_set_log_functions(mat_closelog_func_t closelog,
                           mat_openlog_func_t openlog,
                           mat_syslog_func_t syslog);
void mat_set_log_stream(FILE *stream);

/* wrapper to syslog */
void mat_closelog_syslog(void);
void mat_openlog_syslog(const char *name);
void mat_syslog_syslog(int level, const char *format, va_list args);

void mat_closelog_file(void);
void mat_openlog_file(const char *name);
void mat_syslog_file(int level, const char *format, va_list args);

struct mat_logger {
	mat_closelog_func_t closelog;
	mat_openlog_func_t openlog;
	mat_syslog_func_t syslog;
	unsigned logmask;
	FILE *stream;
};

#endif /* _MATLOG_H */
