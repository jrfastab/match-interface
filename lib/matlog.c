#include <matlog.h>

/* by default, log messages to stdout */
struct mat_logger logger = {
	.closelog = mat_closelog_file,
	.openlog = mat_openlog_file,
	.syslog = mat_syslog_file,
	.logmask = MAT_LOG_UPTO(MAT_LOG_LEVEL),
	.stream = NULL, /* stdout setup by constructor... */
};

static void __attribute__((constructor, used)) mat_set_stdout(void)
{
	mat_set_log_stream(stdout);
}

void mat_setlogmask(unsigned mask)
{
	logger.logmask = mask;
}

void mat_set_log_functions(mat_closelog_func_t closelog,
                           mat_openlog_func_t openlog,
                           mat_syslog_func_t syslog)
{
	logger.closelog = closelog;
	logger.openlog = openlog;
	logger.syslog = syslog;
}

void mat_set_log_stream(FILE *stream)
{
	logger.stream = stream;
}

void mat_closelog_syslog(void)
{
	closelog();
}

void mat_openlog_syslog(const char *name)
{
	openlog(name, LOG_NDELAY | LOG_PID, LOG_DAEMON);
}

void mat_syslog_syslog(int level, const char *format, va_list args)
{
	vsyslog(level, format, args);
}

void mat_syslog_file(int level __attribute__((unused)), const char *format,
                     va_list args)
{
	vfprintf(logger.stream, format, args);
}

void mat_closelog_file(void)
{
}

void mat_openlog_file(const char *name __attribute__((unused)))
{
}

void mat_closelog(void)
{
	(*logger.closelog)();
}

void mat_openlog(const char *name)
{
	(*logger.openlog)(name);
}

void mat_syslog(int level, const char *format, ...)
{
	va_list args;

	if (level <= MAT_LOG_DEBUG && ((1U << level) & logger.logmask)) {
		va_start(args, format);
		(*logger.syslog)(level, format, args);
		va_end(args);
	}
}
