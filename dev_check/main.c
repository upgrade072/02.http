#include "check.h"

extern char *__progname;
main_ctx_t MAIN_CTX;

int logLevel = APPLOG_DEBUG;
int *lOG_FLAG = &logLevel;

int initialize(main_ctx_t *MAIN_CTX)
{
	MAIN_CTX->CLI_ROOT = cli_init();
	cli_set_hostname(MAIN_CTX->CLI_ROOT, "http_check");
	cli_set_banner(MAIN_CTX->CLI_ROOT, "Welcome.\n This is http/2 dev check cli program");

#ifdef LOG_LIB
	char log_path[1024] = {0,};
	sprintf(log_path, "%s/log/ERR_LOG/%s", getenv(IV_HOME), __progname);
	initlog_for_loglib(__progname, log_path);
#elif LOG_APP
	/* log init */
	char log_path[1024] = {0,};
	sprintf(log_path, "%s/log", getenv(IV_HOME));
	LogInit(__progname, log_path);
#endif

	return 0;
}

void start_loop(main_ctx_t *MAIN_CTX)
{
	struct sockaddr_in servaddr = {0,};
	int on = 1, x, s;

	// Create a socket
	s = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	// Listen on port 12345
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(12345);
	bind(s, (struct sockaddr *)&servaddr, sizeof(servaddr));

	// Wait for a connection
	listen(s, 50);

	while ((x = accept(s, NULL, 0)))
	{
		// Pass the connection off to libcli
		cli_loop(MAIN_CTX->CLI_ROOT, x);
		close(x);
	}
}

int main()
{
	main_ctx_t *main_ctx = &MAIN_CTX;

	initialize(main_ctx);
	register_command(main_ctx);
	start_loop(main_ctx);

	cli_done(main_ctx->CLI_ROOT);

	return 0;
}
