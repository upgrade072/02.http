
#include "auth.h"

extern char *__progname;

config_t CFG;

int main(int argc, char **argv) {
	if (argc != 4 && argc != 3) {
		fprintf(stderr, "usage for SVR) %s port key_file cert_file\n", __progname);
		fprintf(stderr, " -- recv via http/2 & response with oauth2.0 token\n");
		fprintf(stderr, "usage for CMD) %s nf_name my_uuid\n", __progname);
		fprintf(stderr, " -- create & print oauth2.0 token\n");
		exit(EXIT_FAILURE);
	}

	if (init_cfg() < 0)
		exit(EXIT_FAILURE);

	if (argc == 3) {
		return cmd_run(argv[1], argv[2]);
	}

	struct sigaction act;
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

	SSL_load_error_strings();
	SSL_library_init();

	/* loop ~! */
	run(argv[1], argv[2], argv[3]);

	return 0;
}
