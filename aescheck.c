#include <stdio.h>
#include <stdint.h>

#define cpuid1ecx(out)                                  \
	asm("movl $1, %%eax\n\t"                        \
	    "cpuid\n\t"                                 \
	    "movl %%ecx, %0\n\t"                        \
	    : "=r" (out)                                \
	    :                                           \
	    : "eax", "ebx", "ecx", "edx")

int main (int argc, char **argv)
{
	uint32_t capabilities;
	cpuid1ecx(capabilities);
	if ((capabilities & (1<<25)) != 0)
	{
		printf("CPU has AES\n");
	}
	else
	{
		printf("CPU does not have AES\n");
	}
	return 0;
}
