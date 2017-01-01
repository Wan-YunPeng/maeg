#include <stdio.h>
int cpy(char *input)
{
	int n;
	char buf[1024];
	strcpy(buf,input);
	printf("%s\r\n", buf);
	printf("123%n\n", &n);
	printf("%d\n", n);
}
int main(int argc, char *argv[])
{
	if(strlen(argv[1]) > 1024){
		printf("buffer overflow attempt!!!\n");
		return 1;
	}
		cpy(argv[1]);
}
