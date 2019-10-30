//must be compiled dynamically
#include <stdio.h>

int main(){
    while(1){
        puts("111");
        sleep(2);
        gettimeofday();
	if (getuid()==0)
	{
		printf("[+] Congratulations! You get root shell !!! [+]\n");
		system("/bin/sh");
	}
    }
}
