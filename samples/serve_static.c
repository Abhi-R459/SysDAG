#include <stdio.h>

int main(void) {
    FILE *f = fopen("/guest/www/index.html", "r");
    if (!f) return 1;
    char buf[1024];
    while (fgets(buf, sizeof buf, f)) fputs(buf, stdout);
    fclose(f);
    return 0;
}
