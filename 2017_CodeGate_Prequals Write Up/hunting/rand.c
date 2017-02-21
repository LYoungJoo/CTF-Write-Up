// http://nextline.tistory.com/110
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void)
{
    int i;
    srand(time(NULL));
    for (i = 0; i < 100; ++i)
        printf("%d\n", rand() & 3);
    return 0;
}
