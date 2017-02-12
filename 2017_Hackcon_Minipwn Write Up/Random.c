#include<stdio.h>
#include<time.h>
#include<stdlib.h>

int main(void)
{
    int a,rand_num;

    scanf("%d", &a); // seed
    srand(a);

    rand_num = rand();
    printf("%d",rand_num);
    return 0;
}
