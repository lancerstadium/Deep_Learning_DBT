/**
 * \file  ./test/temp_02.c
 * \brief 求 0~100 以内所有质数之和
*/

#include <stdio.h>
#include <math.h>

int main() {
    int i, j;
    int sum = 0;
    for (i = 2; i <= 100; i++) {
        for (j = 2; j < i; j++) {
            if (i % j == 0) {
                break;
            }
        }
        if (i == j) {
            sum += i;
        }
    }
    printf("%d\n", sum);
    return 0;
}