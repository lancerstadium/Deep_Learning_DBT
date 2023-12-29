/**
 * \file  ./test/temp_03.c
 * \brief 求第 100 个斐波那契数
*/

#include <stdio.h>

int main() {
    int n = 100;
    unsigned long long first = 0, second = 1, next;
    
    for (int i = 2; i <= n; i++) {
        next = first + second;
        first = second;
        second = next;
    }
    
    printf("%llu\n", next);
    
    return 0;
}
