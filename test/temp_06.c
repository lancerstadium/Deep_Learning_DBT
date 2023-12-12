/**
 * \file  ./test/temp_06.c
 * \brief 矩阵连乘
*/

#include <stdio.h>

// 定义矩阵的数量
#define N 6

// 矩阵的行数和列数
int r[N+1] = {10, 30, 5, 60, 10, 20, 25};

// 定义动态规划数组
int dp[N+1][N+1];

// 返回a和b的最小值
int min(int a, int b) {
    return a < b ? a : b;
}

// 动态规划求解矩阵连乘问题
int matrixChainOrder() {
    // 1. 初始化边界条件
    for (int i = 1; i <= N; i++) {
        dp[i][i] = 0;
    }

    // 2. 填表求解
    for (int l = 2; l <= N; l++) {
        for (int i = 1; i <= N - l + 1; i++) {
            int j = i + l - 1;
            dp[i][j] = 99999999; // 初始值设为一个较大的数
            for (int k = i; k <= j - 1; k++) {
                int q = dp[i][k] + dp[k+1][j] + r[i-1]*r[k]*r[j];
                dp[i][j] = min(dp[i][j], q);
            }
        }
    }

    // 3. 返回最优解
    return dp[1][N];
}

int main() {
    int result = matrixChainOrder();
    // 打印矩阵维度信息
    for (int i = 1; i <= N; i++) {
        printf("%d ", r[i]);
    }
    printf("\nMinimum number of multiplications is: %d\n", result);

    return 0;
}



