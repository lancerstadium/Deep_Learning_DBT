/**
 * \file  ./test/temp_04.c
 * \brief 二分搜索
*/

#include <stdio.h>

/// @brief 二分查找
/// @param arr 有序数组
/// @param left 左侧元素的下标
/// @param right 右侧元素的下标
/// @param target 目标元素
/// @return 目标元素的下标
int binary_search(int arr[], int left, int right, int target) {
    if (left > right) {                     // 1. 递归出口：left > right
        return -1;
    }
    int mid = left + (right - left) / 2;    // 2. 计算中间元素的下标
    if (arr[mid] == target) {               // 3. 如果找到目标元素，返回中间元素的下标
        return mid;
    } else if (arr[mid] < target) {         // 4. 如果中间元素小于目标元素，右半部分递归调用
        return binary_search(arr, mid + 1, right, target);
    } else {                                // 5. 如果中间元素大于目标元素，左半部分递归调用
        return binary_search(arr, left, mid - 1, target);
    }
}



int main() {
    int arr[] = {2, 4, 6, 8, 10, 12, 14, 16};   // 有序数组 arr
    int target = 8;                             // 目标元素
    int res = binary_search(arr, 0, sizeof(arr) / sizeof(arr[0]) - 1, target);
    printf("%d\n", res);
    return 0;
}