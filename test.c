#include <iostream>
#include <math.h>
using namespace std;

#define MAP_SIZE 4096

int main(){
    int cur = 0, pre = 0, index;
    for (int i = 0; i < 61; i++)
    {
        index = cur + pre;
        pre = cur * (int)sqrt(4096);
        cur = (cur + 1) % ((int)sqrt(4096) - 1);
        printf("%d %d %d", index, pre, cur);
    }
    
    return 0;
}