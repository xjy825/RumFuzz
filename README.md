# RumFuzz
RumFuzz is a MOpt-AFL-based fuzzer designed to make reasonable use of memory. We modify the instrumentation algorithm to set the appropriate bitmap size at compile time based on the number of Basic Blocks in the program. In order to reduce memory consumption under the premise of ensuring the performance of the fuzzer, we design a metric to measure the distance between seed and crash seed set, and combine it with the modified Exp3 algorithm to optimize seed scheduling and energy allocation of CGF with lightweight algorithms. The installation of RumFuzz is the same as AFL's. 

### The Difference with the Use of AFL
After compilation, a text file with the same name as the target program is generated, which contains a reasonable `MAP_SIZE`, set the `MAP_SIZE` in `config.h` according to this value, and then recompile the target program, the subsequent fuzzing method is the same as AFL.

