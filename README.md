0. OPTEE directory structure
https://blog.csdn.net/shuaifengyun/article/details/71499945

We need to care about:
CMakeLists.txt
ta/sub.mk


1. RUN OPTEE on QEMU
https://blog.csdn.net/shuaifengyun/article/details/71499619
$ cd build
$ make run // compile and run all projects under optee_examples

the folder will be copied to optee/out-br/build/optee_examples_ext-1.0

QEMU - enter c
normal world - password is "root"
normal world - optee_example_my_test


2. 

