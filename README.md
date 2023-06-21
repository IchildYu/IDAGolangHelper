# 短期内大改，效果如下。

你以为的 Go 逆向（就算通过插件恢复出了函数名， F5 仍然没法看，函数参数完全错误，伪代码依托答辩）：
![image](https://github.com/IchildYu/IDAGolangHelper/assets/54837947/828d2061-73ae-4464-b545-9ec64b66c018)

实际的 Go 逆向（仅通过插件即可恢复到这样的形式。还有一些瑕疵，需要再手动改动一些地方。动调？不如静态分析）：
![image](https://github.com/IchildYu/IDAGolangHelper/assets/54837947/d25122bc-8220-40b0-97e6-5cb69eec54be)

（仅限于 ida 7.5 及以下版本，更高版本 ida 兼容了对 Go 调用约定伪代码会好看很多）

这还不够？再放两张对比图。

![image](https://github.com/IchildYu/IDAGolangHelper/assets/54837947/b9abb28c-7368-43c2-82b8-8e08385cf82b)

![image](https://github.com/IchildYu/IDAGolangHelper/assets/54837947/90072d63-d0bf-4841-95d6-b59abff008b8)

解释一下，这张图里这么多红色的 v4 不是错误，而是 v4 是 xmm15 全 0 ，这些赋值都是清零操作。

===========================

# 以下是原 readme

===========================

# IDAGolangHelper
Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary


This is update for https://gitlab.com/zaytsevgu/GoUtils2.0

Differences:
  1. Add support for go1.8 and go1.9, go1.10 (well actually it seems no difference from go1.9)
  2. Automatically add user-defined types to IDA. (Can be checked in Shift+f9 view)
  3. Add some not very advanced string recognition. You can press Shift+S to process current function


https://2016.zeronights.ru/wp-content/uploads/2016/12/GO_Zaytsev.pdf - My presentation about Golang reversing

support go 1.20 but no 1.18(i have no the sample with go 1.18), only works in rename functions 

pcln struct and version magic number: https://go.dev/src/debug/gosym/pclntab.go

func struct: https://go.dev/src/runtime/runtime2.go


## how to rename functions

click button 1 "try to detemine go version based on moduledata"

if not work

click button 2 "try to detemine go version based on version string"

then click button 3 rename functions

## about go 1.18

Go 1.18 and Go 1.20 have the same struct in pcln and func table. 

U can add go 1.18 magic number detection in Gopclnatb.findGoPcLn, and add go 1.18 string in __init__.getVersionByString.

Then use Gopclnatb.check_is_gopclntab18_20, Gopclnatb.rename120 in go 1.18 version
