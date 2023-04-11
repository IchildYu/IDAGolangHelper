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
