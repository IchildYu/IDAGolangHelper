# Task Done

## Preparation

Download and place file `GolangHelper.py` and directory `GoUtils` under ida plugin directory, shown as below.

```
|- $IDA_HOME
  |- ...
  |- plugins
    |- ...
    |- GoUtils
      |- *.py
    |- GolangHelper.py
    |- ...
  |- ...
```

When you open ida, you can see `[+] GolangHelper loaded` in the output window and an extra menu in the menu bar:

![image](https://github.com/IchildYu/IDAGolangHelper/assets/54837947/21173e8a-6737-4217-91f3-0587790924e9)

And, to use GolangHelper, you need a golang binary.

## Plugin main

After loading a golang binary and finishing the initial autoanalysis of ida, just click `GolangHelper main`, and a form emerges.

![image](https://github.com/IchildYu/IDAGolangHelper/assets/54837947/117f57fd-b370-4258-a6c0-2557b9614888)

## Set function types

The last 2 functions do not need go version and gopclntab.

Golang uses a different calling convention. From ida 7.7 this calling convention was introduced and named as `__golang`. But I guess many of us are still using 7.5, so it's difficult recover beautiful pseudocode with F5. 

Luckily, we have another option: `__usercall`(see [Igor’s tip of the week #51: Custom calling conventions – Hex Rays](https://hex-rays.com/blog/igors-tip-of-the-week-51-custom-calling-conventions/)). We can set function type with `__usercall` and specify every register in the parameters. But we still need to edit every function type manually, that's painful.

Later I found something interesting. Most functions would check stack size and call `runtime.morestack_noctxt` at the beginning, which is clear in the pseudocode. But there's something more, this function would save the parameters before going to `runtime.morestack_noctx`, shown as below.

![image](https://github.com/IchildYu/IDAGolangHelper/assets/54837947/ee3460a9-d1b8-4c26-843d-6eba3e83cf4f)

Apparently, we can utilize this and get to know the count of parameters of this function automatically, and use `__usercall`! For return values, it's still difficult to specify more than 2 registers (in fact, we can, but it makes little effect in pseudocode), so I just set 2 regs to return and spoils other 3 regs: `_OWORD __usercall _@<rbx:rax>([parameters...])`.

Just try clicking `Set function types`, the effect will be obvious.

## Detect strings

Unlike C string ending with NULL, golang gathers many strings together without NULL, and specifies the length of every string (either in data, as string structure or in code). And it's another pain for ida 7.5, that ida only recognize this whole string.

`Detect strings` would take them apart.

## Detect go version and gopclntab

Similar to that of original IDAGolangHelper. But this can be wrong. So I added `Set gopclntab manually` option if you can find the correct address. How to find gopclntab manually is not the topic here.

## Rename functions

Similar to that of original IDAGolangHelper.

## Parse go type names

Parses only type names.

## Parse current go type name

Place your cursor at the type and click this after setting gopclntab.

===========================

# Original README: 

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
