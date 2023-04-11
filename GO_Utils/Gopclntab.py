import idc
import idautils
import idaapi
import ida_bytes
import ida_funcs
import ida_search
import ida_segment
from . import  Utils

info = idaapi.get_inf_structure()
try:
    is_be = info.is_be()
except:
    is_be = info.mf


lookup = "FF FF FF FB 00 00" if is_be else "FB FF FF FF 00 00"
lookup16 = "FF FF FF FA 00 00" if is_be else "FA FF FF FF 00 00"
lookup18 = "FF FF FF F0 00 00" if is_be else "F0 FF FF FF 00 00"
lookup20 = "FF FF FF F1 00 00" if is_be else "F1 FF FF FF 00 00"

def check_is_gopclntab(addr):
    ptr = Utils.get_bitness(addr)
    first_entry = ptr.ptr(addr+8+ptr.size)
    first_entry_off = ptr.ptr(addr+8+ptr.size*2)
    addr_func = addr+first_entry_off
    func_loc = ptr.ptr(addr_func)
    if func_loc == first_entry:
        return True
    return False

def check_is_gopclntab16(addr):
    ptr = Utils.get_bitness(addr)
    offset = 8 + ptr.size *6 
    # print(f"{addr+offset:x}")
    first_entry = ptr.ptr(addr+offset) + addr
    # print(f"{first_entry:x}")
    func_loc = ptr.ptr(first_entry)
    struct_ptr = ptr.ptr(first_entry+8) + first_entry
    first_entry = ptr.ptr(struct_ptr)
    if func_loc == first_entry:
        return True
    return False

def check_is_gopclntab18_20(addr):
    print(f"renzo-----header_addr: {addr:x}")
    ptr = Utils.get_bitness(addr)
    offset = 8 + ptr.size *7 
    first_entry = ptr.ptr(addr+offset) + addr
    print(f"renzo-----pclntable_addr: {first_entry:x}")
    func_loc = idc.get_wide_dword(first_entry)
    struct_ptr = idc.get_wide_dword(first_entry+4) + first_entry
    first_entry = idc.get_wide_dword(struct_ptr)
    print(f"renzo-----func_loc: {func_loc:x}")
    print(f"renzo-----first_entry: {first_entry:x}")
    if func_loc == first_entry:
        return True
    return False

def findGoPcLn():
    possible_loc = ida_search.find_binary(0, idc.BADADDR, lookup, 16, idc.SEARCH_DOWN) #header of gopclntab
    while possible_loc != idc.BADADDR:
        if check_is_gopclntab(possible_loc):
            return possible_loc
        else:
            #keep searching till we reach end of binary
            possible_loc = ida_search.find_binary(possible_loc+1, idc.BADADDR, lookup, 16, idc.SEARCH_DOWN)
    possible_loc = ida_search.find_binary(0, idc.BADADDR, lookup16, 16, idc.SEARCH_DOWN) #header of gopclntab
    while possible_loc != idc.BADADDR:
        print(f"found possible 1.16 gopclntab")
        if check_is_gopclntab16(possible_loc):
            print("Looks like this is go1.16 binary")
            return possible_loc
        else:
            #keep searching till we reach end of binary
            possible_loc = ida_search.find_binary(possible_loc+1, idc.BADADDR, lookup16, 16, idc.SEARCH_DOWN)
    #possible_loc = ida_search.find_binary(0, idc.BADADDR, lookup18, 16, idc.SEARCH_DOWN) #header of gopclntab
    #while possible_loc != idc.BADADDR:
    #    print(f"found possible 1.18 gopclntab")
    #    if check_is_gopclntab18_20(possible_loc):
    #        print("Looks like this is go1.18 binary")
    #        return possible_loc
    #    else:
    #        #keep searching till we reach end of binary
    #        possible_loc = ida_search.find_binary(possible_loc+1, idc.BADADDR, lookup18, 16, idc.SEARCH_DOWN)
    possible_loc = ida_search.find_binary(0, idc.BADADDR, lookup20, 16, idc.SEARCH_DOWN) #header of gopclntab
    while possible_loc != idc.BADADDR:
        print(f"found possible 1.20 gopclntab")
        if check_is_gopclntab18_20(possible_loc):
            print("Looks like this is go1.20 binary")
            return possible_loc
        else:
            #keep searching till we reach end of binary
            possible_loc = ida_search.find_binary(possible_loc+1, idc.BADADDR, lookup20, 16, idc.SEARCH_DOWN)
    return None


def rename(beg, ptr, make_funcs = True):
    base = beg
    pos = beg + 8 #skip header
    size = ptr.ptr(pos)
    pos += ptr.size
    end = pos + (size * ptr.size * 2)
    print("%x" % end)
    while pos < end:
        offset = ptr.ptr(pos + ptr.size)
        ptr.maker(pos)         #in order to get xrefs
        ptr.maker(pos+ptr.size)
        pos += ptr.size * 2
        ptr.maker(base+offset)
        func_addr = ptr.ptr(base+offset)
        if make_funcs == True:
            ida_bytes.del_items(func_addr, 1, ida_bytes.DELIT_SIMPLE)
            ida_funcs.add_func(func_addr)
        name_offset = idc.get_wide_dword(base+offset+ptr.size)
        name = idc.get_strlit_contents(base + name_offset)
        name = Utils.relaxName(name)
        Utils.rename(func_addr, name)


def rename16(beg, ptr, make_funcs = True):
    base = beg
    first_entry = ptr.ptr(base+ptr.size * 6 + 8) + base

    cnt = ptr.ptr(base + 8)
    funcname_start = base + 8 + ptr.size *7
    for i in range(cnt):
        struct_ptr = ptr.ptr(first_entry + i*ptr.size*2 + 8) + first_entry
        # print(f"{struct_ptr:x}")
        func_addr = ptr.ptr(first_entry + i*ptr.size*2)
        str_val = ida_bytes.get_dword(struct_ptr+8) + funcname_start
        name = ida_bytes.get_strlit_contents(str_val, -1, -1) 
        print(f"{func_addr:x} {name}")
        if make_funcs == True:
            ida_bytes.del_items(func_addr, 1, ida_bytes.DELIT_SIMPLE)
            ida_funcs.add_func(func_addr)
        # print(type(name))
        name = Utils.relaxName(name.decode())
        Utils.rename(func_addr, name)

        # fcn_name_offset = ptr.ptr(strict)
        # offset = ptr.ptr(pos + ptr.size)
        # ptr.maker(pos)         #in order to get xrefs
        # ptr.maker(pos+ptr.size)
        # pos += ptr.size * 2
        # ptr.maker(base+offset)
        # func_addr = ptr.ptr(base+offset)
        # if make_funcs == True:
        #     ida_bytes.del_items(func_addr, 1, ida_bytes.DELIT_SIMPLE)
        #     ida_funcs.add_func(func_addr)
        # name_offset = idc.get_wide_dword(base+offset+ptr.size)
        # name = idc.get_strlit_contents(base + name_offset)
        # name = Utils.relaxName(name)
        # Utils.rename(func_addr, name)

def rename120(beg, ptr, make_funcs = True):
    base = beg
    first_entry = ptr.ptr(base+ptr.size * 7 + 8) + base
    cnt = ptr.ptr(base + 8)

    func_entry = ptr.ptr(base + 8 + ptr.size * 2)
    print("renzo-----func_entry: {:x}".format(func_entry))
    funcname_start = base + ptr.ptr(base + 8 + ptr.size * 3)
    print("renzo-----funcname_start: {:x}".format(funcname_start))

    for i in range(cnt):
        struct_ptr = idc.get_wide_dword(first_entry + i*4*2 + 4) + first_entry
        # print(f"{struct_ptr:x}")
        func_addr = func_entry + idc.get_wide_dword(first_entry + i*4*2)
        str_val = idc.get_wide_dword(struct_ptr+4) + funcname_start
        name = ida_bytes.get_strlit_contents(str_val, -1, -1) 
        print(f"{func_addr:x} {name}")
        if make_funcs == True:
            ida_bytes.del_items(func_addr, 1, ida_bytes.DELIT_SIMPLE)
            ida_funcs.add_func(func_addr)
        # print(type(name))
        name = Utils.relaxName(name.decode())
        Utils.rename(func_addr, name)
