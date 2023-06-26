
import ida_bytes
import idaapi
import idautils
import idc
from . import Utils

ptr = Utils.get_bitness()
def is_string(addr, length):
    val = ptr.ptr(addr)
    if idc.is_loaded(val): return False
    if val < 0x100 and val % 8 == 0: return False
    if not idc.is_loaded(addr): return False
    if length <= 0 or not idc.is_loaded(addr + length - 1): return False
    try:
        b = ida_bytes.get_bytes(addr, length)
        if 0 in b: return False
        b.decode()
        return True
    except:
        return False

def detect_string():
    str_table = []
    for seg_start in idautils.Segments():
        perm = idc.get_segm_attr(seg_start, idc.SEGATTR_PERM)
        if perm & 1: continue # x
        if not (perm & 4): continue # r
        seg_end = idc.get_segm_end(seg_start)
        if seg_start & (ptr.size - 1):
            seg_start = seg_start + (ptr.size - 1) & ~(ptr.size - 1)
        for i in range(seg_start, seg_end - ptr.size, ptr.size):
            length = ptr.ptr(i + ptr.size)
            # check length
            if length < 1 or length >= 0x800: continue
            addr = ptr.ptr(i)
            if length and addr not in str_table and is_string(addr, length):
                str_table.append(addr)
                s = ida_bytes.get_bytes(addr, length).decode()
                print('detected string at 0x%x (0x%x, %d): %s' % (i, addr, length, s))
                ida_bytes.del_items(addr)
                ida_bytes.create_strlit(addr, length, -1)

    str_table.sort()
    for i in range(len(str_table) - 1):
        addr = str_table[i]
        end_addr = str_table[i + 1]
        addr += idc.get_item_size(addr)
        while addr < end_addr:
            if idc.get_item_size(addr) != 1:
                ida_bytes.del_items(addr)
            if not next(idautils.XrefsTo(addr), None): break
            length = 1
            while idc.is_loaded(addr + length) and\
                idc.get_item_size(addr + length) == 1 and\
                not next(idautils.XrefsTo(addr + length), None):
                length += 1
            if not is_string(addr, length): break
            s = ida_bytes.get_bytes(addr, length).decode()
            print('extra string detected at 0x%x (%d): %s' % (addr, length, s))
            ida_bytes.del_items(addr)
            ida_bytes.create_strlit(addr, length, -1)
            addr += length

