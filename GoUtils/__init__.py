from . import Gopclntab
from . import Types
from . import Firstmoduledata
from . import Utils
from . import GoStrings

import idc
import idautils
import ida_ida
import ida_bytes
import ida_segment
import idaapi
import re

bt_obj = Utils.get_bitness(ida_ida.inf_get_min_ea())
def find_gopclntab():
    seg = ida_segment.get_segm_by_name('.gopclntab')
    if seg:
        print('.gopclntab segment found: 0x%x' % seg.start_ea)
        return seg.start_ea
    else:
        addr = Gopclntab.findGoPcLn()
        if addr:
            print('possible gopclntab found: 0x%x (Might be wrong. Consider setting it manually)' % addr)
        return addr

def find_go_version(gopclntab):
    possible_go_versions = []
    addr = ida_bytes.bin_search(0, idc.BADADDR, b'go1.', None, 0, ida_bytes.BIN_SEARCH_FORWARD)
    while addr != idc.BADADDR:
        print('go version string found at 0x%x' % addr)
        for i in idautils.XrefsTo(addr):
            size = bt_obj.ptr(i.frm + bt_obj.size)
            # print(hex(addr), size)
            if size == 0 or size > 10: continue
            s = ida_bytes.get_bytes(addr, size).decode()
            if not re.match('go1\.[0-9]+\.[0-9]+', s): continue
            s = 'go ' + s[2: s.rindex('.')]
            if s not in possible_go_versions and Gopclntab.check_go_version(gopclntab, s):
                possible_go_versions.append(s)
        addr = ida_bytes.bin_search(addr + 1, idc.BADADDR, b'go1.', None, 0, ida_bytes.BIN_SEARCH_FORWARD)
    if len(possible_go_versions) == 1:
        return possible_go_versions[0]
    elif len(possible_go_versions) > 1:
        print('Found possible go version:')
        for i in possible_go_versions:
            print(i)
        return possible_go_versions[0]
    else: # go version string not found
        print('Version may be inexact:')
        return Gopclntab.get_inexact_version(gopclntab)

def renameFunctions(gopclntab, go_version):
    return Gopclntab.renameFunctions(gopclntab, go_version, bt_obj)

def to_full_reg_name(reg):
    return ['rax', 'rbx', 'rcx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11'][
        [
            'rax', 'rbx', 'rcx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11',
            'eax', 'ebx', 'ecx', 'edi', 'esi', 'r8d', 'r9d', 'r10d', 'r11d', # in ida it is r8d not er8
            'ax', 'bx', 'cx', 'di', 'si', 'r8w', 'r9w', 'r10w', 'r11w', # not sure
            'al', 'bl', 'cl', 'dil', 'sil', 'r8b', 'r9b', 'r10b', 'r11b'
        ].index(reg) % 9
    ]

def generate_functype(args):
    # 5 return regs may be enough
    # Instead of "_OWORD __spoils<rcx, rdi, rsi> @<rbx:rax>", you can also
    # set return type as "pair__slice_err @<0: rax, 8: rbx, 16: rcx, 24: rdi, 32: rsi>"
    # But it does little help to F5. This is enough.
    if not args: return '_OWORD __usercall __spoils<rcx, rdi, rsi> _@<rbx:rax>()'

    # 9 argument regs may be enough
    go_args = ['rax', 'rbx', 'rcx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11']
    if len(args) > len(go_args):
        assert False, args
    for i in range(len(args)):
        if go_args[i] not in args:
            assert False, args
    return '_OWORD __usercall __spoils<rcx, rdi, rsi> _@<rbx:rax>(_QWORD@<' + '>, _QWORD@<'.join(go_args[: len(args)]) + '>)'

def retype_gofunc(addr):
    func_addr = addr
    functype = idc.get_type(func_addr)
    if functype and '__usercall' in functype: # already defined, or edit by user.
        return
    code = idc.GetDisasm(addr)
    addr += idc.get_item_size(addr)
    if re.match('cmp +rsp, \[r14\+.*\]', code): # cmp     rsp, [r14+10h]
        pass
    elif re.match('lea +r12, \[rsp.+\]', code) and re.match('cmp +r12, \[r14\+.*\]', idc.GetDisasm(addr)): # lea     r12, [rsp+var_28+8]; cmp     r12, [r14+10h]
        addr += idc.get_item_size(addr)
    else:
        return
    code = idc.GetDisasm(addr)
    if not re.match('jbe +.*', code): # jbe     loc_xxxxxx
        return
    if 'short' in code:
        assert idc.get_item_size(addr) == 2, hex(addr)
        addr = addr + ida_bytes.get_byte(addr + 1) + 2
    else:
        assert idc.get_item_size(addr) == 6, hex(addr)
        addr = addr + ida_bytes.get_dword(addr + 2) + 6
    regs_to_save = []
    code = idc.GetDisasm(addr)
    while not re.match('call +.*', code):
        if re.match('mov +(.* ptr )?\[rsp.+\], .*', code): # mov     [rsp+0A0h+var_98], rax
            reg = code[code.rindex(' ') + 1:]
            reg = to_full_reg_name(reg)
            regs_to_save.append(reg)
        addr += idc.get_item_size(addr)
        code = idc.GetDisasm(addr)
    functype = generate_functype(regs_to_save)
    print('0x%x -> %s' % (func_addr, functype))
    idc.SetType(func_addr, functype)


def retypeFunctions():
    if idaapi.get_inf_structure().get_procName() != 'metapc' or not idaapi.get_inf_structure().is_64bit():
        print('Only x86-64 supported.')
        return
    error_lines = []
    for func_addr in idautils.Functions():
        try:
            retype_gofunc(func_addr)
        except Exception as e:
            error_lines.append('Error at 0x%x: %s' % (func_addr, str(e)))
    for i in error_lines:
        print(i)

def parse_types(gopclntab, go_version):
    fmd = Firstmoduledata.findFirstModuleData(gopclntab, bt_obj)
    Types.parse_type_names(fmd, go_version, bt_obj)

def parse_type(type_addr, gopclntab, go_version):
    fmd = Firstmoduledata.findFirstModuleData(gopclntab, bt_obj)
    return Types.parse_type_name_at(type_addr, fmd, go_version, bt_obj)

def detect_string():
    GoStrings.detect_string()
