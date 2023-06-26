import idaapi
import ida_kernwin

class GolangHelper:
    class MyForm(idaapi.Form):
        VERSIONS = [
            ['go 1.2', 'go 1.3', 'go 1.4', 'go 1.5', 'go 1.6', 'go 1.7', 'go 1.8', 'go 1.9', 'go 1.10', 'go 1.11', 'go 1.12', 'go 1.13', 'go 1.14', 'go 1.15'],
            ['go 1.16', 'go 1.17'],
            ['go 1.18', 'go 1.19'],
            ['go 1.20'],
        ]
        def __init__(self):
            import GoUtils
            idaapi.require("GoUtils")
            idaapi.require("GoUtils.Gopclntab")
            idaapi.require("GoUtils.Utils")
            idaapi.require("GoUtils.Types")
            idaapi.require("GoUtils.Firstmoduledata")
            idaapi.require("GoUtils.GoStrings")

            self.gopclntab = 0
            self.go_version = 'go 1.2'
            self.invert = False
            idaapi.Form.__init__(self, r"""STARTITEM {id:cGoVers}
GolangHelper

{FormChangeCb}
<##Detect go version and gopclntab:{detect_btn}>
<##    Set gopclntab manually     :{set_gopclntab_btn}>
Go version:
<Go1.2-1.15:{r2}>
<Go1.16-1.17:{r16}>
<Go1.18-1.19:{r18}>
<Go1.20:{r20}>{cGoVers}>
--------------------------------
<##       Rename functions        :{rename_func_btn}>
<##      Parse go type names      :{parse_types_btn}>
<##  Parse current go type name   :{parse_type_btn}>
--------------------------------
<##  Set function types (simple)  :{retype_func_btn}>
<##     Detect strings (slow)     :{detect_string_btn}>
""", {
                'detect_btn': idaapi.Form.ButtonInput(self.detect),
                'set_gopclntab_btn': idaapi.Form.ButtonInput(self.set_gopclntab),
                'cGoVers': idaapi.Form.RadGroupControl(("r2", "r16", "r18", "r20")),
                'rename_func_btn': idaapi.Form.ButtonInput(self.rename_func),
                'parse_types_btn': idaapi.Form.ButtonInput(self.parse_types),
                'parse_type_btn': idaapi.Form.ButtonInput(self.parse_type),
                'retype_func_btn': idaapi.Form.ButtonInput(self.retype_func),
                'detect_string_btn': idaapi.Form.ButtonInput(self.detect_string),
                'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange),
            })

        def find_version(self, gopclntab):
            vers = GoUtils.find_go_version(gopclntab)
            if vers:
                for i in range(len(self.VERSIONS)):
                    if vers in self.VERSIONS[i]:
                        self.go_version = vers
                        print('Set go version "' + vers + '"')
                        self.SetControlValue(self.cGoVers, i)
                        break
                else:
                    print('Unknown go version: ' + vers)
            else:
                print('Failed to find go version')

        def detect(self, code=0):
            val = GoUtils.find_gopclntab()
            if val:
                print('Set gopclntab to 0x%x' % val)
                self.gopclntab = val
                self.find_version(val)
            else:
                print('Failed to find gopclntab')

        def set_gopclntab(self, code=0):
            val = ida_kernwin.ask_addr(self.gopclntab, "Input gopclntab address:")
            if isinstance(val, int):
                self.gopclntab = val
                print('Set gopclntab to 0x%x' % val)
                self.find_version(val)

        def rename_func(self, code=0):
            if self.gopclntab == 0:
                print('Please set gopclntab and go version first.')
                return
            if self.go_version not in self.VERSIONS[self.GetControlValue(self.cGoVers)]:
                self.go_version = self.VERSIONS[self.GetControlValue(self.cGoVers)][0]
                print('Set go version "' + self.go_version + '"')
            GoUtils.renameFunctions(self.gopclntab, self.go_version)

        def parse_types(self, code=0):
            if self.gopclntab == 0:
                print('Please set gopclntab and go version first.')
                return
            GoUtils.parse_types(self.gopclntab, self.go_version)

        def parse_type(self, code=0):
            if self.gopclntab == 0:
                print('Please set gopclntab and go version first.')
                return
            print(GoUtils.parse_type(ida_kernwin.get_screen_ea(), self.gopclntab, self.go_version))

        def retype_func(self, code=0):
            GoUtils.retypeFunctions()

        def detect_string(self, code=0):
            GoUtils.detect_string()

        def OnFormChange(self, fid):
            if self.go_version not in self.VERSIONS[self.GetControlValue(self.cGoVers)]:
                self.go_version = self.VERSIONS[self.GetControlValue(self.cGoVers)][0]
                print('Set go version "' + self.go_version + '"')
            return 1

    def main(self):
        f = self.MyForm()
        f.Compile()
        ok = f.Execute()
        f.Free()

def GolangHelper_main(ctx):
    GolangHelper().main()

class GolangHelperPlugin(idaapi.plugin_t):
    wanted_name = "GolangHelper"
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE | idaapi.PLUGIN_MOD

    class ActionHandler(idaapi.action_handler_t):
        def __init__(self, name, label, shortcut=None, tooltip=None, icon=-1, flags=0):
            idaapi.action_handler_t.__init__(self)
            self.name = name
            self.action_desc = idaapi.action_desc_t(name, label, self, shortcut, tooltip, icon, flags)

        def register_action(self, callback, menupath):
            self.callback = callback
            if not idaapi.register_action(self.action_desc):
                return False
            if menupath and not idaapi.attach_action_to_menu(menupath, self.name, idaapi.SETMENU_APP):
                return False
            return True

        def activate(self, ctx):
            self.callback(ctx)

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def init(self):
        menu_name = "MyTools"
        idaapi.create_menu(menu_name, menu_name, "Help")
        action = GolangHelperPlugin.ActionHandler("GolangHelper:main", "GolangHelper main")
        if action.register_action(GolangHelper_main, menu_name):
            print('[+] GolangHelper loaded')
            return idaapi.PLUGIN_OK
        print('[-] GolangHelper failed to load')
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return

def PLUGIN_ENTRY():
    return GolangHelperPlugin()
