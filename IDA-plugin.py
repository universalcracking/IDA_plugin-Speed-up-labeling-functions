import os, sys, csv
import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_name
import ida_ua

try:
    import ida_kernwin
except Exception:
    ida_kernwin = None


major, minor = map(int, idaapi.get_kernel_version().split("."))
IDAVER_74PLUS = (major == 7 and minor >= 4) or (major >= 8)

#  Defaults / Config (can be changed at runtime via Settings dialog)
CFG = {
    "export_max_bytes": 64,           # cap bytes per signature
    "export_only_auto": True,         # export only auto-generated names (sub_* etc.)
    "import_exec_first": True,        # search executable segments first
    "export_mask_immediates": True,   # mask tail bytes after offb or any refs
    "export_min_len": 5,              # minimal signature length in bytes
}

PLUGIN_NAME = "CFS Utils"
PLUGIN_HOTKEY_IMPORT = "Ctrl+Shift+I"
PLUGIN_HOTKEY_EXPORT = "Ctrl+Shift+E"
ACTION_PREFIX = "cfs_utils:"
ICON_ID = 198  

def is_autoname(s: str) -> bool:
    if not s:
        return True
    return s.startswith(("sub_", "nullsub_", "j_"))

def ensure_code_and_func(ea):
    flags = ida_bytes.get_full_flags(ea)
    if flags == 0 or not ida_bytes.is_code(flags):
        idc.create_insn(ea)
    if ida_funcs.get_func(ea) is None:
        ida_funcs.add_func(ea)

def iter_exec_segments():
    seg = idaapi.get_first_seg()
    while seg:
        if seg.perm & idaapi.SEGPERM_EXEC:
            yield seg.start_ea, seg.end_ea
        seg = idaapi.get_next_seg(seg.start_ea)

def bytes_to_hex(b):
    return " ".join(f"{x:02X}" for x in b)

def clean_func_name(function_name):
    s = ida_name.demangle_name(function_name, ida_name.DQT_FULL) or function_name
    if '(' in s:
        s = s.split('(')[0]
    parts = s.split()
    return parts[-1] if parts else s

def get_current_function_ea():
    ea = idc.here()
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idaapi.BADADDR

def iter_all_functions():
    for seg_ea in idautils.Segments():
        for func_ea in idautils.Functions(seg_ea):
            f = ida_funcs.get_func(func_ea)
            if not f:
                continue
            yield f

def ask_file_save_cfs(caption="Save CFS Signature File"):
    if IDAVER_74PLUS and ida_kernwin:
        return ida_kernwin.ask_file(True, "*.cfs", caption)
    return idaapi.ask_file(1, "*.cfs", caption)

def ask_file_open_cfs(caption="Cra0 Signature Definition File"):
    if IDAVER_74PLUS and ida_kernwin:
        return ida_kernwin.ask_file(False, "*.cfs", caption)
    return idaapi.ask_file(0, "*.cfs", caption)

def info_box(msg):
    if ida_kernwin:
        ida_kernwin.info(msg)
    else:
        print(msg)



def cfs_iter_rows(path):
    with open(path, "r", newline="") as f:
        reader = csv.reader(f, delimiter=',', quotechar='"', skipinitialspace=True)
        for row in reader:
            if not row:
                continue
            head = row[0].strip()
            if head.startswith("//") or head == "":
                continue
            if len(row) < 3:
                print("[SKIP] malformed line:", row)
                continue
            try:
                idx = int(head)
            except ValueError:
                print("[SKIP] bad index:", row)
                continue
            name = row[1].strip()
            sig = ",".join(row[2:]).strip()
            if sig.startswith('"') and sig.endswith('"'):
                sig = sig[1:-1]
            yield idx, name, sig

def find_all_matches(signature, max_matches=2, exec_first=True):
    matches = []
    if exec_first:
        for (lo, hi) in iter_exec_segments():
            ea = idaapi.find_binary(lo, hi, signature, 16, idaapi.SEARCH_DOWN)
            while ea != idaapi.BADADDR:
                matches.append(ea)
                if 0 < max_matches <= len(matches):
                    return matches
                ea = idaapi.find_binary(ea + 1, hi, signature, 16, idaapi.SEARCH_DOWN)
        if matches:
            return matches
    
    lo, hi = idaapi.cvar.inf.min_ea, idaapi.cvar.inf.max_ea
    ea = idaapi.find_binary(lo, hi, signature, 16, idaapi.SEARCH_DOWN)
    while ea != idaapi.BADADDR:
        matches.append(ea)
        if 0 < max_matches <= len(matches):
            break
        ea = idaapi.find_binary(ea + 1, hi, signature, 16, idaapi.SEARCH_DOWN)
    return matches

def import_cfs_file(cfs_path):
    resolved = 0
    total = 0
    errors = 0
    for idx, func_name, signature in cfs_iter_rows(cfs_path):
        total += 1
        matches = find_all_matches(signature, max_matches=2, exec_first=CFG["import_exec_first"])
        if len(matches) == 0:
            print(f"({resolved}/{total}) [----] [{func_name}] ==> [NOT FOUND]")
            continue
        if len(matches) > 1:
            print(f"({resolved}/{total}) [----] [{func_name}] ==> Multiple matches {len(matches)}. Ignored.")
            continue
        ea = matches[0]
        flags = ida_bytes.get_full_flags(ea)
        print(f"({resolved}/{total}) [{ea:X}] [{func_name}] ==> ", end="")
        if flags == 0:
            errors += 1
            print("[BAD] No flags at {:X}".format(ea))
            continue
        existing = ida_name.get_name(ea) or ""
        ensure_code_and_func(ea)
        if not existing or is_autoname(existing):
            if ida_name.validate_name(func_name, ida_name.VNT_VISIBLE):
                ida_name.set_name(ea, func_name, ida_name.SN_AUTO)
                f = ida_funcs.get_func(ea)
                if f:
                    ida_funcs.set_func_cmt(f, "SIG-RESOLVED " + func_name, True)
                else:
                    idc.set_cmt(ea, "SIG-RESOLVED " + func_name, 1)
                resolved += 1
                print("[RESOLVED]")
            else:
                errors += 1
                print("[ERROR] Invalid name")
        else:
            print("[IGNORED] Already named '{}'".format(existing))
    print("------------------------------------------")
    print("Resolved ({}/{}) Functions!".format(resolved, total))
    if errors:
        print("Errors ({})".format(errors))
        return False
    return True

class ImportAction(idaapi.action_handler_t):
    def activate(self, ctx):
        path = ask_file_open_cfs()
        if not path:
            return 1
        print("------------------------------------------")
        print("CFS Import - (bundle)")
        print("Parsing:", path)
        idaapi.show_wait_box("Importing... Please wait.")
        try:
            ok = import_cfs_file(path)
            if not ok:
                idaapi.warning("Some errors occurred while importing.")
        finally:
            idaapi.hide_wait_box()
        return 1
    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS



def ua_maxop():
    return idaapi.UA_MAXOP if hasattr(idaapi, "UA_MAXOP") else ida_ua.UA_MAXOP

def get_opcode_header_size(insn):
    for i in range(ua_maxop()):
        if insn.ops[i].type == ida_ua.o_void:
            break
        if insn.ops[i].offb != 0:
            return insn.ops[i].offb
    return 0

def has_any_ref(insn):
    return (idaapi.get_first_dref_from(insn.ea) != idaapi.BADADDR) or \
           (idaapi.get_first_cref_from(insn.ea) != idaapi.BADADDR)

def append_masked(insn, sig):
    offb = get_opcode_header_size(insn)
    size = insn.size
    if offb == 0:
        data = ida_bytes.get_bytes(insn.ea, size) or b""
        sig.extend(bytes_to_hex(data).split())
        return
    # header
    hdr = ida_bytes.get_bytes(insn.ea, offb) or b""
    sig.extend(bytes_to_hex(hdr).split())
    # tail
    tail_len = max(0, size - offb)
    if tail_len:
        if CFG["export_mask_immediates"] and (has_any_ref(insn) or tail_len >= 4):
            sig.extend(["?"] * tail_len)
        else:
            data = ida_bytes.get_bytes(insn.ea + offb, tail_len) or b""
            sig.extend(bytes_to_hex(data).split())

def make_signature(start_ea, end_ea, max_bytes):
    ea = start_ea
    sig = []
    while ea < end_ea and len(sig) < max_bytes:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0 or insn.size <= 0:
            break
        append_masked(insn, sig)
        ea += insn.size
    if len(sig) > max_bytes:
        sig = sig[:max_bytes]
    if len(sig) < CFG["export_min_len"]:
        return None
    return " ".join(sig)

def selected_funcs_from_functions_window():
    if not ida_kernwin:
        return []
    try:
        import sip
        tw = ida_kernwin.find_widget("Functions window")
        if not tw:
            return []
        from PyQt5 import QtWidgets
        w = sip.wrapinstance(int(tw), QtWidgets.QWidget)
        if not w:
            return []
        table = w.findChild(QtWidgets.QTableView)
        if not table:
            return []
        rows = table.selectionModel().selectedRows()
        sel_names = [str(s.data()) for s in rows]
        res = []
        names_set = set(sel_names)
      
        for f in iter_all_functions():
            nm = idc.get_name(f.start_ea)
            if nm in names_set or clean_func_name(nm) in names_set:
                res.append(f.start_ea)
        return res
    except Exception:
        return []

def export_signatures():
    # collect candidates
    funcs_ea = []
    selected = selected_funcs_from_functions_window()
    if selected:
        funcs_ea = selected
    else:
        cur = get_current_function_ea()
        if cur != idaapi.BADADDR:
            funcs_ea = [cur]
        else:
            # ask: all?
            if ida_kernwin:
                r = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
                                       "No selection/current function.\nExport all functions?")
                if r == ida_kernwin.ASKBTN_YES:
                    for f in iter_all_functions():
                        nm = idc.get_name(f.start_ea) or ""
                        if CFG["export_only_auto"] and not is_autoname(nm):
                            continue
                        funcs_ea.append(f.start_ea)
            if not funcs_ea:
                idaapi.warning("No suitable functions to export.")
                return

    
    out = ask_file_save_cfs()
    if not out:
        print("No file selected.")
        return

    
    if ida_kernwin:
        s = ida_kernwin.ask_str(str(CFG["export_max_bytes"]), 0,
                                "Max signature length in bytes (16..256)")
        try:
            v = int(s)
            CFG["export_max_bytes"] = max(16, min(256, v))
        except:
            pass

    idaapi.show_wait_box("Exporting signatures...")
    try:
        count = 0
        with open(out, "w", newline="") as fp:
            writer = csv.writer(fp, delimiter=',', quotechar='"')
            writer.writerow(["// CFS exported by CFS Utils"])
            for idx, ea in enumerate(funcs_ea):
                start = idc.get_func_attr(ea, idc.FUNCATTR_START)
                end   = idc.get_func_attr(ea, idc.FUNCATTR_END)
                name  = idc.get_func_name(start) or f"sub_{start:X}"
                if CFG["export_only_auto"] and not is_autoname(name):
                    continue
                clean = clean_func_name(name)
                sig   = make_signature(start, end, CFG["export_max_bytes"])
                if not sig:
                    continue
                # index, "name", "AA BB ??"
                writer.writerow([idx, clean, sig])
                count += 1
        print(f"Exported {count} function signatures to {out}")
        info_box(f"Export selesai: {count} fungsi → {out}")
    finally:
        idaapi.hide_wait_box()

class ExportAction(idaapi.action_handler_t):
    def activate(self, ctx):
        export_signatures()
        return 1
    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


class SettingsAction(idaapi.action_handler_t):
    def activate(self, ctx):
        self.show_dialog()
        return 1
    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS

    def show_dialog(self):
        if not ida_kernwin:
            idaapi.warning("Settings dialog requires ida_kernwin / PyQt5.")
            return
        from PyQt5 import QtWidgets, QtCore

        dlg = QtWidgets.QDialog()
        dlg.setWindowTitle("CFS Utils Settings")
        form = QtWidgets.QFormLayout(dlg)

        spin_max = QtWidgets.QSpinBox()
        spin_max.setRange(16, 256)
        spin_max.setValue(CFG["export_max_bytes"])

        chk_auto = QtWidgets.QCheckBox("Export only auto-named functions (sub_*)")
        chk_auto.setChecked(CFG["export_only_auto"])

        chk_exec = QtWidgets.QCheckBox("Importer: search executable segments first")
        chk_exec.setChecked(CFG["import_exec_first"])

        chk_mask = QtWidgets.QCheckBox("Exporter: mask immediates/refs")
        chk_mask.setChecked(CFG["export_mask_immediates"])

        spin_min = QtWidgets.QSpinBox()
        spin_min.setRange(1, 32)
        spin_min.setValue(CFG["export_min_len"])

        form.addRow("Export max bytes:", spin_max)
        form.addRow("", chk_auto)
        form.addRow("", chk_exec)
        form.addRow("", chk_mask)
        form.addRow("Export min length:", spin_min)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        form.addRow(btns)

        def accept():
            CFG["export_max_bytes"] = spin_max.value()
            CFG["export_only_auto"] = chk_auto.isChecked()
            CFG["import_exec_first"] = chk_exec.isChecked()
            CFG["export_mask_immediates"] = chk_mask.isChecked()
            CFG["export_min_len"] = spin_min.value()
            dlg.accept()
        def reject(): dlg.reject()

        btns.accepted.connect(accept)
        btns.rejected.connect(reject)
        dlg.exec_()

class UIHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        
        try:
            if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(widget, popup_handle, ACTION_PREFIX + "export", "CFS Utils/", idaapi.SETMENU_APP)
                idaapi.attach_action_to_popup(widget, popup_handle, ACTION_PREFIX + "import", "CFS Utils/", idaapi.SETMENU_APP)
                idaapi.attach_action_to_popup(widget, popup_handle, ACTION_PREFIX + "settings", "CFS Utils/", idaapi.SETMENU_APP)
        except Exception:
            pass
        return 0



class CFSUtilsPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "CFS Utils (Import + Export) plugin"
    help = "Import/Export function signatures"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        
        idaapi.unregister_action(ACTION_PREFIX + "import")
        idaapi.unregister_action(ACTION_PREFIX + "export")
        idaapi.unregister_action(ACTION_PREFIX + "settings")

        act_import = idaapi.action_desc_t(
            ACTION_PREFIX + "import", "CFS Import...", ImportAction(),
            PLUGIN_HOTKEY_IMPORT, "Import .cfs signatures", ICON_ID
        )
        act_export = idaapi.action_desc_t(
            ACTION_PREFIX + "export", "CFS Export...", ExportAction(),
            PLUGIN_HOTKEY_EXPORT, "Export .cfs signatures", ICON_ID
        )
        act_settings = idaapi.action_desc_t(
            ACTION_PREFIX + "settings", "CFS Settings...", SettingsAction(),
            "", "Configure CFS Utils", ICON_ID
        )

        idaapi.register_action(act_import)
        idaapi.register_action(act_export)
        idaapi.register_action(act_settings)

      
        idaapi.attach_action_to_menu('File/Load file/', ACTION_PREFIX + "import", idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu('File/Produce file/', ACTION_PREFIX + "export", idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu('Edit/Plugins/', ACTION_PREFIX + "settings", idaapi.SETMENU_APP)

       
        self._hooks = UIHooks()
        self._hooks.hook()

        idaapi.msg(f"{PLUGIN_NAME} initialized (Import/Export/Settings).\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg(f"{PLUGIN_NAME} cannot be run as a script.\n")

    def term(self):
        try:
            self._hooks.unhook()
        except Exception:
            pass
        idaapi.unregister_action(ACTION_PREFIX + "import")
        idaapi.unregister_action(ACTION_PREFIX + "export")
        idaapi.unregister_action(ACTION_PREFIX + "settings")
        idaapi.msg(f"{PLUGIN_NAME} terminated.\n")

def PLUGIN_ENTRY():
    return CFSUtilsPlugin()
