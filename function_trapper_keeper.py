"""
Author: Alexander Hanel
Version: 1.0
Purpose: Function Trapper Keeper is an IDA plugin for writing and storing notes related to functions.
Requirements: ida-netnode
Updates:
    * Version 1.0 Release
"""

import idautils
import idaapi
import ida_idaapi
import idc
import ida_funcs
import ida_kernwin
import ida_hexrays

from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets

try:
    from netnode import netnode
except:
    raise Exception("please install ida-netnode")

frm = None

class MyViewHooks(idaapi.View_Hooks):
    def view_curpos(self, view):
        self.refresh_widget(view)

    def view_dblclick(self, view, event):
        self.refresh_widget(view)

    def view_click(self, view, event):
        self.refresh_widget(view)

    def view_loc_changed(self, view, now, was):
        self.refresh_widget(view)

    def refresh_widget(self, view):
        global frm
        frm.refresh_widget(view)

class FuncNotes(PluginForm):

    def OnCreate(self, form):
        self.current_display = 0
        self.current_function = 0
        self.func_comment = False
        self.ViewHook = MyViewHooks()
        self.ViewHook.hook()
        # init storage
        self.name = "___FUNC_NOTES___"
        self.netnode_instance = None
        self.init_netnode()
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        self.main_layout = QtWidgets.QVBoxLayout()
        self.parent.setLayout(self.main_layout)

        self.menu_bar = QtWidgets.QMenuBar()
        self.func_comment_menu = self.menu_bar.addMenu('Options..')

        viewStatAct = QtWidgets.QAction('Add Function Comments', self.parent, checkable=True)
        viewStatAct.setChecked(False)
        viewStatAct.triggered.connect(self.enable_comments)
        self.func_comment_menu.addAction(viewStatAct)

        if ida_hexrays.init_hexrays_plugin():
            viewStatActPseudo = QtWidgets.QAction('Refresh decompiler comments', self.parent,
                                                  checkable=True)
            viewStatActPseudo.setChecked(False)
            viewStatActPseudo.triggered.connect(self.refresh_psuedo)
        else:
            viewStatActPseudo = QtWidgets.QAction('Refresh decompiler comments - Decompiler Not Found', self.parent,
                                                  checkable=False)
            viewStatActPseudo.setChecked(False)
        self.func_comment_menu.addAction(viewStatActPseudo)

        self.markdown_editor_label = QtWidgets.QLabel()
        self.markdown_editor_label.setText("Editor")

        self.markdown_editor = QtWidgets.QTextEdit()
        self.markdown_editor.textChanged.connect(self.reload_markdown)

        self.markdown_viewer_label = QtWidgets.QLabel()
        self.markdown_viewer_label.setText("Preview")
        self.markdown_viewer = QtWidgets.QTextEdit()
        self.markdown_viewer.setReadOnly(True)

        # add button
        self.addbtn = QtWidgets.QPushButton("Export Report")
        self.addbtn.clicked.connect(self.export_md)

        self.main_layout.addWidget(self.menu_bar)
        self.main_layout.addWidget(self.markdown_editor_label)
        self.main_layout.addWidget(self.markdown_editor)
        self.main_layout.addWidget(self.markdown_viewer_label)
        self.main_layout.addWidget(self.markdown_viewer)
        self.main_layout.addWidget(self.addbtn)
        self.reload_markdown()

    def reload_markdown(self):
        # check if the current function has changed
        if self.current_display != self.current_function:
            # current function has changed
            self.current_display = self.current_function
            # get saved data
            markdown_text = self.get_data(self.current_display)
            if markdown_text:
                # markdown data is present
                # change editor and view
                self.markdown_viewer.setMarkdown(markdown_text)
                self.markdown_editor.setText(markdown_text)
                self.update_data(self.current_display, markdown_text)

            else:
                self.markdown_viewer.setMarkdown("")
                self.markdown_editor.setMarkdown("")
                self.update_data(self.current_display, markdown_text)

        else:
            # editor function has not changed
            # save persistent data and display it
            markdown_text = self.markdown_editor.toPlainText()
            self.update_data(self.current_display, markdown_text)
            self.markdown_viewer.setMarkdown(markdown_text)

    def refresh_widget(self, view):
        widgetType = idaapi.get_widget_type(view)
        if widgetType == idaapi.BWN_DISASM:
            ea = ida_kernwin.get_screen_ea()
            if not ea:
                return
            # validate offset is within a function
            temp_current_function = ida_funcs.get_func(ea)
            if not temp_current_function:
                return
            # get the start of the function
            temp_current_f = temp_current_function.start_ea
            if not temp_current_f:
                return
            if temp_current_f != self.current_function:
                self.current_function = temp_current_f
                self.reload_markdown()

        elif widgetType == idaapi.BWN_PSEUDOCODE:
            ea = ida_kernwin.get_screen_ea()
            if not ea:
                return
            cfunc = idaapi.decompile(ea)
            for cc, item in enumerate(cfunc.treeitems):
                if item.ea != idaapi.BADADDR:
                    if cfunc.treeitems.at(cc).ea == ea:
                        # cursor offset was found in decompiler tree
                        # validate offset is within a function
                        cur_func = ida_funcs.get_func(ea)
                        if not cur_func:
                            return
                            # get the start of the function
                        current_f = cur_func.start_ea
                        if not current_f:
                            return
                        if current_f != self.current_function:
                            self.current_function = current_f
                            self.reload_markdown()
            if self.refresh_psuedo:
                cfunc.refresh_func_ctext()

    def enable_comments(self):
        if self.func_comment:
            self.func_comment = False
        else:
            self.func_comment = True

    def refresh_psuedo(self):
        if ida_hexrays.init_hexrays_plugin():
            if self.refresh_psuedo:
                self.refresh_psuedo = False
            else:
                self.refresh_psuedo = True

    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        self.ViewHook.unhook()
        pass

    def init_netnode(self):
        self.netnode_instance = netnode.Netnode(self.name)

    def update_data(self, func_start_ea, data):
        self.netnode_instance[func_start_ea] = data
        if self.func_comment:
            if isinstance(data, (bytes, bytearray)):
                idc.set_func_cmt(func_start_ea, data, 1)
            else:
                idc.set_func_cmt(func_start_ea, data, 1)

    def get_data(self, func_start_ea):
        if func_start_ea not in self.netnode_instance:
            return ""
        str_data = self.netnode_instance[func_start_ea]
        if not str_data or str_data == b"\x00":
            return ""
        return str_data

    def export_md(self):
        idb_path = idc.get_idb_path()
        import sys
        import os
        if sys.version_info[0] < 3.4:
            import pathlib
            suffix = pathlib.Path(idb_path).suffix
        else:
            suffix = os.path.splitext(idb_path)[1]
        md_path = idb_path.replace(suffix, ".md")
        if not md_path:
            print("ERROR: could not export markdown report.")
            return
        out_data = ""
        with open(md_path, "w") as export_file:
            for func in idautils.Functions():
                t_data = self.get_data(func)
                if not t_data:
                    continue
                out_data += t_data
                out_data += os.linesep
                off_str = " - name: %s " % idc.get_func_name(func)
                out_data += off_str
                out_data += os.linesep
                off_str = " - start: 0x%x " % func
                out_data += off_str
                out_data += os.linesep
                out_data += "***"
                out_data += os.linesep
            export_file.write(out_data)
        print("STATUS: exported", md_path)


class FuncNotesPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MOD
    comment = 'Function Trapper Keeper is a function note taker window that supports Markdown.'
    help = ''
    wanted_name = 'Function Trapper Keeper'
    wanted_hotkey = 'Ctrl-Shift-N'

    def init(self):
        self.forms = []
        self.options = (ida_kernwin.PluginForm.WOPN_MENU |
            ida_kernwin.PluginForm.WOPN_ONTOP |
            ida_kernwin.PluginForm.WOPN_RESTORE |
            ida_kernwin.PluginForm.WOPN_PERSIST |
            ida_kernwin.PluginForm.WCLS_CLOSE_LATER)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        global frm
        frm = FuncNotes()
        frm.Show("Function Trapper Keeper", options=self.options)
        frm.reload_markdown()

    def term(self):
        pass

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return FuncNotesPlugin()