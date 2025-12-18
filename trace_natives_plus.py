# -*- coding: utf-8 -*-
"""
Trace Natives Plus - IDA Pro Plugin
Author: LunFengChen
"""
import os
import re
from typing import Optional

import idaapi
import idautils
import idc

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QGroupBox, QRadioButton,
    QButtonGroup, QMessageBox
)


class IDA:
    """IDA API 封装，提供文件信息和函数获取"""
    
    @staticmethod
    def get_file_info() -> tuple[str, str]:
        fullpath = idaapi.get_input_file_path()
        return os.path.split(fullpath)
    
    @staticmethod
    def get_output_dir(filepath: str) -> str:
        output_dir = os.path.join(filepath, "trace_natives_plus")
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    @staticmethod
    def get_text_segment_range() -> tuple[Optional[int], Optional[int]]:
        starts, ends = [], []
        for seg in idautils.Segments():
            name = idc.get_segm_name(seg)
            if name and name.lower() in ('.text', 'text'):
                starts.append(idc.get_segm_start(seg))
                ends.append(idc.get_segm_end(seg))
        return (min(starts), max(ends)) if starts else (None, None)
    
    @staticmethod
    def get_all_functions() -> list[tuple[int, str]]:
        return [(ea, idc.get_func_name(ea)) for ea in idautils.Functions()]
    
    @staticmethod
    def get_text_functions(min_instructions: int = 10) -> list[tuple[int, str]]:
        ea_start, ea_end = IDA.get_text_segment_range()
        if ea_start is None:
            return []
        
        result = []
        for func in idautils.Functions(ea_start, ea_end):
            try:
                name = idaapi.ida_funcs.get_func_name(func)
                if len(list(idautils.FuncItems(func))) > min_instructions:
                    if idc.get_sreg(func, "T"):  # thumb 模式地址 +1
                        func += 1
                    result.append((func, name))
            except Exception:
                pass
        return result


class KeywordFilter:
    """
    关键字过滤器
    ',' 分隔同组关键字 (OR)
    '|' 分隔不同组 (AND - 链式过滤)
    """
    
    def __init__(self, raw: str):
        self.groups = self._parse(raw)
    
    def _parse(self, raw: str) -> list[list[str]]:
        groups = []
        for group in raw.split('|'):
            keywords = [kw.strip() for kw in group.split(',') if kw.strip()]
            if keywords:
                groups.append(keywords)
        return groups
    
    def filter(self, functions: list[tuple[int, str]], verbose: bool = True) -> list[tuple[int, str]]:
        result = functions
        
        for i, group in enumerate(self.groups):
            if not group:
                continue
            
            filtered = []
            for ea, name in result:
                for kw in group:
                    if kw.lower() in name.lower():
                        filtered.append((ea, name))
                        break
            
            result = filtered
            
            if verbose and len(result) <= 200:
                print(f"[*] 阶段 {i+1} ({','.join(group)}): {len(result)} 个函数")
                for _, name in result:
                    print(f"    {name}")
        
        return result


class TraceNativesPlusDialog(QDialog):
    BATCH_OPTIONS = [
        ("不分批", -1),
        ("5000", 5000),
        ("10000", 10000),
        ("20000", 20000),
        ("50000", 50000),
    ]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Trace Natives Plus")
        self.setMinimumWidth(500)
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        mode_group = QGroupBox("选择模式")
        mode_layout = QVBoxLayout(mode_group)
        self.mode_btn_group = QButtonGroup(self)
        self.radio_all = QRadioButton("Trace All - 批量trace所有native函数")
        self.radio_keyword = QRadioButton("Trace by Keyword - 关键字过滤函数")
        self.radio_all.setChecked(True)
        self.mode_btn_group.addButton(self.radio_all, 0)
        self.mode_btn_group.addButton(self.radio_keyword, 1)
        mode_layout.addWidget(self.radio_all)
        mode_layout.addWidget(self.radio_keyword)
        layout.addWidget(mode_group)
        
        self.all_group = QGroupBox("Trace All 选项")
        all_layout = QHBoxLayout(self.all_group)
        all_layout.addWidget(QLabel("分批数量:"))
        self.batch_combo = QComboBox()
        for label, _ in self.BATCH_OPTIONS:
            self.batch_combo.addItem(label)
        all_layout.addWidget(self.batch_combo)
        all_layout.addStretch()
        layout.addWidget(self.all_group)
        
        self.keyword_group = QGroupBox("Keyword 选项")
        keyword_layout = QVBoxLayout(self.keyword_group)
        hint = QLabel("链式过滤: ',' = OR, '|' = AND  示例: encrypt,crypto|md5,sha|sign")
        hint.setStyleSheet("color: gray; font-size: 11px;")
        keyword_layout.addWidget(hint)
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("输入关键字...")
        keyword_layout.addWidget(self.keyword_input)
        self.keyword_group.setVisible(False)
        layout.addWidget(self.keyword_group)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.run_btn = QPushButton("执行")
        self.run_btn.setMinimumWidth(100)
        self.run_btn.clicked.connect(self._on_run)
        btn_layout.addWidget(self.run_btn)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        self.mode_btn_group.buttonClicked.connect(self._on_mode_changed)
    
    def _on_mode_changed(self, btn):
        is_keyword = (btn == self.radio_keyword)
        self.all_group.setVisible(not is_keyword)
        self.keyword_group.setVisible(is_keyword)
        self.adjustSize()
    
    def _on_run(self):
        if self.radio_all.isChecked():
            self._run_trace_all()
        else:
            self._run_trace_keyword()
        self.accept()
    
    def _run_trace_all(self):
        batch_size = self.BATCH_OPTIONS[self.batch_combo.currentIndex()][1]
        filepath, filename = IDA.get_file_info()
        functions = IDA.get_text_functions()
        
        if not functions:
            print("[!] 未找到函数")
            return
        
        print(f"[*] 找到 {len(functions)} 个函数")
        args = [f"-a '{filename}!{hex(ea)}'" for ea, _ in functions]
        base_name = filename.split(".")[0]
        output_dir = IDA.get_output_dir(filepath)
        
        if batch_size <= 0:
            output_path = os.path.join(output_dir, f"{base_name}_all.txt")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(" ".join(args))
            print(f"[+] 已保存: {output_path}")
            print(f"[+] frida-trace -UF -O {output_path}")
            QMessageBox.information(self, "完成", f"已导出 {len(functions)} 个函数\n{output_path}")
        else:
            num_batches = (len(args) + batch_size - 1) // batch_size
            print(f"[*] 分 {num_batches} 批，每批 {batch_size} 个")
            for i in range(num_batches):
                batch = args[i * batch_size:(i + 1) * batch_size]
                output_path = os.path.join(output_dir, f"{base_name}_batch_{i+1}.txt")
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(" ".join(batch))
                print(f"[+] 批次 {i+1}: frida-trace -UF -O {output_path} -o batch_{i+1}.log")
            QMessageBox.information(self, "完成", f"已导出 {len(functions)} 个函数，分 {num_batches} 批\n{output_dir}")
    
    def _run_trace_keyword(self):
        keyword = self.keyword_input.text().strip()
        if not keyword:
            QMessageBox.warning(self, "提示", "请输入关键字")
            return
        
        filepath, filename = IDA.get_file_info()
        functions = IDA.get_all_functions()
        
        kf = KeywordFilter(keyword)
        filtered = kf.filter(functions)
        
        if not filtered:
            print("[!] 未找到匹配的函数")
            return
        
        print(f"[+] 找到 {len(filtered)} 个匹配函数")
        args = [f"-a '{filename}!0x{ea:X}'" for ea, _ in filtered]
        
        output_dir = IDA.get_output_dir(filepath)
        safe_keyword = re.sub(r'[\\/:*?"<>|]', '_', keyword)
        output_path = os.path.join(output_dir, f"trace_keyword_{safe_keyword}.txt")
        func_path = os.path.join(output_dir, f"trace_keyword_{safe_keyword}_funcs.txt")
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(" ".join(args))
        with open(func_path, "w", encoding="utf-8") as f:
            f.write("\n".join(name for _, name in filtered))
        
        print(f"[+] 已保存: {output_path}")
        print(f"[+] 函数列表: {func_path}")
        print(f"[+] frida-trace -UF -O {output_path}")
        QMessageBox.information(self, "完成", f"已导出 {len(filtered)} 个函数\n{output_path}")


class TraceNativesPlus(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Trace Natives Plus"
    help = "批量trace或关键字过滤trace"
    wanted_name = "Trace Natives Plus"
    wanted_hotkey = "Ctrl+Alt+T"
    
    def init(self):
        print("[*] Trace Natives Plus 已加载 (Ctrl+Alt+T)")
        return idaapi.PLUGIN_OK
    
    def run(self, arg):
        TraceNativesPlusDialog().exec_()
    
    def term(self):
        pass


def PLUGIN_ENTRY():
    return TraceNativesPlus()
