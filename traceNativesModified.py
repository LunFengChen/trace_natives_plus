# -*- coding: utf-8 -*-
# author: LunFengChen
# date: 2025-09-06
import os
import sys
import time

# ida提供的api
import idaapi
import idautils
import idc


class TraceNativesModified(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Generate frida-trace command for all native functions"
    help = "Trace functions and export 'frida-trace' command to txt"
    wanted_name = "traceNatives_modified"
    wanted_hotkey = "Ctrl+Shift+H" # 如果使用快捷键的话就可以修改分批的数量
    
    def init(self):
        print("traceNatives(modified by LunFengChen) plugin has been loaded.")
        
        self.HAS_PYPERCLIP = False  # 是否安装了 pyperclip 模块
        self.check_pyperclip()
        return idaapi.PLUGIN_OK


    def check_pyperclip(self):
        """检查 pyperclip 是否可用"""
        try:
            import pyperclip
            self.HAS_PYPERCLIP = True
        except ImportError:
            self.HAS_PYPERCLIP = False
            print(
                "pyperclip模块不可用，无法自动复制到剪切板。如需此功能请在ida的python环境下执行命令安装：python.exe -m pip install pyperclip, 方法如下:"
            )
            print("1. 前IDA使用的Python版本：", sys.version)
            print("2. 当前ida工作目录：", os.path.dirname(sys.executable), "，请在此目录下寻找 python 目录，并使用其中的 pip.exe 执行上述安装命令。")


    def ask_str_compat(self, default, flags, prompt):
        """兼容新旧IDA的字符串输入"""
        try:
            import ida_kernwin
            return ida_kernwin.ask_str(default, flags, prompt)
        except ImportError:
            return idc.ask_str(default, flags, prompt)
            
    
    def get_so_path_and_name(self):
        """获取当前分析文件的路径和文件名"""
        fullpath = idaapi.get_input_file_path()
        filepath, filename = os.path.split(fullpath)
        return filepath, filename


    def get_text_seg_range(self):
        """获取.text段的起止地址"""
        text_start = []
        text_end = []
        for seg in idautils.Segments():
            seg_name = idc.get_segm_name(seg)
            if seg_name and seg_name.lower() in ('.text', 'text'):
                text_start.append(idc.get_segm_start(seg))
                text_end.append(idc.get_segm_end(seg))
        if text_start and text_end:
            return min(text_start), max(text_end)
        return None, None

    
    def run(self, arg):
        """ida脚本默认运行函数"""
        batch_num = self.ask_str_compat("-1", 0, "输入分批trace的函数数量(默认10000, 输入-1则进行整体trace):")
        self.trace_natives(batch_num)
        
        
    def command_copy_to_clipboard(self, text):
        """将文本复制到剪切板"""
        if self.HAS_PYPERCLIP:
            try:
                import pyperclip
                pyperclip.copy(text)
                print("命令已复制到剪切板！")
            except Exception as e:
                print(f"复制到剪切板失败: {e}")
        else:
            print("pyperclip模块不可用，无法自动复制到剪切板。")
        
    def trace_natives(self, batch_num_str):
        # 查找需要的函数
        # ==================== 1. 获取.text段起止地址 ====================
        ea, ed = self.get_text_seg_range()  # 获取.text段起止地址
        search_result = []     # 存放目标函数地址
        for func in idautils.Functions(ea, ed):  # 遍历.text段内所有函数
            try:
                function_name = str(idaapi.ida_funcs.get_func_name(func))  # 获取函数名
                if len(list(idautils.FuncItems(func))) > 10:  # 函数指令数大于10
                    # 如果是thumb模式，地址+1
                    arm_or_thumb = idc.get_sreg(func, "T")  # 判断是否为thumb
                    if arm_or_thumb:
                        func += 1  # thumb模式地址+1
                    search_result.append(hex(func))  # 记录函数地址
            except Exception as e:
                print(f"获取函数名失败: {e}")
        
        # ==================== 2. 获取so路径和名称 ====================
        so_path, so_name = self.get_so_path_and_name()  # 获取so路径和名称
        search_result = [f"-a '{so_name}!{offset}'" for offset in search_result]  # 按照frida-trace命令格式，hook so中的函数

        
        # ==================== 3. 保存trace命令 ====================
        is_batch = False
        if batch_num_str == "-1" or not batch_num_str or not batch_num_str.isdigit() or int(batch_num_str) <= 0:
            print("进行整体trace")
        else:
            is_batch = True
            print("进行分批trace, 每批最大函数数量:", batch_num_str)
            
            
        if not is_batch:
            # ==================== 3.1 全部trace ====================
            script_base = so_name.split(".")[0]  # 生成文件名
            all_trace_path = os.path.join(so_path, f"{script_base}_all.txt")   # 全部trace命令保存路径
            with open(all_trace_path, "w", encoding="utf-8") as F:
                F.write(" ".join(search_result))  # 写入全部trace命令

            cmd_all = f"frida-trace -UF -O {all_trace_path}"
            cmd_all_log = f"frida-trace -UF -O {all_trace_path} -o all.log"
            print("全部trace命令：")
            print(cmd_all)  # 输出frida-trace命令
            self.command_copy_to_clipboard(cmd_all)
            print(cmd_all_log)  # 输出frida-trace命令
        else:
            # ==================== 3.2 分批trace ====================
            batch_size = int(batch_num_str)  # 每批最大10000个
            total = len(search_result)  # 总数
            num_files = (total + batch_size - 1) // batch_size  # 计算批次数
            save_paths = []  # 保存每批文件路径

            script_base = so_name.split(".")[0]  # 生成文件名
            for i in range(num_files):
                batch = search_result[i*batch_size:(i+1)*batch_size]  # 当前批次
                script_name = f"{script_base}_batch_{i+1}.txt"  # 当前批次文件名
                save_path = os.path.join(so_path, script_name)  # 当前批次文件路径
                with open(save_path, "w", encoding="utf-8") as F:
                    F.write(" ".join(batch))  # 写入当前批次trace命令
                save_paths.append(save_path)  # 记录路径

            print("分批trace命令(手动复制执行)：")
            for idx, path in enumerate(save_paths):
                print(f"frida-trace -UF -O {path} -o {idx+1}.log")  # 输出每批frida-trace命令

    def term(self):
        """ida脚本卸载时调用"""
        pass


def PLUGIN_ENTRY():
    return TraceNativesModified()


if __name__ == "__main__":
    print("请在IDA中使用此脚本作为插件运行。 主要逻辑在TraceNativesModified类的trace_natives中。")
