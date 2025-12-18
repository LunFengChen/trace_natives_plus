# Trace Natives Plus


## 解决什么问题？
在原始项目 [Pr0214/trace_natives](https://github.com/Pr0214/trace_natives) (批量 trace 功能) 的基础上新增如下功能：

1. **分批导出** 避免一次 hook 太多函数导致卡死
2. **关键字过滤** 只 trace 你关心的函数（如 encrypt、sign、md5）

为啥要有？ flutter 或者 游戏app的so函数太多了，直接frida-trace会崩溃但是分批还好，且过滤也不好，如我只想过滤 `encrypt` 的函数看走没走;


## 安装

将 `trace_natives_plus.py` 复制到 IDA 插件目录，我的是 `C:\software\idaPro9.2\plugins\` 下

## 使用

快捷键: `Ctrl+Alt+T`

或菜单: `Edit -> Plugins -> Trace Natives Plus`

### Trace All

选择分批数量：
- 不分批 - 导出所有函数到单个文件
- 5000/10000/20000/50000 - 按指定数量分批导出

### Trace by Keyword

支持链式过滤语法：
- `,` 表示 OR（同组内任一匹配）
- `|` 表示 AND（链式过滤）

示例：
```
encrypt,crypto|md5,sha,aes|sign
```
含义：先筛选包含 encrypt 或 crypto 的函数，再从结果中筛选包含 md5/sha/aes 的，最后筛选包含 sign 的。

## 输出

所有文件输出到 so 文件同目录下的 `trace_natives_plus/` 文件夹。

## 依赖

- IDA Pro 7.x+
- Python 3.x
- PyQt5（IDA 自带）

---
