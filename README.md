作用：ida插件，把所有函数都捕捉然后生成`frida-trace`命令，并支持复制到剪切板，快捷键 `Ctrl+Shift+H`

原版readme可以去看 [Pr0214/trace_natives](https://github.com/Pr0214/trace_natives)

这个仓库主要改了什么:
1. 添加分批trace的功能， 主要是对抗so函数非常多的情况
2. 优化使用体验和代码
    - 添加快捷键 `Ctrl+Shift+H` (H->hook)
    - 全部trace直接复制到剪切板
    - 代码加注释，采取PEP8规范，并直接使用面向对象写法

其他：
1. 如果需要关键次过滤可以看 [LunFengChen/traceFuncByKeyword](https://github.com/LunFengChen/traceFuncByKeyword)
2. ida插件练手用的，为后面的自动化去ollvm混淆插件做一些铺垫(但感觉之后也搞不出来hhh)


自我评价: 有点用但不是特别有用


反馈：issue或者进q群：686725227；

