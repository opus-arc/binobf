# binobf

binobf 是面向通用软件的 ARM64 二进制混淆工具。首版提供三个可实际接入构建流程的模块：指定函数的原生寄存器多样化、独立整数函数的字节码虚拟化，以及任意二进制资源的分页编码。实现不依赖音频、模型或某一个应用。

**0.1.0 是受限后端的实验性首版。** 当前保护范围有意收紧，遇到不能可靠识别的代码会拒绝处理。它没有宣称不可逆、无法被 AI 分析，或已经实现通用强加密。

## 构建与验证

```sh
sh ./build.sh --test-only
python3 ./bin/binobf --version
sh ./build.sh --platform source
```

需要 Python 3.10+。读取、检查和原生代码变换只使用标准库；虚拟化和资源访问器的编译需要 C99 编译器。macOS 请安装命令行开发工具。

在 Apple Silicon macOS 上运行 `sh ./build.sh --platform macos-arm64`，才会执行该平台的原生机器码、重链接与签名验证。Linux 宿主机的测试结果不能替代这一步。发布工作流只在原生测试和实际压缩包解包验证通过之后发布。

## 使用

```sh
binobf inspect engine.o
binobf protect engine.o -o engine.protected.o --function control_step
binobf virtualize control.o -o control.protected.o --abi u32x2
binobf pack-data model.bin -o model.packed.c --symbol model --notice-ja
```

- `inspect`：识别 ARM64 Mach-O / AArch64 ELF64，列出符号及每个函数是否符合当前后端约束，不执行输入文件。
- `protect`：对指定整数叶函数的 W8–W15 临时寄存器做一致置换，保持指令数量、函数大小、地址与计算顺序。它主要提供构建多样性，单独使用的语义隐藏能力有限。
- `virtualize`：读取独立 `.o` 中的真实 ARM64 机器码，生成每函数独立编码的字节码、解释器和原符号接口，再编译成替换对象。用它替代原来的对象参与链接。当前仅支持 `uint32_t(uint32_t,uint32_t)` 的无栈、无访存、无调用、无跳转整数叶函数。额外数据、局部代码、别名和文本重定位会被拒绝。
- `pack-data`：把任意文件生成为分页打乱和可逆编码后的 C 资源，通过 `model_size()` 与 `model_read(offset, buffer, length)` 按需读取，不分配内存，也不维护整份明文缓存。它不是密码学加密；找到读取接口仍可恢复完整资源。

虚拟化适合低频控制与选择逻辑。实时 DSP、逐像素渲染和数值热循环应先保持原生，再根据实际测量决定是否保护。当前不对浮点/SIMD做代数变换。

`--notice-ja` 加入普通的日文许可告知，提示遵守宿主应用的许可并保留合法使用例外；它不是 AI 访问控制机制，也不改变 binobf 自身的 MIT 许可。

默认每次生成新种子；`--seed` 可用于可复现构建。保留的生成 C、种子和构建记录应视为应用的私有构建中间产物。发行应用时不要同时打包原始资源或未保护的函数对象。

## 发行

采用与 cppobf 相近的简洁目录和发布形式：README、根目录构建脚本、源码随附的 `.tar.gz` / `.zip`、`SHA256SUMS`。安装方式是解压后运行 `bin/binobf` 或把该目录加入 PATH；首版没有 Homebrew 公式。

输入始终保留，输出必须使用另一个路径。已有输出需要 `--force`。已经签名的 Mach-O 修改后需重新签名；`--sign ad-hoc` 用于 macOS 本地验证，正式发行仍需在保护完成后按你的流程进行 Developer ID 签名与公证。

完整参数、指令限制和验证要求见 [README.md](README.md)。原始实现采用 [MIT License](LICENSE)，来源说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
