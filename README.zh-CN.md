# binobf

binobf 是面向通用软件的 ARM64 二进制混淆工具。提供指定函数的原生寄存器多样化、独立整数函数的字节码虚拟化，以及任意二进制资源的分页编码。0.2 开发分支新增分桶数据程序和配套的数值消费接口。实现不依赖音频或某一个应用。

**0.2.0-dev 是研究版本，尚未形成新的稳定保护等级。** 已发布的 0.1.0 仍单独保留。当前保护范围有意收紧，遇到不能可靠识别的代码会拒绝处理。它没有宣称不可逆、无法被 AI 分析，或已经实现通用强加密。新增模块需要接入源码构建，不能直接包裹任意已发行 CLI。

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

## 0.2 开发模块

### 分桶数据程序

```sh
binobf pack-data model.bin -o model.packed.c --symbol model --profile diverse
```

每次构建选取 8 或 16 个桶，每个有效桶使用不同的可逆整数运算顺序、页排列和字排列，不再输出统一的逐页 key / page-map 数组。接口仍是 `size/read`；旧提取器需要适配，复用隐藏读取器依然可以恢复全部数据。因此暂不改变默认的 `legacy` 配置，也不把旧脚本失效计为防破解成功。

载荷改用相邻转义字符串，减少大数据编译时的整数初始化节点。生成单元应使用 GCC / Clang，不启用 LTO，不组合使用 `-Wpedantic -Werror`；超长字符串超过了 C99 的最低翻译限额。读取成本通过 `python3 tools/benchmark_data.py` 实测；它测的是访问器，不是整个应用的音频延迟。

### 直接消费变换后的数值模型

```sh
binobf compile-model matrix.f32 -o matrix.compiled.c --symbol matrix --channels 6
cc -std=c99 -O2 -fno-lto -c matrix.compiled.c -o matrix.compiled.o
```

输入是按行排列的小端有限 f32，支持 2–16 列、最多 64 MiB。生成器在保持每个存储值精确可逆的条件下，对列做置换、变号和二次幂缩放，并在私有头文件中生成配套权重变换。模型载荷大小保持不变，另有一个字符串终止字节和生成代码。

权重变化时调用头文件中的 `matrix_prepare(weights, matrix_channels, &context)`，热循环调用 `matrix_evaluate(row, &context, &value)`；后者输出 double。两个接口都以 0 表示成功、-1 表示无效参数。`prepare` 为 static inline，可编译进入真实调用方。运行时不提供通用明文字节读取接口，不分配内存，也不还原整张矩阵。

这个模块只处理行点积，需要显式接入计算流程；它不自动改写任意 DSP、滤波器、神经网络或二进制函数。**移除明文读取接口不等于原始数据不可恢复**：可以控制基向量权重并观察输出时，仍能逐列恢复矩阵；变换后的数据与计算内核也能整体复用。上下文标签只用于防止误用，不是鉴权。单纯的列置换和二次幂缩放本身也不足以对抗熟练分析。

数值要求是 IEEE 舍入到最近、保留非正规数、不使用 fast-math 或重结合。f32 数据与权重的乘积可在 f64 中精确表示，但改变求和顺序会改变舍入结果，不能承诺逐位一致；发生抵消时也不能承诺很小的相对误差。生成代码拒绝 fast-math 编译，运行时浮点模式仍需调用方保证。完整误差界和 C 接入示例见英文 README。

`python3 tools/benchmark_model.py` 比较原始 f32 数据的原生 f64 点积与生成内核，单独记录权重准备、单行热点和整表扫描。CI 在 Linux 与 Apple Silicon 上保存这两种微基准结果，不用宿主机噪声较大的时间比值作为硬性通过门槛。

本轮负面验证已经确认：在剥除符号的 Linux x86-64 独立测试程序中，`diverse` 消除了测试的明文指纹，旧固定提取脚本也失效，但复用内部读取器仍完整恢复了 44 MiB 数据，176/176 个记录逐字节相同。这是它继续保持可选实验配置的原因。模型测试同样验证了可访问准备/求值接口时的基向量数值恢复；另一次剥符号模型的独立逆向检查尚未完成，不能记为通过。这些结果均不代表某个完整应用已经获得保护。

## 发行

采用与 cppobf 相近的简洁目录和发布形式：README、根目录构建脚本、源码随附的 `.tar.gz` / `.zip`、`SHA256SUMS`。安装方式是解压后运行 `bin/binobf` 或把该目录加入 PATH；首版没有 Homebrew 公式。

输入始终保留，输出必须使用另一个路径。已有输出需要 `--force`。已经签名的 Mach-O 修改后需重新签名；`--sign ad-hoc` 用于 macOS 本地验证，正式发行仍需在保护完成后按你的流程进行 Developer ID 签名与公证。

完整参数、指令限制和验证要求见 [README.md](README.md)。原始实现采用 [MIT License](LICENSE)，来源说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
