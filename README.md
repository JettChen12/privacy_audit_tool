# 隐私合规检测工具 v2.0

对标商业隐私合规检测（如史宾格）：在用户**同意隐私协议之前**，全量监测 App 的敏感行为调用，
输出违规结论、分类统计与调用堆栈归属。适用于送审（小米/OPPO/应用宝等 164 号文口径）前的自查。

## 使用（三步）

1. 启动**已 root** 的模拟器（MuMu：设置 → 打开 Root）或连接 root 真机
   —— 顶部"环境状态"卡实时显示 ADB / 设备 / Root / Frida 是否就绪
2. **把 APK 拖进投放区**（或点击选择），包名自动识别
3. 点 **开始检测**。弹窗提示时在设备上点隐私协议"同意"后继续对照复测

结束自动在 `reports/` 生成报告。**首次启动会自动安装依赖（frida、拖拽组件）到
`vendor/`，无需任何手动 pip install。**

## 打包成 EXE（可选）

```bash
python build_exe.py
```

- 产物：`dist/privacy_audit_tool.exe`（单文件，~45 MB，无需安装 Python 即可运行）
- PyInstaller 缺失时自动安装到 `vendor/`，同样零手工依赖
- exe 首次运行会在**自身所在目录**生成 `bin/`（frida-server 缓存）、`reports/`（报告）
  等运行目录——拷走单个 exe 即可便携分发

## 检测项（14 类，数据驱动，可扩展）

| 分类 | 监测点 |
|---|---|
| 设备标识 | IMEI/MEID/DeviceId/IMSI/SimSerial/本机号码/AndroidId/SystemProperties(serial 等) |
| MAC 地址 | NetworkInterface / WifiInfo |
| 传感器 | SensorManager.getSensorList / getDefaultSensor |
| 位置 | LocationManager（最后位置/持续定位/Provider） |
| 应用列表 | PackageManager 查询族 / UsageStatsManager（查询自身包名自动豁免） |
| 剪切板 | ClipboardManager 读取 |
| 网络信息 | SSID/BSSID/DHCP/网络状态 |
| 用户账户 | AccountManager |
| 通讯录 / 短信 / 通话记录 / 媒体库 | ContentResolver.query 按 URI 权限归类 |
| 运行中应用 | ActivityManager |

## 判定口径（与应用商店一致）

- **未同意阶段命中任何 API = ❌ 违规风险**；同意后命中仅记录（合规）
- 命中自动按堆栈归属责任 SDK（内置 Firebase/支付宝/百度/EMAS/人脸核身等 17 条规则，编辑
  `SDK_PREFIXES` 可扩展）
- 崩溃链路测试（`am crash` 定点崩溃主进程）：商店沙箱网络受限常诱发未捕获错误 →
  错误上报触发设备信息采集，这是最常见的送审命中路径

## 已知限制

- hook 通常在启动后 0.3s 内挂载，进程诞生最初 0.3s 内的调用可能漏采（崩溃链路测试可兜底）
- 基于 Java 层 hook，native 层直接 syscall 的采集不在覆盖范围
- frida-server 首次按设备 ABI 自动下载（GitHub 直连 + 双镜像回退），缓存于 `bin/`

## 目录

```
privacy_audit_tool/
├── privacy_audit_gui.py   # 工具本体（单文件）
├── build_exe.py           # 一键打包 EXE 脚本
├── README.md
├── settings.json          # 检测参数（时长/崩溃链路/复测）
├── vendor/                # 依赖（自动安装，git 忽略）
├── bin/                   # frida-server 缓存（git 忽略）
├── dist/                  # EXE 打包产物（git 忽略）
└── reports/               # 报告输出（git 忽略）
```

## 本工具的实际战绩

2026-10 小米送审命中"同意前读取传感器列表"：本工具完整复现了
`Firebase Crashlytics 20.1.1 → getProximitySensorEnabled → getDefaultSensor(8) → getSensorList`
调用链（与小米报告混淆堆栈经 R8 mapping 还原后逐帧一致），并验证修复方案
（延迟初始化 Firebase）后回归通过。
