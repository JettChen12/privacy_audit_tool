#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
隐私合规检测工具（GUI）

对标商业隐私合规检测（如史宾格）：在用户同意隐私协议之前，全量监测 App 的
敏感行为调用（设备标识/位置/应用列表/传感器/剪切板/网络/账户/内容数据等 14 类），
输出违规结论与调用堆栈归属。

流程：环境就绪(设备/root/frida) -> 拖入 APK -> 静置监测 -> 崩溃链路监测
      -> (交互)同意 -> 同意后对照 -> 结论报告。

零手工依赖：frida / tkinterdnd2 首次启动自动安装到本工具目录下的 vendor/。
运行：python privacy_audit_gui.py
"""

import ctypes
import datetime
import glob
import json
import lzma
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

TOOL_DIR = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) \
    else Path(__file__).resolve().parent
REPORT_DIR = TOOL_DIR / "reports"
SETTINGS_FILE = TOOL_DIR / "settings.json"
FRIDA_SERVER_CACHE = TOOL_DIR / "bin"
VENDOR_DIR = TOOL_DIR / "vendor"

# PyInstaller --windowed 打包后无控制台，print 到 None 句柄会抛异常
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w', encoding='utf-8')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w', encoding='utf-8')
FRIDA_VERSION = "16.7.19"

COMMON_ADB_PORTS = [5555, 16384, 16416, 7555, 21503, 62001, 5554]
FRIDA_FORWARD_PORT = 27042
APP_VERSION = "2.0"

# 检测项分类（与 HOOK_SCRIPT 中的分类一致，用于 UI 徽标统计）
CATEGORIES = ['设备标识', 'MAC地址', '传感器', '位置', '应用列表', '剪切板',
              '网络信息', '用户账户', '通讯录', '短信', '通话记录', '媒体库',
              '运行中应用', '系统属性']


# ---------------------------------------------------------------------------
# 依赖自举：frida / tkinterdnd2 缺失时自动安装到 tools/vendor，用户无感
# ---------------------------------------------------------------------------
def _ensure_deps():
    missing = []
    for mod in ('frida', 'tkinterdnd2'):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if not missing:
        return True
    if getattr(sys, 'frozen', False):
        # 打包版依赖已内嵌进 exe，缺失说明打包配置有误；exe 环境下也无法 pip
        print('[引导] 打包版依赖缺失: ' + ', '.join(missing))
        return False
    if str(VENDOR_DIR) not in sys.path and VENDOR_DIR.exists():
        sys.path.insert(0, str(VENDOR_DIR))
        for mod in missing:
            try:
                __import__(mod)
                missing.remove(mod)
            except ImportError:
                pass
    if missing and VENDOR_DIR != '':
        pkgs = {'frida': f'frida=={FRIDA_VERSION}', 'tkinterdnd2': 'tkinterdnd2'}
        need = [pkgs[m] for m in missing]
        print(f'[引导] 首次运行，自动安装依赖: {need} -> {VENDOR_DIR}')
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        r = subprocess.run([sys.executable, '-m', 'pip', 'install', '-q',
                            '-i', 'https://pypi.tuna.tsinghua.edu.cn/simple',
                            '--target', str(VENDOR_DIR), *need],
                           capture_output=True, text=True, timeout=600,
                           creationflags=flags)
        if r.returncode != 0:
            print('[引导] 自动安装失败：' + (r.stderr or '')[:500])
            return False
        if str(VENDOR_DIR) not in sys.path:
            sys.path.insert(0, str(VENDOR_DIR))
        import importlib
        importlib.invalidate_caches()
        for m in list(missing):
            try:
                __import__(m)
                missing.remove(m)
            except ImportError:
                pass
    return not missing


HAVE_DND = False
try:
    if _ensure_deps():
        from tkinterdnd2 import DND_FILES, TkinterDnD
        HAVE_DND = True
except Exception:
    pass

# ---------------------------------------------------------------------------
# 内嵌 hook 脚本：全量敏感行为监测（数据驱动注册表）
# ---------------------------------------------------------------------------
HOOK_SCRIPT = r"""
function report(cat, api, detail) {
  var Log = Java.use('android.util.Log');
  var stack = Log.getStackTraceString(Java.use('java.lang.Exception').$new());
  send({ kind: 'hit', cat: cat, api: api, detail: detail ? String(detail) : '', stack: stack });
}

var hooked = 0;
var OWN_PKG = '';
function ownPackage() {
  if (OWN_PKG) return OWN_PKG;
  try {
    OWN_PKG = String(Java.use('android.app.ActivityThread').currentApplication().getPackageName());
  } catch (e) {}
  return OWN_PKG;
}

function hookMethod(cat, cls, method, skipSelf) {
  try {
    var C = Java.use(cls);
    if (!C[method]) return;
    C[method].overloads.forEach(function (ov) {
      ov.implementation = function () {
        var d = '';
        try {
          for (var i = 0; i < arguments.length; i++) {
            var a = arguments[i];
            if (a !== null && a !== undefined && typeof a !== 'object') { d = String(a); break; }
          }
        } catch (e) {}
        // 查询自身包信息不算"收集应用列表"（与商业检测工具口径一致）
        if (!(skipSelf && d && d === ownPackage())) {
          report(cat, cls.split('.').pop() + '.' + method, d);
        }
        return ov.apply(this, arguments);
      };
    });
    hooked++;
  } catch (e) { /* 类未加载等，忽略 */ }
}

Java.perform(function () {
  // [分类, 类, 方法数组]
  var TABLE = [
    ['设备标识', 'android.telephony.TelephonyManager',
     ['getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getSimSerialNumber',
      'getLine1Number', 'getGroupId1', 'getDeviceSoftwareVersion']],
    ['MAC地址', 'java.net.NetworkInterface', ['getHardwareAddress']],
    ['MAC地址', 'android.net.wifi.WifiInfo', ['getMacAddress']],
    ['传感器', 'android.hardware.SystemSensorManager', ['getSensorList']],
    ['传感器', 'android.hardware.SensorManager', ['getDefaultSensor']],
    ['位置', 'android.location.LocationManager',
     ['getLastKnownLocation', 'requestLocationUpdates', 'getBestProvider', 'getProviders']],
    ['应用列表', 'android.app.ApplicationPackageManager',
     ['getInstalledPackages', 'getInstalledApplications', 'getPackageInfo',
      'queryIntentActivities', 'queryIntentServices', 'getApplicationInfo']],
    ['应用列表', 'android.app.PackageManager',
     ['getInstalledPackages', 'getInstalledApplications']],
    ['应用列表', 'android.app.usage.UsageStatsManager', ['queryEvents', 'queryAndAggregateUsageStats']],
    ['剪切板', 'android.content.ClipboardManager', ['getPrimaryClip', 'getPrimaryClipDescription']],
    ['网络信息', 'android.net.wifi.WifiInfo', ['getSSID', 'getBSSID']],
    ['网络信息', 'android.net.wifi.WifiManager', ['getConnectionInfo', 'getDhcpInfo']],
    ['网络信息', 'android.net.ConnectivityManager', ['getActiveNetworkInfo', 'getAllNetworkInfo']],
    ['用户账户', 'android.accounts.AccountManager', ['getAccounts', 'getAccountsByType']],
    ['运行中应用', 'android.app.ActivityManager', ['getRunningAppProcesses', 'getRunningTasks']],
  ];
  for (var i = 0; i < TABLE.length; i++) {
    var skipSelf = TABLE[i][0] === '应用列表';
    for (var j = 0; j < TABLE[i][2].length; j++) {
      hookMethod(TABLE[i][0], TABLE[i][1], TABLE[i][2][j], skipSelf);
    }
  }

  // —— AndroidId ——
  try {
    var SS = Java.use('android.provider.Settings$Secure');
    SS.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation =
      function (cr, name) {
        var r = this.getString(cr, name);
        if (name && String(name).indexOf('android_id') >= 0) {
          report('设备标识', 'Settings.Secure.android_id', '');
        }
        return r;
      };
    hooked++;
  } catch (e) {}

  // —— 系统属性（过滤设备标识相关 key）——
  try {
    var SP = Java.use('android.os.SystemProperties');
    SP.get.overload('java.lang.String').implementation = function (key) {
      var k = String(key);
      if (/serial|imei|meid|gsm\.sn|device.?uid|wlan\.mac/i.test(k)) {
        report('系统属性', 'SystemProperties.get', k);
      }
      return this.get(key);
    };
    hooked++;
  } catch (e) {}

  // —— 内容数据：按 URI 权限归类（通讯录/短信/通话记录/媒体库）——
  try {
    var CR = Java.use('android.content.ContentResolver');
    CR.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
                      '[Ljava.lang.String;', 'java.lang.String').implementation =
      function (uri, proj, sel, args, ord) {
        try {
          var u = String(uri);
          if (/contacts/i.test(u)) report('通讯录', 'ContentResolver.query', u);
          else if (/sms|mms|telephony/i.test(u)) report('短信', 'ContentResolver.query', u);
          else if (/call_log/i.test(u)) report('通话记录', 'ContentResolver.query', u);
          else if (/media|external/i.test(u)) report('媒体库', 'ContentResolver.query', u);
        } catch (e) {}
        return this.query(uri, proj, sel, args, ord);
      };
    hooked++;
  } catch (e) {}

  console.log('[*] 敏感行为 hooks 挂载完成，共 ' + hooked + ' 处');
});
"""

# 已知 SDK 归属前缀表：把堆栈自动归类到责任方
SDK_PREFIXES = [
    ('com.google.firebase.crashlytics', 'Firebase Crashlytics'),
    ('com.google.firebase.sessions', 'Firebase Sessions'),
    ('com.google.firebase', 'Firebase'),
    ('com.google.android.gms', 'Google Play Services'),
    ('com.alipay.alipaysecuritysdk', '支付宝安全SDK'),
    ('com.alipay', '支付宝SDK'),
    ('com.baidu.location', '百度定位SDK'),
    ('com.baidu', '百度SDK'),
    ('com.dtf.face', '阿里云人脸核身'),
    ('com.alibaba.sdk.android.push', '阿里云EMAS推送'),
    ('com.ut.device', '阿里UT设备SDK'),
    ('com.alibaba', '阿里系SDK'),
    ('com.tencent', '腾讯系SDK'),
    ('androidx.media3', 'AndroidX media3'),
    ('io.flutter', 'Flutter引擎'),
    ('com.huawei', '华为系SDK'),
    ('com.xiaomi', '小米系SDK'),
    ('com.elequ', '宿主App'),
]


def attribute_sdk(stack_text):
    for prefix, name in SDK_PREFIXES:
        if prefix in stack_text:
            return name
    for line in stack_text.splitlines():
        m = re.search(r'at\s+([a-zA-Z][\w.]*)\.', line)
        if m:
            cls = m.group(1)
            if not cls.startswith(('android.', 'java.', 'javax.', 'com.android.')):
                return cls.split('.')[0] + '(未知SDK)'
    return '未知'


def find_adb():
    exe = shutil.which('adb')
    if exe:
        return exe
    candidates = []
    sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if sdk:
        candidates.append(Path(sdk) / 'platform-tools' / 'adb.exe')
    local = os.environ.get('LOCALAPPDATA')
    if local:
        candidates.append(Path(local) / 'Android' / 'Sdk' / 'platform-tools' / 'adb.exe')
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def find_aapt():
    for name in ('aapt', 'aapt2'):
        exe = shutil.which(name)
        if exe:
            return exe
    local = os.environ.get('LOCALAPPDATA')
    if local:
        p = Path(local) / 'Android' / 'Sdk' / 'build-tools'
        if p.exists():
            exes = sorted(glob.glob(str(p / '*' / 'aapt.exe')), reverse=True)
            if exes:
                return exes[0]
    return None


def run_cmd(args, timeout=60, check=True, quiet=False):
    """执行外部命令，统一 utf-8 容错解码"""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=timeout)
        out = (r.stdout or '').strip()
        err = (r.stderr or '').strip()
        if check and r.returncode != 0:
            raise RuntimeError(f"命令失败({' '.join(map(str, args[:4]))}…): {err or out or r.returncode}")
        return out if quiet else (out + ('\n' + err if err else ''))
    except FileNotFoundError:
        raise RuntimeError(f'找不到可执行文件: {args[0]}')
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'命令超时: {" ".join(map(str, args[:4]))}…')


# ---------------------------------------------------------------------------
# 环境巡检：GUI 轮询与引擎共用
# ---------------------------------------------------------------------------
class EnvState:
    def __init__(self):
        self.adb = None
        self.device = None
        self.root = False
        self.abi = None
        self.frida_module = False
        self.detail = {}

    @property
    def ready(self):
        return self.adb and self.device and self.root and self.frida_module

    def message(self):
        if not self.adb:
            return '未找到 adb（需安装 Android platform-tools）'
        if not self.frida_module:
            return 'frida 模块不可用'
        if not self.device:
            return '未发现设备：请启动模拟器（开启 root）或连接真机'
        if not self.root:
            return '设备未 root：MuMu 请在系统设置中开启 Root 权限'
        return None  # 就绪


def probe_env(connect_ports=True):
    st = EnvState()
    st.adb = find_adb()
    try:
        import frida  # noqa
        st.frida_module = True
    except ImportError:
        st.frida_module = False
    if not st.adb:
        return st
    try:
        out = run_cmd([st.adb, 'devices'], check=False)
        serial = None
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == 'device':
                serial = parts[0]
                break
        if not serial and connect_ports:
            for port in COMMON_ADB_PORTS:
                run_cmd([st.adb, 'connect', f'127.0.0.1:{port}'], check=False, quiet=True)
                out = run_cmd([st.adb, 'devices'], check=False)
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == 'device':
                        serial = parts[0]
                        break
                if serial:
                    break
        if serial:
            st.device = serial
            out = run_cmd([st.adb, '-s', serial, 'shell', 'su -c id'], check=False, quiet=True)
            st.root = 'uid=0' in out
            st.abi = run_cmd([st.adb, '-s', serial, 'shell', 'getprop ro.product.cpu.abi'],
                             check=False, quiet=True).strip() or None
    except Exception:
        pass
    return st


# ---------------------------------------------------------------------------
# 审计引擎（后台线程）
# ---------------------------------------------------------------------------
class EngineStop(Exception):
    pass


class AuditEngine:
    """UI 通信经由队列：
    ('log', level, text) ('phase', idx, state) ('progress', pct, text)
    ('hit', dict) ('done', summary) ('error', text) ('consent_prompt',)
    """

    PHASES = ['环境自检', '安装应用', '静置监测', '崩溃链路', '同意后对照', '结论']

    def __init__(self, cfg, q, env):
        self.cfg = cfg
        self.q = q
        self.env = env          # 就绪的 EnvState（启动前已由 UI 校验）
        self.stop_event = threading.Event()
        self.consent_event = threading.Event()
        self.consent_skip = False
        self.hits = []
        self._frida_dev = None
        self._current_phase_label = ''

    # ---- 基础 ----
    def log(self, level, text):
        self.q.put(('log', level, text))

    def phase(self, idx, state):
        self.q.put(('phase', idx, state))

    def progress(self, pct, text):
        self.q.put(('progress', pct, text))

    def check_stop(self):
        if self.stop_event.is_set():
            raise EngineStop()

    def adb(self, *args, **kw):
        return run_cmd([self.env.adb, '-s', self.env.device, *args], **kw)

    def adb_shell(self, cmd, **kw):
        return self.adb('shell', cmd, **kw)

    def su(self, cmd, **kw):
        return self.adb_shell(f"su -c '{cmd}'", **kw)

    # ---- 主流程 ----
    def run(self):
        try:
            self._step_env()
            self._step_install()
            self._step_capture_pre()
            self._step_crash_pre()
            self._step_post_consent()
            summary = self._build_summary()
            self.phase(5, 'done')
            self.progress(100, '检测完成')
            self.q.put(('done', summary))
        except EngineStop:
            self.log('WARN', '用户停止，检测中断')
            self.q.put(('done', self._build_summary(interrupted=True)))
        except Exception as e:
            self.log('ERR', f'检测失败: {e}')
            self.log('ERR', traceback.format_exc(limit=3))
            self.q.put(('error', str(e)))

    def _step_env(self):
        self.phase(0, 'running')
        self.progress(2, '复核环境…')
        adb, device = self.env.adb, self.env.device
        self.log('OK', f'adb: {adb}')
        self.log('OK', f'设备: {device}  ABI: {self.env.abi}')
        if not self.env.root:
            raise RuntimeError('设备 root 失效，请重新开启')
        import frida
        self.log('OK', f'frida 模块: {frida.__version__}')
        self._ensure_frida_server(frida.__version__)
        dm = frida.get_device_manager()
        self._frida_dev = dm.add_remote_device(f'127.0.0.1:{FRIDA_FORWARD_PORT}')
        n = len(self._frida_dev.enumerate_processes())
        self.log('OK', f'frida-server 连接正常（可见 {n} 个进程）')
        self.phase(0, 'done')

    def _ensure_frida_server(self, fver):
        self.progress(8, '部署 frida-server…')
        abi = self.env.abi or 'x86_64'
        arch = 'arm64' if 'arm64' in abi else ('x86_64' if 'x86_64' in abi else
                                               ('x86' if abi.startswith('x86') else 'arm'))
        local = FRIDA_SERVER_CACHE / f'frida-server-{fver}-{arch}'
        if not local.exists():
            local = self._download_frida_server(fver, arch, local)
        dev_path = f'/data/local/tmp/fs-{fver}-{arch}'
        exists = self.su(f'ls {dev_path}', check=False, quiet=True)
        if 'No such file' in exists or not exists:
            self.log('INFO', '推送 frida-server 到设备…')
            self.adb('push', str(local), dev_path, timeout=180)
            self.su(f'chmod 755 {dev_path}', check=False)
        running = self.su(f'ps -A | grep fs-{fver}-{arch}', check=False, quiet=True)
        if f'fs-{fver}-{arch}' not in running:
            self.log('INFO', '启动 frida-server…')
            self.su(f'nohup {dev_path} >/dev/null 2>&1 &', check=False)
            time.sleep(1.5)
        self.adb('forward', f'tcp:{FRIDA_FORWARD_PORT}', f'tcp:{FRIDA_FORWARD_PORT}', check=False)

    def _download_frida_server(self, fver, arch, dest):
        FRIDA_SERVER_CACHE.mkdir(parents=True, exist_ok=True)
        fname = f'frida-server-{fver}-android-{arch}'
        urls = [
            f'https://github.com/frida/frida/releases/download/{fver}/{fname}.xz',
            f'https://ghproxy.cn/https://github.com/frida/frida/releases/download/{fver}/{fname}.xz',
            f'https://gh-proxy.com/https://github.com/frida/frida/releases/download/{fver}/{fname}.xz',
        ]
        xz_path = dest.with_suffix('.xz')
        last_err = None
        for url in urls:
            try:
                self.log('INFO', f'下载 {url} …')

                def hook(cnt, block, total):
                    if total > 0 and cnt % 200 == 0:
                        self.progress(12, f'下载 frida-server {cnt*block//1024//1024}/{total//1024//1024} MB')

                urllib.request.urlretrieve(url, xz_path, reporthook=hook)
                with lzma.open(xz_path) as fin, open(dest, 'wb') as fout:
                    shutil.copyfileobj(fin, fout)
                xz_path.unlink(missing_ok=True)
                self.log('OK', f'frida-server 已就绪: {dest.name}')
                return dest
            except Exception as e:
                last_err = e
                self.log('WARN', f'下载失败，尝试下一个源…')
        raise RuntimeError(f'frida-server 下载失败：{last_err}\n'
                           f'请手动下载 {fname}.xz 解压后放到 {FRIDA_SERVER_CACHE}')

    def _step_install(self):
        self.phase(1, 'running')
        cfg = self.cfg
        self.progress(20, '解析包名…')
        pkg = (cfg['package'] or '').strip()
        if not pkg:
            aapt = find_aapt()
            if aapt:
                out = run_cmd([aapt, 'dump', 'badging', cfg['apk']], check=False, quiet=True)
                m = re.search(r"package:\s*name='([^']+)'", out)
                if m:
                    pkg = m.group(1)
        if not pkg:
            raise RuntimeError('无法识别包名：请安装 Android build-tools(aapt) 或在开始前填写包名')
        self.pkg = pkg
        self.log('OK', f'包名: {pkg}')
        self.progress(28, f'卸载旧包 {pkg}…')
        self.adb('uninstall', pkg, check=False, quiet=True)
        self.progress(35, '安装 APK…')
        out = self.adb('install', cfg['apk'], timeout=600)
        self.log('OK', 'APK 安装完成' if 'Success' in out else f'安装输出: {out[:200]}')
        self.progress(45, '清除应用数据（重置首启状态）…')
        self.adb_shell(f'pm clear {pkg}', check=False, quiet=True)
        self.phase(1, 'done')

    # ---- hook / 采集 ----
    def _launch_and_attach(self, phase_label):
        self.log('INFO', '启动应用…')
        self.adb_shell(f'monkey -p {self.pkg} -c android.intent.category.LAUNCHER 1',
                       check=False, quiet=True)
        t0 = time.time()
        while time.time() - t0 < 25:
            self.check_stop()
            out = self.adb_shell(f'pidof {self.pkg}', check=False, quiet=True, timeout=5)
            pid_str = (out or '').strip().split()
            if pid_str:
                pid = int(pid_str[0])
                try:
                    session = self._frida_dev.attach(pid)
                    script = session.create_script(HOOK_SCRIPT)
                    script.on('message', self._on_frida_message)
                    script.load()
                    self.log('OK', f'{phase_label}: 已附加并挂载 hooks (pid={pid}, '
                                   f'启动后 {time.time()-t0:.2f}s)')
                    return session, pid
                except Exception as e:
                    self.log('WARN', f'attach 失败重试: {e}')
                    time.sleep(0.15)
            else:
                time.sleep(0.06)
        raise RuntimeError('无法附加到应用进程（应用可能启动失败，查看设备屏幕）')

    def _on_frida_message(self, message, data):
        if message.get('type') == 'send':
            payload = message.get('payload') or {}
            if payload.get('kind') == 'hit':
                hit = {
                    'time': datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'phase': self._current_phase_label,
                    'cat': payload.get('cat', '其他'),
                    'api': payload.get('api', '?'),
                    'detail': (payload.get('detail') or '')[:120],
                    'stack': payload.get('stack', ''),
                    'sdk': attribute_sdk(payload.get('stack', '')),
                }
                self.hits.append(hit)
                self.q.put(('hit', hit))
        elif message.get('type') == 'log':
            self.log('INFO', str(message.get('payload')))
        elif message.get('type') == 'error':
            self.log('ERR', f'hook 脚本错误: {message.get("description")}')

    def _wait_capture(self, session, duration, base_pct, span_pct):
        t0 = time.time()
        while time.time() - t0 < duration:
            self.check_stop()
            time.sleep(0.2)
            el = time.time() - t0
            self.progress(base_pct + span_pct * el / duration,
                          f'{self._current_phase_label} 剩余 {int(duration-el)}s')
        try:
            session.detach()
        except Exception:
            pass

    def _crash_target(self, session, pid):
        self.log('INFO', f'注入崩溃 am crash {pid}（验证崩溃上报链路）…')
        self.adb_shell(f'am crash {pid}', check=False, quiet=True)
        t0 = time.time()
        while time.time() - t0 < 8:
            self.check_stop()
            time.sleep(0.2)
        try:
            session.detach()
        except Exception:
            pass
        out = self.adb_shell(f'pidof {self.pkg}', check=False, quiet=True, timeout=5)
        pids = [int(x) for x in (out or '').split()]
        if pid in pids:
            self.log('WARN', f'崩溃注入未生效（pid={pid} 仍存活），结果可能不完整')
        elif pids:
            self.log('INFO', f'主进程已崩溃（系统自动重启，新 pid={pids[0]}）')
        else:
            self.log('INFO', '主进程已崩溃')

    def _step_capture_pre(self):
        self._current_phase_label = '静置·未同意'
        self.phase(2, 'running')
        session, pid = self._launch_and_attach('静置·未同意')
        self._wait_capture(session, self.cfg['duration'], 50, 22)
        self.phase(2, 'done')

    def _step_crash_pre(self):
        if not self.cfg['crash_test']:
            self.phase(3, 'skip')
            return
        self._current_phase_label = '崩溃·未同意'
        self.phase(3, 'running')
        session, pid = self._launch_and_attach('崩溃·未同意')
        time.sleep(1)
        self._crash_target(session, pid)
        self.phase(3, 'done')

    def _step_post_consent(self):
        if not self.cfg['post_test']:
            self.phase(4, 'skip')
            return
        self._current_phase_label = '对照·已同意'
        self.q.put(('consent_prompt',))
        self.log('INFO', '等待用户在设备上点击"同意"…')
        while not self.consent_event.wait(timeout=0.2):
            self.check_stop()
            if self.consent_skip:
                self.log('INFO', '已跳过同意后对照')
                self.phase(4, 'skip')
                return
        self.phase(4, 'running')
        # 强停重拉：保证同意后的初始化发生在已挂 hook 的新进程里
        self.adb_shell(f'am force-stop {self.pkg}', check=False, quiet=True)
        time.sleep(1)
        session, pid = self._launch_and_attach('对照·已同意')
        self._wait_capture(session, min(self.cfg['duration'], 20), 78, 8)
        if self.cfg['crash_test']:
            session, pid = self._launch_and_attach('对照·已同意')
            time.sleep(1)
            self._crash_target(session, pid)
        self.phase(4, 'done')

    def _build_summary(self, interrupted=False):
        pre = [h for h in self.hits if '未同意' in h['phase']]
        post = [h for h in self.hits if '已同意' in h['phase']]
        cats = {}
        for h in pre:
            cats[h['cat']] = cats.get(h['cat'], 0) + 1
        if interrupted:
            verdict = '⚠ 检测被中断，结果不完整'
        elif pre:
            verdict = f'❌ 发现 {len(pre)} 处"同意前"敏感行为（涉及 {len(cats)} 类）'
        else:
            verdict = '✅ 未发现"同意前"敏感行为'
        return {'verdict': verdict, 'pre_hits': pre, 'post_hits': post,
                'pre_cats': cats, 'interrupted': interrupted,
                'apk': self.cfg['apk'], 'package': getattr(self, 'pkg', self.cfg['package'] or '-'),
                'device': self.env.device, 'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    def build_report_text(self, s):
        lines = ['隐私合规检测报告', '=' * 64, f"结论: {s['verdict']}", f"时间: {s['time']}",
                 f"APK: {s['apk']}", f"包名: {s['package']}", f"设备: {s['device']}",
                 f"工具: privacy_audit_gui v{APP_VERSION}", '',
                 f"— 未同意阶段命中 {len(s['pre_hits'])} 处 —"]
        bycat = {}
        for h in s['pre_hits']:
            bycat.setdefault(h['cat'], []).append(h)
        for cat, hits in bycat.items():
            lines.append(f'【{cat}】{len(hits)} 处')
            for h in hits:
                lines.append(f"  [{h['time']}] {h['api']} {h['detail']}  (归属: {h['sdk']})")
                for ln in h['stack'].splitlines()[:14]:
                    lines.append(f'      {ln}')
            lines.append('-' * 56)
        lines.append('')
        lines.append(f"— 同意后阶段命中 {len(s['post_hits'])} 处（合规，供参考）—")
        for h in s['post_hits']:
            lines.append(f"  [{h['time']}] {h['api']} {h['detail']}  (归属: {h['sdk']})")
        lines.append('')
        lines.append('口径: 与应用商店(164号文)送检一致——"未同意"阶段命中即视为合规风险。')
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# GUI：向导式暗色界面
# ---------------------------------------------------------------------------
C_BG = '#131519'
C_CARD = '#1b1e24'
C_CARD2 = '#22262e'
C_LINE = '#2c313a'
C_TEXT = '#e9eaee'
C_MUTED = '#8b919d'
C_ACCENT = '#5b8cff'
C_ACCENT_D = '#3a5fb8'
C_OK = '#37c46b'
C_ERR = '#ff5f57'
C_WARN = '#e0a83c'
C_HIT = '#ff9a4d'

FONT = ('Microsoft YaHei UI', 10)
FONT_S = ('Microsoft YaHei UI', 9)
FONT_B = ('Microsoft YaHei UI', 10, 'bold')
FONT_XL = ('Microsoft YaHei UI', 20, 'bold')
FONT_MONO = ('Cascadia Mono', 9)


class Chip(tk.Label):
    """状态芯片：圆角感的着色小标签"""
    def __init__(self, master, text='', fg=C_MUTED, bg=C_CARD2, font=FONT_S, **kw):
        super().__init__(master, text=text, fg=fg, bg=bg, font=font,
                         padx=10, pady=4, **kw)

    def set(self, text, fg=None, bg=None):
        self.configure(text=text, fg=fg or self.cget('fg'), bg=bg or self.cget('bg'))


class App(tk.Tk if not HAVE_DND else TkinterDnD.Tk):
    def __init__(self):
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
            self.tk.call('tk', 'scaling', 1.35)
        except Exception:
            pass
        super().__init__()
        self.title(f'隐私合规检测 v{APP_VERSION}')
        self.geometry('1080x760')
        self.minsize(940, 660)
        self.configure(bg=C_BG)
        self._setup_style()

        self.q = queue.Queue()
        self.engine = None
        self.hits_rows = []
        self.summary = None
        self.env = None
        self.filter_var = tk.StringVar(value='全部')
        self.status_var = tk.StringVar(value='空闲')
        self.prog_var = tk.DoubleVar(value=0)
        self.prog_text = tk.StringVar(value='')
        self.log_all = []

        self._build_ui()
        self._load_settings()
        self._start_env_poll()
        self.after(80, self._poll)
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    # ---- 样式 ----
    def _setup_style(self):
        s = ttk.Style(self)
        s.theme_use('clam')
        s.configure('.', background=C_BG, foreground=C_TEXT, font=FONT, bordercolor=C_LINE)
        s.configure('TFrame', background=C_BG)
        s.configure('Card.TFrame', background=C_CARD)
        s.configure('TLabel', background=C_BG, foreground=C_TEXT)
        s.configure('Card.TLabel', background=C_CARD, foreground=C_TEXT)
        s.configure('Muted.TLabel', background=C_CARD, foreground=C_MUTED, font=FONT_S)
        s.configure('H1.TLabel', background=C_BG, foreground=C_TEXT,
                    font=('Microsoft YaHei UI', 14, 'bold'))
        s.configure('TEntry', fieldbackground=C_CARD2, foreground=C_TEXT,
                    insertcolor=C_TEXT, bordercolor=C_LINE)
        s.configure('TSpinbox', fieldbackground=C_CARD2, foreground=C_TEXT,
                    arrowcolor=C_TEXT, bordercolor=C_LINE)
        s.configure('TCheckbutton', background=C_CARD, foreground=C_TEXT,
                    focuscolor=C_CARD, font=FONT_S)
        s.map('TCheckbutton', background=[('active', C_CARD)])
        s.configure('TButton', background=C_CARD2, foreground=C_TEXT,
                    bordercolor=C_LINE, focusthickness=0, padding=(12, 5))
        s.map('TButton', background=[('active', '#2e333d'), ('disabled', '#25282f')],
              foreground=[('disabled', '#5d636e')])
        s.configure('Accent.TButton', background=C_ACCENT, foreground='white', font=FONT_B)
        s.map('Accent.TButton', background=[('active', '#78a0ff'), ('disabled', C_ACCENT_D)])
        s.configure('Danger.TButton', background='#7e3b3b', foreground='white')
        s.map('Danger.TButton', background=[('active', '#964a4a'), ('disabled', '#453030')])
        s.configure('Horizontal.TProgressbar', background=C_ACCENT, troughcolor=C_CARD2,
                    bordercolor=C_LINE, lightcolor=C_ACCENT)
        s.configure('Treeview', background=C_CARD, foreground=C_TEXT, fieldbackground=C_CARD,
                    bordercolor=C_LINE, rowheight=26, font=FONT_S)
        s.configure('Treeview.Heading', background=C_CARD2, foreground=C_TEXT,
                    font=('Microsoft YaHei UI', 9, 'bold'), relief='flat')
        s.map('Treeview', background=[('selected', '#2f4c7e')], foreground=[('selected', '#fff')])
        s.configure('Vertical.TScrollbar', background=C_CARD2, troughcolor=C_BG,
                    bordercolor=C_BG, arrowcolor=C_MUTED)

    # ---- 界面 ----
    def _build_ui(self):
        # 顶栏
        header = ttk.Frame(self, padding=(20, 14, 20, 8))
        header.pack(fill='x')
        ttk.Label(header, text='隐私合规检测', style='H1.TLabel').pack(side='left')
        ttk.Label(header, text='  同意隐私协议前的敏感行为全量监测',
                  foreground=C_MUTED, background=C_BG, font=FONT_S).pack(side='left', pady=(6, 0))
        self.status_chip = Chip(header, '● 空闲', fg=C_MUTED, bg=C_CARD2, font=FONT_B)
        self.status_chip.pack(side='right')

        # 环境就绪卡（始终可见）
        envcard = ttk.Frame(self, style='Card.TFrame', padding=(16, 10))
        envcard.pack(fill='x', padx=20, pady=(0, 10))
        ttk.Label(envcard, text='环境状态', style='Card.TLabel', font=FONT_B)\
            .pack(side='left')
        ttk.Label(envcard, text='  自动检测，就绪后即可投放 APK', style='Muted.TLabel')\
            .pack(side='left')
        self.env_hint = ttk.Label(envcard, text='', style='Muted.TLabel', foreground=C_ERR)
        self.env_hint.pack(side='right')
        chips = ttk.Frame(envcard, style='Card.TFrame')
        chips.pack(side='right', padx=(0, 16))
        self.chip_adb = Chip(chips, '… ADB')
        self.chip_dev = Chip(chips, '… 设备')
        self.chip_root = Chip(chips, '… Root')
        self.chip_frida = Chip(chips, '… Frida')
        for c in (self.chip_adb, self.chip_dev, self.chip_root, self.chip_frida):
            c.pack(side='left', padx=(6, 0))

        # 内容区
        self.content = ttk.Frame(self)
        self.content.pack(fill='both', expand=True, padx=20)
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(0, weight=1)

        # —— 视图1：投放页 ——
        self.view_idle = ttk.Frame(self.content, style='Card.TFrame')
        self.view_idle.grid(row=0, column=0, sticky='nsew')
        self.view_idle.columnconfigure(0, weight=1)
        self.view_idle.rowconfigure(1, weight=1)

        toprow = ttk.Frame(self.view_idle, style='Card.TFrame')
        toprow.grid(row=0, column=0, sticky='ew', pady=(6, 0))
        self.apk_state_label = ttk.Label(toprow, text='', style='Card.TLabel', font=FONT)
        self.apk_state_label.pack(side='left')
        self.btn_remove_apk = ttk.Button(toprow, text='移除', width=6,
                                         command=self._remove_apk)
        self.btn_remove_apk.pack(side='right')

        # 投放区 / APK 信息卡 二选一
        self.dropzone = tk.Frame(self.view_idle, bg=C_CARD2,
                                 highlightbackground=C_LINE, highlightthickness=2)
        self.dropzone.grid(row=1, column=0, sticky='nsew', pady=(10, 4), padx=60)
        self.dropzone.columnconfigure(0, weight=1)
        self.dropzone.rowconfigure((0, 1, 2), weight=0)
        self.dropzone.rowconfigure(3, weight=1)
        tk.Label(self.dropzone, text='⬇', font=('Microsoft YaHei UI', 26),
                 bg=C_CARD2, fg=C_MUTED).grid(row=0, column=0, pady=(60, 4))
        self.dz_title = tk.Label(self.dropzone, text='将 APK 拖到此处',
                                 font=FONT_XL, bg=C_CARD2, fg=C_TEXT)
        self.dz_title.grid(row=1, column=0, pady=2)
        self.dz_sub = tk.Label(self.dropzone, text='或点击此处选择文件',
                               font=FONT_S, bg=C_CARD2, fg=C_MUTED)
        self.dz_sub.grid(row=2, column=0, pady=(4, 60))
        for w in (self.dropzone, self.dz_title, self.dz_sub):
            w.bind('<Button-1>', lambda e: self._pick_apk())
        if HAVE_DND:
            self.dropzone.drop_target_register(DND_FILES)
            self.dropzone.dnd_bind('<<Drop>>', self._on_drop)
            self.bind('<Escape>', lambda e: None)

        # 开始区
        actrow = ttk.Frame(self.view_idle, style='Card.TFrame')
        actrow.grid(row=2, column=0, sticky='ew', pady=(4, 8))
        adv = ttk.Frame(actrow, style='Card.TFrame')
        adv.pack(side='left')
        ttk.Label(adv, text='静置时长', style='Card.TLabel', font=FONT_S).pack(side='left')
        self.dur_var = tk.IntVar(value=60)
        ttk.Spinbox(adv, from_=10, to=600, increment=10, textvariable=self.dur_var,
                    width=6, font=FONT_S).pack(side='left', padx=(4, 14))
        self.crash_var = tk.BooleanVar(value=True)
        self.post_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(adv, text='崩溃链路测试', variable=self.crash_var).pack(side='left')
        ttk.Checkbutton(adv, text='同意后对照', variable=self.post_var).pack(side='left', padx=(10, 0))
        self.btn_start = ttk.Button(actrow, text='开 始 检 测', style='Accent.TButton',
                                    command=self._start, state='disabled')
        self.btn_start.pack(side='right', ipady=4, ipadx=10)

        self.apk_var = tk.StringVar()
        self.pkg_var = tk.StringVar()

        # —— 视图2：运行/结果页 ——
        self.view_run = ttk.Frame(self.content, style='Card.TFrame')
        # 结果横幅
        self.banner = tk.Label(self.view_run, text='', font=('Microsoft YaHei UI', 13, 'bold'),
                               bg=C_CARD, fg=C_TEXT, anchor='w', padx=14, pady=10)
        self.banner.pack(fill='x')
        # 阶段步进器
        stepper = ttk.Frame(self.view_run, style='Card.TFrame', padding=(12, 8))
        stepper.pack(fill='x')
        self.step_vars, self.step_labels = [], []
        for name in AuditEngine.PHASES:
            v = tk.StringVar(value=name)
            self.step_vars.append(v)
            lbl = tk.Label(stepper, textvariable=v, bg=C_CARD, fg=C_MUTED, font=FONT_S,
                           padx=10, pady=4)
            lbl.pack(side='left', padx=(0, 4))
            self.step_labels.append(lbl)
        progwrap = ttk.Frame(self.view_run, style='Card.TFrame', padding=(12, 0, 12, 8))
        progwrap.pack(fill='x')
        self.progbar = ttk.Progressbar(progwrap, variable=self.prog_var, maximum=100)
        self.progbar.pack(fill='x')
        self.prog_label = ttk.Label(progwrap, textvariable=self.prog_text,
                                    style='Card.TLabel', font=FONT_S, foreground=C_MUTED)
        self.prog_label.pack(anchor='w', pady=(3, 0))
        # 分类徽标条
        self.catbar = ttk.Frame(self.view_run, style='Card.TFrame', padding=(12, 8))
        self.catbar.pack(fill='x')
        self.cat_chips = {}
        for cat in CATEGORIES:
            c = Chip(self.catbar, cat, fg=C_MUTED)
            c.pack(side='left', padx=(0, 5))
            self.cat_chips[cat] = c
        # 命中表
        treeholder = ttk.Frame(self.view_run, style='Card.TFrame', padding=(12, 4))
        treeholder.pack(fill='both', expand=True)
        treeholder.rowconfigure(0, weight=1)
        treeholder.columnconfigure(0, weight=1)
        cols = ('time', 'phase', 'cat', 'api', 'sdk', 'verdict')
        self.tree = ttk.Treeview(treeholder, columns=cols, show='headings', selectmode='browse')
        for cid, text, w in (('time', '时间', 86), ('phase', '阶段', 104), ('cat', '分类', 92),
                             ('api', 'API', 300), ('sdk', '归属SDK', 150), ('verdict', '判定', 76)):
            self.tree.heading(cid, text=text)
            self.tree.column(cid, width=w, anchor='w')
        self.tree.tag_configure('fail', foreground=C_ERR)
        self.tree.tag_configure('pass', foreground=C_OK)
        self.tree.grid(row=0, column=0, sticky='nsew')
        sb = ttk.Scrollbar(treeholder, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.grid(row=0, column=1, sticky='ns')
        self.tree.bind('<Double-1>', self._show_stack_popup)
        # 操作行
        actrow2 = ttk.Frame(self.view_run, style='Card.TFrame', padding=(12, 8))
        actrow2.pack(fill='x')
        self.btn_stop = ttk.Button(actrow2, text='停止', style='Danger.TButton',
                                   command=self._stop, state='disabled')
        self.btn_stop.pack(side='left')
        self.btn_export = ttk.Button(actrow2, text='导出报告', command=self._export,
                                     state='disabled')
        self.btn_export.pack(side='left', padx=(8, 0))
        self.btn_again = ttk.Button(actrow2, text='再次检测', command=self._reset_to_idle)
        self.btn_again.pack(side='right')

        self.view_idle.grid_propagate(True)
        self._show_view('idle')

        # —— 底部日志（可折叠） ——
        logwrap = ttk.Frame(self, padding=(20, 0, 20, 10))
        logwrap.pack(fill='x')
        bar = ttk.Frame(logwrap)
        bar.pack(fill='x', pady=(4, 3))
        self.log_toggle_btn = ttk.Button(bar, text='日志 ▾', width=8,
                                         command=self._toggle_log)
        self.log_toggle_btn.pack(side='left')
        self.filter_box = ttk.Combobox(bar, textvariable=self.filter_var,
                                       values=['全部', '仅命中', '仅错误'], width=8,
                                       state='readonly', font=FONT_S)
        self.filter_box.pack(side='left', padx=10)
        self.filter_box.bind('<<ComboboxSelected>>', lambda e: self._render_log())
        self.log_count = ttk.Label(bar, text='', foreground=C_MUTED, font=FONT_S)
        self.log_count.pack(side='left')
        ttk.Button(bar, text='清空', width=6, command=self._clear_log).pack(side='right')
        self.log_text = tk.Text(logwrap, bg='#101216', fg=C_TEXT, font=FONT_MONO,
                                relief='flat', height=8, state='disabled',
                                insertbackground=C_TEXT)
        self.log_open = True
        for tag, color in (('INFO', C_MUTED), ('OK', C_OK), ('WARN', C_WARN),
                           ('ERR', C_ERR), ('HIT', C_HIT)):
            self.log_text.tag_configure(tag, foreground=color)

    # ---- 视图切换 ----
    def _show_view(self, name):
        self.view_idle.grid_remove() if name != 'idle' else self.view_idle.grid()
        self.view_run.grid_remove() if name != 'run' else self.view_run.grid(
            row=0, column=0, sticky='nsew')

    def _toggle_log(self):
        self.log_open = not self.log_open
        self.log_toggle_btn.configure(text='日志 ▾' if self.log_open else '日志 ▸')
        if self.log_open:
            self.log_text.pack(fill='x')
        else:
            self.log_text.pack_forget()

    # ---- 环境轮询：worker 线程探测，结果入队由主循环消费（线程安全） ----
    def _start_env_poll(self):
        self.env_q = queue.Queue()

        def worker():
            while True:
                try:
                    st = probe_env()
                    self.env_q.put(st)
                except Exception:
                    pass
                time.sleep(4)
        threading.Thread(target=worker, daemon=True).start()

    def _apply_env(self, st):
        self.env = st
        ok = dict(fg=C_OK, bg='#1d2b22')
        bad = dict(fg=C_ERR, bg='#2b1d1d')
        pend = dict(fg=C_MUTED, bg=C_CARD2)
        self.chip_adb.set(('✓ ADB' if st.adb else '✗ ADB'), **(ok if st.adb else bad))
        self.chip_dev.set((f'✓ {st.device}' if st.device else '✗ 设备'),
                          **(ok if st.device else bad))
        self.chip_root.set(('✓ Root' if st.root else '✗ Root'),
                           **(ok if st.root else (bad if st.device else pend)))
        self.chip_frida.set(('✓ Frida' if st.frida_module else '✗ Frida'),
                            **(ok if st.frida_module else bad))
        msg = st.message() if not st.ready else '环境就绪，投放 APK 开始检测'
        self.env_hint.configure(text=msg, foreground=C_MUTED if st.ready else C_ERR)
        # 未就绪时投放区提示；就绪且无 APK 时高亮可投放
        if not st.ready:
            self.dz_title.configure(fg=C_MUTED)
            self.dz_sub.configure(text='等待环境就绪：' + (msg or ''))
        else:
            self.dz_title.configure(fg=C_TEXT)
            if not self.apk_var.get():
                self.dz_sub.configure(text='或点击此处选择文件')
        self._refresh_start_state()

    # ---- APK 拖拽/选择 ----
    def _on_drop(self, event):
        try:
            paths = self.tk.splitlist(event.data)
        except Exception:
            paths = [event.data.strip('{}')]
        for p in paths:
            if str(p).lower().endswith('.apk'):
                self._set_apk(str(p))
                return
        messagebox.showinfo('不支持的文件', '请拖入 .apk 文件')

    def _pick_apk(self):
        p = filedialog.askopenfilename(title='选择 APK', filetypes=[('APK', '*.apk')])
        if p:
            self._set_apk(p)

    def _set_apk(self, path):
        if not self.env or not self.env.ready:
            messagebox.showwarning('环境未就绪', '请先等待设备连接并开启 root（见上方环境状态）')
            return
        self.apk_var.set(path)
        size = Path(path).stat().st_size / 1024 / 1024
        pkg = self._guess_package(path)
        self.pkg_var.set(pkg)
        name = Path(path).name
        self.apk_state_label.configure(
            text=f'📦 {name}  ({size:.1f} MB)' + (f'  ·  {pkg}' if pkg else '  ·  包名将自动识别'))
        self.dropzone.grid_remove()
        self._refresh_start_state()
        self._log('OK', f'已载入 APK: {name} ({size:.1f} MB)')

    def _guess_package(self, path):
        aapt = find_aapt()
        if aapt:
            try:
                out = run_cmd([aapt, 'dump', 'badging', path], check=False, quiet=True)
                m = re.search(r"package:\s*name='([^']+)'", out)
                if m:
                    return m.group(1)
            except Exception:
                pass
        return ''

    def _remove_apk(self):
        self.apk_var.set('')
        self.pkg_var.set('')
        self.apk_state_label.configure(text='')
        self.dropzone.grid()
        self._refresh_start_state()

    def _refresh_start_state(self):
        ready = bool(self.env and self.env.ready and self.apk_var and self.apk_var.get())
        self.btn_start.configure(state='normal' if ready else 'disabled')

    # ---- 设置 ----
    def _load_settings(self):
        try:
            d = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
            self.dur_var.set(int(d.get('duration', 60)))
            self.crash_var.set(bool(d.get('crash', True)))
            self.post_var.set(bool(d.get('post', True)))
        except Exception:
            pass

    def _save_settings(self):
        try:
            SETTINGS_FILE.write_text(json.dumps({
                'duration': self.dur_var.get(), 'crash': self.crash_var.get(),
                'post': self.post_var.get()}, ensure_ascii=False), encoding='utf-8')
        except Exception:
            pass

    # ---- 启停 ----
    def _start(self):
        apk = self.apk_var.get()
        if not apk or not Path(apk).exists():
            messagebox.showerror('参数错误', '请先投放有效的 APK')
            return
        self._save_settings()
        # 复位
        for i, lbl in enumerate(self.step_labels):
            lbl.configure(fg=C_MUTED, bg=C_CARD)
            self.step_vars[i].set(AuditEngine.PHASES[i])
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.hits_rows.clear()
        for c in self.cat_chips.values():
            c.set(c.cget('text').split(' ')[0] if ' ' in c.cget('text') else c.cget('text'),
                  fg=C_MUTED, bg=C_CARD2)
        self.banner.configure(text='', bg=C_CARD)
        self.log_all.clear()
        self._render_log()
        self.prog_var.set(0)
        self.prog_text.set('正在启动…')
        self._show_view('run')
        self.btn_stop.configure(state='normal')
        self.btn_export.configure(state='disabled')
        self._set_status('running')

        cfg = {'apk': apk, 'package': self.pkg_var.get().strip(),
               'duration': int(self.dur_var.get()),
               'crash_test': self.crash_var.get(), 'post_test': self.post_var.get()}
        self.engine = AuditEngine(cfg, self.q, self.env)
        threading.Thread(target=self.engine.run, daemon=True).start()

    def _stop(self):
        if self.engine:
            self.engine.stop_event.set()
            self.engine.consent_event.set()
        self._set_status('stopping')

    def _reset_to_idle(self):
        self._show_view('idle')
        self._set_status('idle')

    def _export(self):
        if not self.summary or not self.engine:
            return
        default = REPORT_DIR / f"隐私合规报告_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt"
        default.parent.mkdir(parents=True, exist_ok=True)
        p = filedialog.asksaveasfilename(title='导出报告', initialfile=default.name,
                                         initialdir=str(default.parent),
                                         filetypes=[('文本文件', '*.txt')])
        if p:
            Path(p).write_text(self.engine.build_report_text(self.summary), encoding='utf-8')
            self._log('OK', f'报告已导出: {p}')

    # ---- 结果/堆栈 ----
    def _show_stack_popup(self, _e):
        sel = self.tree.selection()
        if not sel:
            return
        hit = self.hits_rows[self.tree.index(sel[0])]
        win = tk.Toplevel(self)
        win.title(f"堆栈 - {hit['api']}")
        win.configure(bg=C_CARD, padx=12, pady=10)
        win.geometry('860x520')
        head = tk.Label(win, text=f"[{hit['time']}] {hit['phase']} · {hit['cat']} · "
                                  f"{hit['api']} {hit['detail']}\n归属: {hit['sdk']}",
                        bg=C_CARD, fg=C_TEXT, font=FONT_S, justify='left', anchor='w')
        head.pack(fill='x', pady=(0, 6))
        txt = tk.Text(win, bg='#101216', fg=C_TEXT, font=FONT_MONO, relief='flat', wrap='none')
        txt.insert('1.0', hit['stack'])
        txt.configure(state='disabled')
        txt.pack(fill='both', expand=True)
        sb = ttk.Scrollbar(txt, orient='vertical', command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')

    # ---- 队列消费 ----
    def _poll(self):
        # 消费环境巡检结果
        try:
            while True:
                self._apply_env(self.env_q.get_nowait())
        except queue.Empty:
            pass
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == 'log':
                    self._log(msg[1], msg[2])
                elif kind == 'phase':
                    self._set_phase(msg[1], msg[2])
                elif kind == 'progress':
                    self.prog_var.set(msg[1])
                    self.prog_text.set(msg[2])
                elif kind == 'hit':
                    self._add_hit(msg[1])
                elif kind == 'consent_prompt':
                    self._ask_consent()
                elif kind == 'done':
                    self._finish(msg[1])
                elif kind == 'error':
                    self._log('ERR', msg[1])
                    self._finish(None)
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _finish(self, summary):
        self.btn_stop.configure(state='disabled')
        if summary:
            self.summary = summary
            self.btn_export.configure(state='normal')
            fail = bool(summary['pre_hits'])
            self._set_status('fail' if fail else 'pass')
            self.banner.configure(
                text=f"  {summary['verdict']}", bg='#3a2222' if fail else '#1d3324',
                fg=C_ERR if fail else C_OK)
            self.prog_text.set(summary['verdict'])
            self._log('ERR' if fail else 'OK', f"结论: {summary['verdict']}")
            try:
                REPORT_DIR.mkdir(parents=True, exist_ok=True)
                p = REPORT_DIR / f"隐私合规报告_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt"
                p.write_text(self.engine.build_report_text(summary), encoding='utf-8')
                self._log('INFO', f'报告已自动保存: {p}')
            except Exception as e:
                self._log('WARN', f'自动保存报告失败: {e}')
        else:
            self._set_status('idle')
            self.banner.configure(text='  检测失败，详见日志', bg='#3a2c22', fg=C_WARN)

    def _ask_consent(self):
        win = tk.Toplevel(self)
        win.title('等待同意操作')
        win.configure(bg=C_CARD, padx=20, pady=16)
        win.transient(self)
        win.grab_set()
        win.protocol('WM_DELETE_WINDOW', lambda: self._consent_done(win, True))
        ttk.Label(win, text='请在设备上点击隐私协议的"同意"按钮，\n完成后继续对照复测。',
                  style='Card.TLabel', justify='center', font=FONT).pack(pady=(0, 14))
        btns = ttk.Frame(win, style='Card.TFrame')
        btns.pack()
        ttk.Button(btns, text='已同意，继续', style='Accent.TButton',
                   command=lambda: self._consent_done(win, False)).pack(side='left', padx=6)
        ttk.Button(btns, text='跳过对照',
                   command=lambda: self._consent_done(win, True)).pack(side='left', padx=6)

    def _consent_done(self, win, skip):
        win.destroy()
        if self.engine:
            self.engine.consent_skip = skip
            self.engine.consent_event.set()

    # ---- 渲染 ----
    def _set_phase(self, idx, state):
        marks = {'pending': ('', C_MUTED, C_CARD), 'running': ('▶ ', C_ACCENT, C_CARD2),
                 'done': ('✓ ', C_OK, C_CARD2), 'skip': ('— ', C_MUTED, C_CARD2)}
        mark, fg, bg = marks.get(state, ('', C_MUTED, C_CARD))
        if idx < len(self.step_labels):
            self.step_labels[idx].configure(fg=fg, bg=bg)
        self.step_vars[idx].set(f'{mark}{AuditEngine.PHASES[idx]}')

    def _add_hit(self, hit):
        fail = '未同意' in hit['phase']
        self.hits_rows.append(hit)
        self.tree.insert('', 'end', values=(
            hit['time'], hit['phase'], hit['cat'],
            f"{hit['api']} {hit['detail']}".strip(), hit['sdk'],
            '❌ 违规' if fail else '✅ 合规'), tags=('fail' if fail else 'pass',))
        self.tree.see(self.tree.get_children()[-1])
        chip = self.cat_chips.get(hit['cat'])
        if chip:
            n = sum(1 for h in self.hits_rows if h['cat'] == hit['cat'] and '未同意' in h['phase'])
            base = hit['cat']
            if fail:
                chip.set(f'{base} ×{n}', fg=C_HIT, bg='#3a2a1d')
            else:
                chip.set(base, fg=C_OK, bg='#1d2b22')
        self._log('HIT', f"[{hit['phase']}][{hit['cat']}] {hit['api']} {hit['detail']} -> {hit['sdk']}")

    def _log(self, level, text):
        stamp = datetime.datetime.now().strftime('%H:%M:%S')
        for line in str(text).splitlines() or ['']:
            self.log_all.append((level, f'[{stamp}] [{level}] {line}'))
        self.log_count.configure(text=f'{len(self.log_all)} 条')
        self._render_log()

    def _render_log(self):
        if not self.log_open and self.filter_var.get() == '全部':
            return
        mode = self.filter_var.get()
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        for level, text in self.log_all[-500:]:
            if mode == '仅命中' and level != 'HIT':
                continue
            if mode == '仅错误' and level != 'ERR':
                continue
            self.log_text.insert('end', text + '\n', level)
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

    def _clear_log(self):
        self.log_all.clear()
        self._render_log()

    def _set_status(self, state):
        table = {'idle': ('● 空闲', C_MUTED), 'running': ('● 检测中', C_ACCENT),
                 'stopping': ('● 停止中', C_WARN), 'pass': ('● 通过', C_OK),
                 'fail': ('● 有风险', C_ERR)}
        text, color = table.get(state, ('●', C_MUTED))
        self.status_chip.set(text, fg=color)

    def _on_close(self):
        if self.engine:
            self.engine.stop_event.set()
            self.engine.consent_event.set()
        self._save_settings()
        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == '__main__':
    main()
