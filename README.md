# LanGuardian - Windows 局域网实时状况检测、异常节点定位与修正诊断工具

## 1. 核心特性
- **单文件 `.exe` 独立运行**：`LanGuardian.exe` 仅 77KB，无需安装 Python、Go 或额外运行时，在任意 Windows 10 / 11 上开箱即用。
- **普适自适应任意网段（不写死 IP）**：
  - 启动时自动枚举所有网卡，动态计算当前网段 CIDR（无论 `10.0.0.0/24`、`192.168.1.0/24`、`172.16.0.0/16` 等）、默认网关与 DNS。
  - 支持在 Web 界面右上角随时**切换监控网卡**（如切换到插在路由器 `LAN4` 端口镜像口上的专用抓包网卡）或自定义监控网段。
- **双模混杂抓包引擎 + 主动探测**：
  - **模式 1（推荐，支持交换机/路由器端口镜像全量二层抓包）**：自动检测并加载 **Npcap (`wpcap.dll`)**，在二层混杂模式下捕获所有以太网帧（ARP、VLAN、DHCP、TCP、UDP、DNS、mDNS、TLS SNI、HTTP Host、广播风暴）。
  - **模式 2（零驱动开箱即用）**：即使未安装 Npcap，右键以管理员身份运行时也会自动启用 **Windows 原生 `RawSocket (SIO_RCVALL)` 混杂抓包引擎 + 内核 ARP 表轮询 (`SendARP`)**。
- **内置 10 类异常检测 + 自动修正意见（含通用、维盟 WayOS、TP-LINK 商用路由落地方案）**：
  1. **私接路由器 / 非法 DHCP 抢答 (`ROGUE_DHCP`)**
  2. **跨网段异常节点窜入 (`CROSS_SUBNET`，如 `192.168.0.1` 混入 `10.0.0.0/24`)**
  3. **ARP 欺骗 / IP 地址冲突 (`ARP_CONFLICT`，同一 IP 对应多个 MAC)**
  4. **广播风暴 / 高频 ARP 扫描 (`BROADCAST_STORM`)**
  5. **突发大流量尖峰 (`TRAFFIC_BURST`，滑动窗口 + EWMA 动态基线 + 自动提取正在访问的域名/SNI/端口)**
  6. **单机连接数/SYN 洪泛 (`CONN_FLOOD`，P2P 迅雷或异常高并发打满 NAT 表)**
  7. **内网横向端口扫描 (`PORT_SCAN`)**
  8. **高 TCP 重传率 / 零窗口 (`HIGH_RETRANSMIT`，定位劣质网线或百兆小路由瓶颈)**
  9. **内网网关劣化 (`GATEWAY_DEGRADED`，区分内网堵死 vs 外网宽带慢)**
  10. **外网宽带出口抖动 (`WAN_DEGRADED`)**

## 2. 使用方法
1. 将 [LanGuardian.exe](file:///Users/mandoli/.gemini/antigravity/scratch/LanGuardian/LanGuardian.exe)（及可选的 [启动局域网检测(管理员).bat](file:///Users/mandoli/.gemini/antigravity/scratch/LanGuardian/启动局域网检测(管理员).bat)）复制到 Windows 监控电脑。
2. 右键 **`LanGuardian.exe`** -> **以管理员身份运行**（或直接双击 `启动局域网检测(管理员).bat`）。
3. 程序会自动在浏览器打开可视化诊断面板：`http://127.0.0.1:8088`（局域网其他电脑也可通过 `http://<监控机IP>:8088` 访问）。
4. 若需配合维盟 `IBR-740` 或 TP-LINK `TL-R476G+` 的**端口镜像口**抓全网二层流量，建议在 Windows 上安装免费开源的 [Npcap](https://npcap.com/)（安装时勾选 `Install Npcap in WinPcap API-compatible Mode`）。

## 3. 重新编译命令（如需修改源码 `LanGuardian.cs`）
- **在 Windows 上（无需安装任何工具，使用系统自带编译器）**：
  ```cmd
  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /optimize+ /out:LanGuardian.exe LanGuardian.cs
  ```
- **在当前 Mac 上交叉编译**：
  ```bash
  /usr/local/share/dotnet/dotnet /usr/local/share/dotnet/sdk/9.0.102/Roslyn/bincore/csc.dll -nologo -optimize+ -target:exe -platform:anycpu -nostdlib -r:/usr/local/share/dotnet/sdk/9.0.102/ref/mscorlib.dll -r:/usr/local/share/dotnet/sdk/9.0.102/ref/netstandard.dll -out:LanGuardian.exe LanGuardian.cs
  ```
