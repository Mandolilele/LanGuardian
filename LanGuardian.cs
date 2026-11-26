using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LanGuardian
{
    public class AdapterInfo
    {
        public string Id = "";
        public string Name = "";
        public string Description = "";
        public string Mac = "";
        public string Ip = "";
        public string Mask = "";
        public string Cidr = "";
        public string Gateway = "";
        public string Dns = "";
        public long SpeedMbps = 0;
        public string PcapDeviceName = "";
        public bool IsUp = true;
        public bool IsMirrorCandidate = false;
    }

    public class HostStats
    {
        public string Ip = "";
        public string Mac = "";
        public string Vendor = "未知厂商";
        public string Hostname = "";
        public bool IsLocalSubnet = true;
        public bool IsGateway = false;
        public DateTime FirstSeen = DateTime.Now;
        public DateTime LastSeen = DateTime.Now;
        public double LastPingMs = -1;

        // Cumulative counters
        public long TotalTxBytes = 0;
        public long TotalRxBytes = 0;
        public long TotalTxPkts = 0;
        public long TotalRxPkts = 0;
        public long BroadcastPkts = 0;
        public long ArpReqPkts = 0;
        public long ArpReplyPkts = 0;
        public long SynPkts = 0;
        public long RstPkts = 0;
        public long TcpTotalPkts = 0;
        public long TcpRetransPkts = 0;
        public long LanTcpTotalPkts = 0;
        public long LanTcpRetransPkts = 0;
        public long TcpZeroWinPkts = 0;
        public long DnsQueryPkts = 0;
        public long DhcpServerPkts = 0;

        // Window counters (1-second tick)
        public long WinTxBytes = 0;
        public long WinRxBytes = 0;
        public long WinTxPkts = 0;
        public long WinRxPkts = 0;
        public long WinBcastPkts = 0;
        public long WinArpReqPkts = 0;
        public long WinSynPkts = 0;
        public long WinRstPkts = 0;

        // Real-time calculated rates (per second)
        public double TxBps = 0;
        public double RxBps = 0;
        public double EwmaTotalBps = 0;
        public double Pps = 0;
        public double BcastPps = 0;
        public double ArpPps = 0;
        public double SynRate = 0;
        public double RetransRatePct = 0;

        // Historical MACs seen for this IP (to detect ARP conflict / spoofing)
        public ConcurrentDictionary<string, DateTime> SeenMacs = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        // Recent target ports & IPs (to detect port scanning)
        public ConcurrentDictionary<string, DateTime> RecentSynTargets = new ConcurrentDictionary<string, DateTime>();
        // Recent domains / SNI / ports
        public ConcurrentQueue<string> RecentActivities = new ConcurrentQueue<string>();
        // Recent TCP sequence tracking for lightweight retransmission detection
        public ConcurrentDictionary<ulong, uint> FlowMaxSeq = new ConcurrentDictionary<ulong, uint>();

        public void AddActivity(string act)
        {
            if (string.IsNullOrEmpty(act)) return;
            foreach (var existing in RecentActivities)
            {
                if (existing == act) return;
            }
            RecentActivities.Enqueue(act);
            while (RecentActivities.Count > 8)
            {
                string _;
                RecentActivities.TryDequeue(out _);
            }
        }
    }

    public class AnomalyAlert
    {
        public string Id = "";
        public string Code = "";
        public string Severity = "warning"; // critical, warning, info
        public string Title = "";
        public string TargetIp = "";
        public string TargetMac = "";
        public string TargetVendor = "";
        public string Evidence = "";
        public string Cause = "";
        public string FixGeneral = "";
        public string FixWayOS = "";
        public string FixTpLink = "";
        public DateTime FirstTime = DateTime.Now;
        public DateTime LastTime = DateTime.Now;
        public int Count = 1;
    }

    public class TrafficPoint
    {
        public string Time = "";
        public double TotalKBps = 0;
        public double TotalPps = 0;
        public double BcastPps = 0;
    }

    public class FlowLink
    {
        public string Key = "";
        public string SrcIp = "";
        public string DstIp = "";
        public string Label = "";
        public long WinBytes = 0;
        public long TotalBytes = 0;
        public double KBps = 0;
        public DateTime LastSeen = DateTime.Now;
    }

    internal static class NativeWin
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int phyAddrLen);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetDllDirectory(string lpPathName);

        // Npcap / WinPcap P/Invoke
        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_pkthdr
        {
            public int tv_sec;
            public int tv_usec;
            public uint caplen;
            public uint len;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_if
        {
            public IntPtr next;
            public IntPtr name;
            public IntPtr description;
            public IntPtr addresses;
            public uint flags;
        }

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int pcap_findalldevs(ref IntPtr alldevs, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_freealldevs(IntPtr alldevs);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int to_ms, StringBuilder errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_next_ex(IntPtr p, ref IntPtr pkt_header, ref IntPtr pkt_data);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_datalink(IntPtr p);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_close(IntPtr p);
    }

    public static class OuiDb
    {
        private static readonly Dictionary<string, string> Map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            {"80:81:00", "维盟 (WayOS)"},
            {"3C:06:A7", "TP-LINK (普联)"},
            {"B8:F8:83", "TP-LINK (普联)"},
            {"BC:46:99", "TP-LINK (普联)"},
            {"50:BD:5F", "TP-LINK (普联)"},
            {"60:3A:7C", "TP-LINK (普联)"},
            {"EC:17:2F", "TP-LINK (普联)"},
            {"14:CF:92", "TP-LINK (普联)"},
            {"F4:83:CD", "TP-LINK (普联)"},
            {"24:5E:BE", "威联通 (QNAP NAS)"},
            {"00:11:32", "群晖 (Synology NAS)"},
            {"78:45:C4", "戴尔 (Dell)"},
            {"18:F2:2C", "Intel / 网卡"},
            {"3C:46:D8", "TP-LINK / 网卡"},
            {"C0:25:A5", "戴尔 / Realtek"},
            {"20:4E:7F", "网件 (Netgear)"},
            {"00:26:F2", "网件 (Netgear)"},
            {"E4:AA:EC", "小米 / 创米科技"},
            {"58:B6:23", "小米 / 领普科技"},
            {"6C:1F:F7", "Realtek / 终端"},
            {"34:BD:F9", "小米 / 终端"},
            {"AC:C9:06", "华为 / 荣耀"},
            {"34:04:9E", "海康威视 / 网络设备"},
            {"70:B5:E8", "联发科 / 无线网卡"},
            {"78:55:36", "Realtek / 有线网卡"},
            {"9C:76:0E", "Apple (苹果 Mac)"},
            {"00:15:5D", "Microsoft (Hyper-V)"},
            {"00:0C:29", "VMware 虚拟机"},
            {"00:50:56", "VMware 虚拟机"},
            {"08:00:27", "VirtualBox 虚拟机"}
        };

        public static string Lookup(string mac)
        {
            if (string.IsNullOrEmpty(mac) || mac.Length < 8) return "未知设备";
            string norm = mac.Replace("-", ":").ToUpperInvariant();
            string prefix = norm.Substring(0, 8);
            string vendor;
            if (Map.TryGetValue(prefix, out vendor)) return vendor;

            // Check Locally Administered Address (Randomized MAC on modern phones/laptops)
            char secondHex = norm[1];
            if (secondHex == '2' || secondHex == '6' || secondHex == 'A' || secondHex == 'E')
            {
                return "移动终端 (随机隐私MAC)";
            }
            return "通用网卡 (" + prefix + ")";
        }
    }

    public class NicLiveStats
    {
        public string Id = "";
        public string Name = "";
        public string Ip = "";
        public string Cidr = "";
        public bool IsMirror = false;
        public long TotalPkts = 0;
        public long TotalBytes = 0;
        public long WinPkts = 0;
        public long WinBytes = 0;
        public double Pps = 0;
        public double KBps = 0;
        public ConcurrentDictionary<string, string> SeenMacToIp = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<string, int> ObservedSubnets = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    }

    public class MonitorEngine
    {
        public const string AppVersion = "v1.4.2";
        public List<AdapterInfo> Adapters = new List<AdapterInfo>();
        public AdapterInfo ActiveAdapter = new AdapterInfo();
        public List<string> IgnoredLocalSubnets = new List<string>();
        public HashSet<string> LocalHostIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> LocalHostMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<string, NicLiveStats> NicStats = new ConcurrentDictionary<string, NicLiveStats>(StringComparer.OrdinalIgnoreCase);
        public volatile bool IsolateCrossWireCheck = false;
        public long CrossWireSyncHits = 0;
        public List<string> CrossWireSharedMacs = new List<string>();
        public bool DualNicSameSegment = true;
        private IntPtr _secondaryPcapHandle = IntPtr.Zero;
        private readonly ConcurrentDictionary<ulong, Tuple<string, long>> _crossBcastWindow = new ConcurrentDictionary<ulong, Tuple<string, long>>();
        public uint SubnetNetUint = 0;
        public uint SubnetMaskUint = 0;
        public string ActiveCidr = "";
        public string CaptureEngineName = "初始化中...";
        public bool NpcapAvailable = false;
        public volatile bool IsPaused = false;

        public ConcurrentDictionary<string, HostStats> Hosts = new ConcurrentDictionary<string, HostStats>();
        public ConcurrentDictionary<string, AnomalyAlert> Alerts = new ConcurrentDictionary<string, AnomalyAlert>();
        public ConcurrentDictionary<string, FlowLink> ActiveLinks = new ConcurrentDictionary<string, FlowLink>();
        public ConcurrentQueue<TrafficPoint> History = new ConcurrentQueue<TrafficPoint>();

        public double GatewayLatencyMs = -1;
        public double GatewayLossPct = 0;
        public string UpstreamGatewayIp = "";
        public double UpstreamLatencyMs = -1;
        public double DnsLatencyMs = -1;
        public double WanLatencyMs = -1;
        public double WanLossPct = 0;

        public long TotalCapturedPackets = 0;
        public long TotalCapturedBytes = 0;
        public double CurrentTotalKBps = 0;
        public double CurrentTotalPps = 0;
        public double CurrentBcastPps = 0;

        private volatile bool _running = false;
        private volatile int _captureGeneration = 0;
        private IntPtr _activePcapHandle = IntPtr.Zero;
        private Socket _activeRawSocket = null;
        public string GatewayMac = "";
        private string _preferredAdapterHint = "";

        // Recent packet ring buffer to deduplicate identical packets mirrored across multiple switch ports
        private const int MirrorDedupSize = 1024;
        private readonly ulong[] _dedupSigs = new ulong[MirrorDedupSize];
        private readonly long[] _dedupTicks = new long[MirrorDedupSize];
        private int _dedupCursor = 0;
        private readonly object _dedupLock = new object();

        private bool IsMirrorDuplicatePacket(ulong sig)
        {
            long now = Environment.TickCount & 0x7FFFFFFF;
            lock (_dedupLock)
            {
                for (int i = 0; i < MirrorDedupSize; i++)
                {
                    if (_dedupSigs[i] == sig)
                    {
                        long diff = (now - _dedupTicks[i]) & 0x7FFFFFFF;
                        if (diff < 100) return true;
                    }
                }
                _dedupSigs[_dedupCursor] = sig;
                _dedupTicks[_dedupCursor] = now;
                _dedupCursor = (_dedupCursor + 1) & (MirrorDedupSize - 1);
            }
            return false;
        }

        private static string GetConfigPath()
        {
            try
            {
                return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LanGuardian.cfg");
            }
            catch { return "LanGuardian.cfg"; }
        }

        public static string LoadSavedAdapterPreference()
        {
            try
            {
                string p = GetConfigPath();
                if (File.Exists(p))
                {
                    foreach (string line in File.ReadAllLines(p))
                    {
                        if (line.StartsWith("adapter=", StringComparison.OrdinalIgnoreCase))
                            return line.Substring(8).Trim();
                    }
                }
            }
            catch { }
            return "";
        }

        public static void SaveAdapterPreference(string adapterId)
        {
            try
            {
                if (!string.IsNullOrEmpty(adapterId))
                {
                    File.WriteAllText(GetConfigPath(), "adapter=" + adapterId + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch { }
        }

        public void Start(string preferredIpOrAdapter)
        {
            if (string.IsNullOrEmpty(preferredIpOrAdapter))
            {
                preferredIpOrAdapter = LoadSavedAdapterPreference();
            }
            _preferredAdapterHint = preferredIpOrAdapter ?? "";
            DetectNpcap();
            RefreshAdapters();
            SelectBestAdapter(_preferredAdapterHint);

            _running = true;
            Task.Run(() => TickerLoop());
            Task.Run(() => HealthAndDiscoveryLoop());
            RestartPacketCapture();
        }

        private void DetectNpcap()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    string npcapDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
                    if (Directory.Exists(npcapDir))
                    {
                        NativeWin.SetDllDirectory(npcapDir);
                    }
                    IntPtr h = NativeWin.LoadLibrary("wpcap.dll");
                    if (h != IntPtr.Zero)
                    {
                        NpcapAvailable = true;
                    }
                }
            }
            catch
            {
                NpcapAvailable = false;
            }
        }

        public static bool IsVirtualAdapter(string name, string desc)
        {
            string s = ((name ?? "") + " " + (desc ?? "")).ToLowerInvariant();
            string[] kw = new[] {
                "zerotier", "tailscale", "wireguard", "wintun", "tap-windows", "tap-", "openvpn",
                "hyper-v", "vethernet", "vmware", "virtualbox", "virtual", "wan miniport",
                "bluetooth", "loopback", "radmin", "hamachi", "anyconnect", "sangfor", "vpn", "teredo", "isatap"
            };
            foreach (var k in kw)
            {
                if (s.Contains(k)) return true;
            }
            return false;
        }

        public void RefreshAdapters()
        {
            var list = new List<AdapterInfo>();
            var ignoredSubs = new List<string>();
            var localIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var localMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var pcapMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var pcapEntries = new List<Tuple<string, string, string>>();

            if (NpcapAvailable)
            {
                try
                {
                    IntPtr alldevs = IntPtr.Zero;
                    var err = new StringBuilder(256);
                    if (NativeWin.pcap_findalldevs(ref alldevs, err) == 0 && alldevs != IntPtr.Zero)
                    {
                        IntPtr cur = alldevs;
                        while (cur != IntPtr.Zero)
                        {
                            var pif = Marshal.PtrToStructure<NativeWin.pcap_if>(cur);
                            string name = pif.name != IntPtr.Zero ? Marshal.PtrToStringAnsi(pif.name) : "";
                            string desc = pif.description != IntPtr.Zero ? Marshal.PtrToStringAnsi(pif.description) : "";
                            if (!string.IsNullOrEmpty(name))
                            {
                                // Extract GUID {xxxx-...}
                                int brace = name.IndexOf('{');
                                if (brace >= 0)
                                {
                                    string guid = name.Substring(brace);
                                    pcapMap[guid] = name;
                                    pcapEntries.Add(Tuple.Create(guid, name, desc));
                                }
                            }
                            cur = pif.next;
                        }
                        NativeWin.pcap_freealldevs(alldevs);
                    }
                }
                catch { }
            }

            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                var ipProps = ni.GetIPProperties();
                var ipv4 = ipProps.UnicastAddresses
                    .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(u.Address));

                string ipStr = ipv4 != null ? ipv4.Address.ToString() : "";
                string maskStr = (ipv4 != null && ipv4.IPv4Mask != null) ? ipv4.IPv4Mask.ToString() : "255.255.255.0";
                string cidr = (!string.IsNullOrEmpty(ipStr) && !ipStr.StartsWith("169.254.")) ? ComputeCidr(ipStr, maskStr) : "";

                // Strictly isolate virtual VPN / ZeroTier / Hyper-V adapters so they never affect LAN monitoring
                if (IsVirtualAdapter(ni.Name, ni.Description))
                {
                    if (!string.IsNullOrEmpty(cidr)) ignoredSubs.Add(cidr);
                    if (!string.IsNullOrEmpty(ipStr)) localIps.Add(ipStr);
                    continue;
                }

                bool isUp = ni.OperationalStatus == OperationalStatus.Up;
                bool isPhysicalEth = (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                                      ni.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet ||
                                      ni.NetworkInterfaceType == NetworkInterfaceType.FastEthernetT);

                if (!isUp && string.IsNullOrEmpty(ipStr) && !isPhysicalEth) continue;

                var gw = ipProps.GatewayAddresses
                    .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0");
                var dns = ipProps.DnsAddresses
                    .FirstOrDefault(d => d.AddressFamily == AddressFamily.InterNetwork);

                string gwStr = gw != null ? gw.Address.ToString() : "";
                string mac = FormatMac(ni.GetPhysicalAddress().GetAddressBytes());
                if (!string.IsNullOrEmpty(ipStr)) localIps.Add(ipStr);
                if (IsValidUnicastMac(mac)) localMacs.Add(mac);

                string pcapDev = "";
                if (!string.IsNullOrEmpty(ni.Id) && pcapMap.ContainsKey(ni.Id))
                {
                    pcapDev = pcapMap[ni.Id];
                }

                bool isMirrorCand = isPhysicalEth && string.IsNullOrEmpty(gwStr);

                list.Add(new AdapterInfo
                {
                    Id = ni.Id,
                    Name = ni.Name,
                    Description = ni.Description,
                    Mac = mac,
                    Ip = ipStr,
                    Mask = maskStr,
                    Cidr = cidr,
                    Gateway = gwStr,
                    Dns = dns != null ? dns.ToString() : "223.5.5.5",
                    SpeedMbps = ni.Speed > 0 ? ni.Speed / 1000000 : 1000,
                    PcapDeviceName = pcapDev,
                    IsUp = isUp,
                    IsMirrorCandidate = isMirrorCand
                });
            }

            // Also include pure L2 Npcap adapters (e.g. mirror NICs with IPv4/IPv6 disabled so .NET NetworkInterface hides them)
            foreach (var pe in pcapEntries)
            {
                string guid = pe.Item1;
                string pcapName = pe.Item2;
                string pcapDesc = pe.Item3 ?? "";
                if (list.Any(a => string.Equals(a.Id, guid, StringComparison.OrdinalIgnoreCase))) continue;
                if (IsVirtualAdapter(pcapName, pcapDesc)) continue;

                string friendlyName = !string.IsNullOrEmpty(pcapDesc) ? ("镜像口: " + pcapDesc) : "纯二层镜像网卡";

                list.Add(new AdapterInfo
                {
                    Id = guid,
                    Name = friendlyName,
                    Description = pcapDesc,
                    Mac = "",
                    Ip = "",
                    Mask = "255.255.255.0",
                    Cidr = "",
                    Gateway = "",
                    Dns = "223.5.5.5",
                    SpeedMbps = 1000,
                    PcapDeviceName = pcapName,
                    IsUp = true,
                    IsMirrorCandidate = true
                });
            }

            // Inherit fallback CIDR & Gateway for mirror NICs that have 169.254.x.x or no IP
            var primary = list.FirstOrDefault(a => !string.IsNullOrEmpty(a.Gateway) && !string.IsNullOrEmpty(a.Cidr));
            if (primary != null)
            {
                foreach (var a in list)
                {
                    if (string.IsNullOrEmpty(a.Cidr)) a.Cidr = primary.Cidr;
                    if (string.IsNullOrEmpty(a.Gateway)) a.Gateway = primary.Gateway;
                }
            }

            IgnoredLocalSubnets = ignoredSubs;
            LocalHostIps = localIps;
            LocalHostMacs = localMacs;
            Adapters = list;
        }

        public void SelectBestAdapter(string preferred)
        {
            AdapterInfo chosen = null;
            if (!string.IsNullOrEmpty(preferred))
            {
                chosen = Adapters.FirstOrDefault(a =>
                    string.Equals(a.Id, preferred, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(a.Ip) && string.Equals(a.Ip, preferred, StringComparison.OrdinalIgnoreCase)) ||
                    a.Name.IndexOf(preferred, StringComparison.OrdinalIgnoreCase) >= 0);
            }
            if (chosen == null && NpcapAvailable)
            {
                // Auto-select connected L2 mirror NIC if present alongside a primary uplink NIC
                chosen = Adapters.FirstOrDefault(a =>
                    a.IsMirrorCandidate && a.IsUp &&
                    !string.IsNullOrEmpty(a.Cidr) && !string.IsNullOrEmpty(a.PcapDeviceName));
            }
            if (chosen == null)
            {
                // Prefer physical adapter with a valid IPv4 gateway and non-APIPA IP
                chosen = Adapters
                    .OrderByDescending(a => !string.IsNullOrEmpty(a.Gateway))
                    .ThenByDescending(a => !string.IsNullOrEmpty(a.Ip) && !a.Ip.StartsWith("169.254."))
                    .FirstOrDefault();
            }
            if (chosen != null)
            {
                SetActiveAdapter(chosen, chosen.Cidr);
            }
        }

        public void SetActiveAdapter(AdapterInfo adapter, string overrideCidr)
        {
            ActiveAdapter = adapter;
            ActiveCidr = !string.IsNullOrEmpty(overrideCidr) ? overrideCidr : adapter.Cidr;
            ParseCidr(ActiveCidr, out SubnetNetUint, out SubnetMaskUint);

            if (!string.IsNullOrEmpty(adapter.Ip))
            {
                var self = GetOrAddHost(adapter.Ip, adapter.Mac);
                self.Hostname = Dns.GetHostName() + " (本机)";
            }
            if (!string.IsNullOrEmpty(adapter.Gateway))
            {
                var gw = GetOrAddHost(adapter.Gateway, "");
                gw.IsGateway = true;
                if (string.IsNullOrEmpty(gw.Hostname)) gw.Hostname = "默认网关 / 路由器";
            }
        }

        public void TogglePause(bool? forceState = null)
        {
            bool next = forceState.HasValue ? forceState.Value : !IsPaused;
            IsPaused = next;
            if (IsPaused)
            {
                Interlocked.Increment(ref _captureGeneration);
                try { if (_activePcapHandle != IntPtr.Zero) { NativeWin.pcap_close(_activePcapHandle); _activePcapHandle = IntPtr.Zero; } } catch { }
                try { if (_activeRawSocket != null) { _activeRawSocket.Close(); _activeRawSocket = null; } } catch { }
                CaptureEngineName = "⏸️ 监控已暂停 (点击顶部【恢复监控】可随时继续抓包)";
            }
            else
            {
                RestartPacketCapture();
            }
        }

        public void ResetAllStats()
        {
            Hosts.Clear();
            Alerts.Clear();
            ActiveLinks.Clear();
            TrafficPoint _;
            while (History.TryDequeue(out _)) { }
            Interlocked.Exchange(ref TotalCapturedPackets, 0);
            Interlocked.Exchange(ref TotalCapturedBytes, 0);
            CurrentTotalKBps = 0;
            CurrentTotalPps = 0;
            CurrentBcastPps = 0;
            RefreshAdapters();
            SetActiveAdapter(ActiveAdapter, ActiveCidr);
        }

        public void RestartPacketCapture()
        {
            if (IsPaused) return;
            int gen = Interlocked.Increment(ref _captureGeneration);
            try
            {
                if (_activePcapHandle != IntPtr.Zero)
                {
                    NativeWin.pcap_close(_activePcapHandle);
                    _activePcapHandle = IntPtr.Zero;
                }
            }
            catch { }
            try
            {
                if (_secondaryPcapHandle != IntPtr.Zero)
                {
                    NativeWin.pcap_close(_secondaryPcapHandle);
                    _secondaryPcapHandle = IntPtr.Zero;
                }
            }
            catch { }
            try
            {
                if (_activeRawSocket != null)
                {
                    _activeRawSocket.Close();
                    _activeRawSocket = null;
                }
            }
            catch { }

            NicStats.Clear();
            _crossBcastWindow.Clear();
            CrossWireSyncHits = 0;
            CrossWireSharedMacs = new List<string>();
            foreach (var a in Adapters)
            {
                NicStats[a.Id] = new NicLiveStats
                {
                    Id = a.Id,
                    Name = a.Name,
                    Ip = a.Ip,
                    Cidr = a.Cidr,
                    IsMirror = a.IsMirrorCandidate
                };
            }

            Task.Run(() => CaptureWorker(gen));

            // Launch concurrent L2 listener on the second physical NIC (if present) for dual-segment & cross-wire detection
            if (NpcapAvailable && Adapters.Count >= 2)
            {
                var secondary = Adapters.FirstOrDefault(a =>
                    !string.Equals(a.Id, ActiveAdapter.Id, StringComparison.OrdinalIgnoreCase) &&
                    a.IsUp && !string.IsNullOrEmpty(a.PcapDeviceName));
                if (secondary != null)
                {
                    Task.Run(() => SecondaryCaptureWorker(gen, secondary));
                }
            }
        }

        private void SecondaryCaptureWorker(int gen, AdapterInfo nic)
        {
            try
            {
                var err = new StringBuilder(256);
                IntPtr handle = NativeWin.pcap_open_live(nic.PcapDeviceName, 256, 1, 150, err);
                if (handle == IntPtr.Zero) return;
                _secondaryPcapHandle = handle;
                int dlt = NativeWin.pcap_datalink(handle);
                byte[] buf = new byte[256];
                while (_running && gen == _captureGeneration)
                {
                    IntPtr hdrPtr = IntPtr.Zero;
                    IntPtr dataPtr = IntPtr.Zero;
                    int res = NativeWin.pcap_next_ex(handle, ref hdrPtr, ref dataPtr);
                    if (res == 1 && hdrPtr != IntPtr.Zero && dataPtr != IntPtr.Zero)
                    {
                        var hdr = Marshal.PtrToStructure<NativeWin.pcap_pkthdr>(hdrPtr);
                        int capLen = (int)Math.Min(hdr.caplen, 256u);
                        if (capLen >= 14 && dlt == 1)
                        {
                            Marshal.Copy(dataPtr, buf, 0, capLen);
                            InspectFrameForDualNic(nic.Id, buf, capLen, (int)hdr.len);
                        }
                    }
                }
            }
            catch { }
        }

        private void InspectFrameForDualNic(string adapterId, byte[] buf, int capLen, int wireLen)
        {
            if (capLen < 14 || string.IsNullOrEmpty(adapterId)) return;
            NicLiveStats ns;
            if (!NicStats.TryGetValue(adapterId, out ns)) return;

            Interlocked.Increment(ref ns.TotalPkts);
            Interlocked.Add(ref ns.TotalBytes, wireLen);
            Interlocked.Increment(ref ns.WinPkts);
            Interlocked.Add(ref ns.WinBytes, wireLen);

            string srcMac = FormatMac(buf, 6);
            bool isBcast = (buf[0] & 0x01) != 0;
            int offset = 12;
            ushort etherType = (ushort)((buf[offset] << 8) | buf[offset + 1]);
            offset += 2;
            if (etherType == 0x8100 && capLen >= 18)
            {
                etherType = (ushort)((buf[offset + 2] << 8) | buf[offset + 3]);
                offset += 4;
            }

            string srcIp = "";
            ulong bcastSig = 0;
            if (etherType == 0x0806 && capLen >= offset + 28) // ARP
            {
                srcIp = string.Format("{0}.{1}.{2}.{3}", buf[offset + 14], buf[offset + 15], buf[offset + 16], buf[offset + 17]);
                uint sU = ((uint)buf[offset + 14] << 24) | ((uint)buf[offset + 15] << 16) | ((uint)buf[offset + 16] << 8) | buf[offset + 17];
                uint tU = ((uint)buf[offset + 24] << 24) | ((uint)buf[offset + 25] << 16) | ((uint)buf[offset + 26] << 8) | buf[offset + 27];
                bcastSig = ((ulong)sU << 32) ^ tU ^ 0x08060000UL;
            }
            else if (etherType == 0x0800 && capLen >= offset + 20) // IPv4
            {
                srcIp = string.Format("{0}.{1}.{2}.{3}", buf[offset + 12], buf[offset + 13], buf[offset + 14], buf[offset + 15]);
                ushort ipId = (ushort)((buf[offset + 4] << 8) | buf[offset + 5]);
                uint sU = ((uint)buf[offset + 12] << 24) | ((uint)buf[offset + 13] << 16) | ((uint)buf[offset + 14] << 8) | buf[offset + 15];
                uint dU = ((uint)buf[offset + 16] << 24) | ((uint)buf[offset + 17] << 16) | ((uint)buf[offset + 18] << 8) | buf[offset + 19];
                if (isBcast) bcastSig = ((ulong)sU << 32) ^ dU ^ ((ulong)ipId << 16) ^ (ulong)wireLen;
            }

            if (IsValidUnicastMac(srcMac) && !LocalHostMacs.Contains(srcMac))
            {
                if (!string.IsNullOrEmpty(srcIp) && srcIp != "0.0.0.0" && IsPrivateOrLocalIp(srcIp))
                {
                    if (ns.SeenMacToIp.Count < 512) ns.SeenMacToIp[srcMac] = srcIp;
                    string sub24 = srcIp.Substring(0, srcIp.LastIndexOf('.')) + ".0/24";
                    ns.ObservedSubnets.AddOrUpdate(sub24, 1, (k, v) => v + 1);
                }
                else if (ns.SeenMacToIp.Count < 512 && !ns.SeenMacToIp.ContainsKey(srcMac))
                {
                    ns.SeenMacToIp[srcMac] = "";
                }
            }

            // Cross-wire broadcast frame collision detection (same broadcast/ARP frame seen on 2 physical NICs within 200ms)
            if (isBcast && bcastSig != 0 && IsValidUnicastMac(srcMac) && !LocalHostMacs.Contains(srcMac))
            {
                long now = Environment.TickCount & 0x7FFFFFFF;
                Tuple<string, long> prev;
                if (_crossBcastWindow.TryGetValue(bcastSig, out prev))
                {
                    if (!string.Equals(prev.Item1, adapterId, StringComparison.OrdinalIgnoreCase))
                    {
                        long dt = (now - prev.Item2) & 0x7FFFFFFF;
                        if (dt < 200)
                        {
                            Interlocked.Increment(ref CrossWireSyncHits);
                        }
                    }
                }
                if (_crossBcastWindow.Count > 2048) _crossBcastWindow.Clear();
                _crossBcastWindow[bcastSig] = Tuple.Create(adapterId, now);
            }
        }

        private void CaptureWorker(int gen)
        {
            // 1. Try Npcap Layer-2 Promiscuous Mode first if available
            if (NpcapAvailable && !string.IsNullOrEmpty(ActiveAdapter.PcapDeviceName))
            {
                try
                {
                    var err = new StringBuilder(256);
                    IntPtr handle = NativeWin.pcap_open_live(ActiveAdapter.PcapDeviceName, 65536, 1, 100, err);
                    if (handle != IntPtr.Zero)
                    {
                        _activePcapHandle = handle;
                        int dlt = NativeWin.pcap_datalink(handle);
                        CaptureEngineName = "Npcap 二层混杂抓包引擎 (L2 Ethernet + 镜像流量支持)";
                        byte[] buf = new byte[65536];

                        while (_running && gen == _captureGeneration)
                        {
                            IntPtr hdrPtr = IntPtr.Zero;
                            IntPtr dataPtr = IntPtr.Zero;
                            int res = NativeWin.pcap_next_ex(handle, ref hdrPtr, ref dataPtr);
                            if (res == 1 && hdrPtr != IntPtr.Zero && dataPtr != IntPtr.Zero)
                            {
                                var hdr = Marshal.PtrToStructure<NativeWin.pcap_pkthdr>(hdrPtr);
                                int capLen = (int)Math.Min(hdr.caplen, 65536u);
                                if (capLen >= 14)
                                {
                                    Marshal.Copy(dataPtr, buf, 0, capLen);
                                    if (dlt == 1) // DLT_EN10MB (Ethernet)
                                    {
                                        ProcessEthernetFrame(buf, capLen, (int)hdr.len);
                                    }
                                }
                            }
                        }
                        return;
                    }
                }
                catch { }
            }

            // 2. Fallback to Windows Native Raw Socket Promiscuous Mode (SIO_RCVALL)
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !string.IsNullOrEmpty(ActiveAdapter.Ip))
            {
                try
                {
                    var sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                    sock.Bind(new IPEndPoint(IPAddress.Parse(ActiveAdapter.Ip), 0));
                    sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                    byte[] inValue = new byte[] { 1, 0, 0, 0 }; // RCVALL_ON
                    byte[] outValue = new byte[4];
                    sock.IOControl(IOControlCode.ReceiveAll, inValue, outValue);
                    _activeRawSocket = sock;
                    CaptureEngineName = "Windows 原生 RawSocket 混杂抓包引擎 (SIO_RCVALL + ARP表监控)";

                    byte[] buf = new byte[65536];
                    while (_running && gen == _captureGeneration)
                    {
                        int n = sock.Receive(buf);
                        if (n >= 20)
                        {
                            ProcessIpv4Packet(buf, 0, n, n, "", "", false);
                        }
                    }
                    return;
                }
                catch (Exception ex)
                {
                    CaptureEngineName = "主动探测 + 系统ARP/流量表模式 (提示: 以管理员身份运行或安装Npcap可启用底层抓包: " + ex.Message + ")";
                }
            }
            else
            {
                CaptureEngineName = "主动局域网探测 + 系统ARP表监控模式 (未检测到管理员RawSocket或Npcap)";
            }
        }

        private void ProcessEthernetFrame(byte[] buf, int capLen, int wireLen)
        {
            if (capLen < 14) return;
            InspectFrameForDualNic(ActiveAdapter.Id, buf, capLen, wireLen);
            string dstMac = FormatMac(buf, 0);
            string srcMac = FormatMac(buf, 6);
            bool isBcast = (buf[0] & 0x01) != 0; // Broadcast or Multicast bit

            int offset = 12;
            ushort etherType = (ushort)((buf[offset] << 8) | buf[offset + 1]);
            offset += 2;

            // Handle 802.1Q VLAN tag
            if (etherType == 0x8100 && capLen >= offset + 4)
            {
                etherType = (ushort)((buf[offset + 2] << 8) | buf[offset + 3]);
                offset += 4;
            }

            if (etherType == 0x0806) // ARP
            {
                ProcessArpPacket(buf, offset, capLen - offset, srcMac, dstMac, wireLen);
            }
            else if (etherType == 0x0800) // IPv4
            {
                ProcessIpv4Packet(buf, offset, capLen - offset, wireLen, srcMac, dstMac, isBcast);
            }
        }

        private void ProcessArpPacket(byte[] buf, int offset, int len, string ethSrcMac, string ethDstMac, int wireLen)
        {
            if (len < 28) return;
            ushort op = (ushort)((buf[offset + 6] << 8) | buf[offset + 7]);
            string senderMac = FormatMac(buf, offset + 8);
            string senderIp = string.Format("{0}.{1}.{2}.{3}", buf[offset + 14], buf[offset + 15], buf[offset + 16], buf[offset + 17]);
            string targetIp = string.Format("{0}.{1}.{2}.{3}", buf[offset + 24], buf[offset + 25], buf[offset + 26], buf[offset + 27]);

            Interlocked.Increment(ref TotalCapturedPackets);
            Interlocked.Add(ref TotalCapturedBytes, wireLen);

            if (senderIp != "0.0.0.0")
            {
                var host = GetOrAddHost(senderIp, senderMac);
                Interlocked.Increment(ref host.TotalTxPkts);
                Interlocked.Add(ref host.TotalTxBytes, wireLen);
                Interlocked.Increment(ref host.WinTxPkts);
                Interlocked.Add(ref host.WinTxBytes, wireLen);
                Interlocked.Increment(ref host.BroadcastPkts);
                Interlocked.Increment(ref host.WinBcastPkts);

                if (op == 1) // ARP Request
                {
                    Interlocked.Increment(ref host.ArpReqPkts);
                    Interlocked.Increment(ref host.WinArpReqPkts);
                    host.AddActivity("ARP请求 -> " + targetIp);
                }
                else if (op == 2) // ARP Reply
                {
                    Interlocked.Increment(ref host.ArpReplyPkts);
                }
            }
        }

        private void ProcessIpv4Packet(byte[] buf, int offset, int len, int wireLen, string srcMac, string dstMac, bool isL2Bcast)
        {
            if (len < 20) return;
            byte verIhl = buf[offset];
            if ((verIhl >> 4) != 4) return;
            int ihl = (verIhl & 0x0F) * 4;
            if (ihl < 20 || len < ihl) return;

            byte proto = buf[offset + 9];
            ushort ipId = (ushort)((buf[offset + 4] << 8) | buf[offset + 5]);
            int payloadOffset0 = offset + ihl;
            int payloadLen0 = len - ihl;
            if (ipId != 0 || proto == 6)
            {
                uint sIpU = ((uint)buf[offset + 12] << 24) | ((uint)buf[offset + 13] << 16) | ((uint)buf[offset + 14] << 8) | buf[offset + 15];
                uint dIpU = ((uint)buf[offset + 16] << 24) | ((uint)buf[offset + 17] << 16) | ((uint)buf[offset + 18] << 8) | buf[offset + 19];
                uint t4 = payloadLen0 >= 4 ? (((uint)buf[payloadOffset0] << 24) | ((uint)buf[payloadOffset0 + 1] << 16) | ((uint)buf[payloadOffset0 + 2] << 8) | buf[payloadOffset0 + 3]) : 0;
                uint t8 = payloadLen0 >= 8 ? (((uint)buf[payloadOffset0 + 4] << 24) | ((uint)buf[payloadOffset0 + 5] << 16) | ((uint)buf[payloadOffset0 + 6] << 8) | buf[payloadOffset0 + 7]) : 0;
                ulong sig = ((ulong)sIpU << 32) ^ dIpU ^ ((ulong)proto << 48) ^ ((ulong)ipId << 16) ^ ((ulong)wireLen << 4) ^ ((ulong)t4 << 20) ^ t8;
                if (IsMirrorDuplicatePacket(sig)) return;
            }

            string srcIp = string.Format("{0}.{1}.{2}.{3}", buf[offset + 12], buf[offset + 13], buf[offset + 14], buf[offset + 15]);
            string dstIp = string.Format("{0}.{1}.{2}.{3}", buf[offset + 16], buf[offset + 17], buf[offset + 18], buf[offset + 19]);

            bool isIpBcast = isL2Bcast || buf[offset + 19] == 255 || (buf[offset + 16] >= 224 && buf[offset + 16] <= 239);

            Interlocked.Increment(ref TotalCapturedPackets);
            Interlocked.Add(ref TotalCapturedBytes, wireLen);

            HostStats srcHost = null;
            HostStats dstHost = null;

            bool srcInLan = IsInCurrentSubnet(srcIp);
            bool dstInLan = IsInCurrentSubnet(dstIp);

            // Only add a host to LAN table if it is in the active subnet, OR if it is sending L2/IP broadcast on this physical LAN (and not belonging to another virtual NIC on this machine)
            if (srcIp != "0.0.0.0" && (srcInLan || (isIpBcast && IsPrivateOrLocalIp(srcIp) && !IsInOtherLocalAdapterSubnet(srcIp))))
            {
                srcHost = GetOrAddHost(srcIp, srcMac);
                Interlocked.Increment(ref srcHost.TotalTxPkts);
                Interlocked.Add(ref srcHost.TotalTxBytes, wireLen);
                Interlocked.Increment(ref srcHost.WinTxPkts);
                Interlocked.Add(ref srcHost.WinTxBytes, wireLen);
                if (isIpBcast)
                {
                    Interlocked.Increment(ref srcHost.BroadcastPkts);
                    Interlocked.Increment(ref srcHost.WinBcastPkts);
                }
            }

            if (dstInLan && !isIpBcast)
            {
                dstHost = GetOrAddHost(dstIp, dstMac);
                Interlocked.Increment(ref dstHost.TotalRxPkts);
                Interlocked.Add(ref dstHost.TotalRxBytes, wireLen);
                Interlocked.Increment(ref dstHost.WinRxPkts);
                Interlocked.Add(ref dstHost.WinRxBytes, wireLen);
            }

            int payloadOffset = offset + ihl;
            int payloadLen = len - ihl;

            // Record active topology link for LAN-to-LAN or LAN-to-WAN traffic (skip tiny NetBIOS 137 discovery probes)
            bool isNetBiosProbe = false;
            if (proto == 17 && payloadLen >= 4)
            {
                ushort sp = (ushort)((buf[payloadOffset] << 8) | buf[payloadOffset + 1]);
                ushort dp = (ushort)((buf[payloadOffset + 2] << 8) | buf[payloadOffset + 3]);
                if (sp == 137 || dp == 137) isNetBiosProbe = true;
            }

            if (!isIpBcast && !isNetBiosProbe && srcIp != "0.0.0.0" && dstIp != "0.0.0.0")
            {
                if (srcInLan && dstInLan && srcIp != dstIp)
                {
                    RecordLink(srcIp, dstIp, proto == 6 ? "TCP内网互访" : (proto == 17 ? "UDP内网互访" : "ICMP"), wireLen);
                }
                else if (srcInLan && !dstInLan && !string.IsNullOrEmpty(ActiveAdapter.Gateway))
                {
                    RecordLink(srcIp, ActiveAdapter.Gateway, "外网通信", wireLen);
                }
                else if (!srcInLan && dstInLan && !string.IsNullOrEmpty(ActiveAdapter.Gateway))
                {
                    RecordLink(ActiveAdapter.Gateway, dstIp, "外网下行", wireLen);
                }
            }

            if (proto == 6 && payloadLen >= 20) // TCP
            {
                ProcessTcp(buf, payloadOffset, payloadLen, srcIp, dstIp, srcHost, dstHost);
            }
            else if (proto == 17 && payloadLen >= 8) // UDP
            {
                ProcessUdp(buf, payloadOffset, payloadLen, srcIp, dstIp, srcMac, srcHost, dstHost);
            }
        }

        private void ProcessTcp(byte[] buf, int offset, int len, string srcIp, string dstIp, HostStats srcHost, HostStats dstHost)
        {
            ushort srcPort = (ushort)((buf[offset] << 8) | buf[offset + 1]);
            ushort dstPort = (ushort)((buf[offset + 2] << 8) | buf[offset + 3]);
            uint seq = ((uint)buf[offset + 4] << 24) | ((uint)buf[offset + 5] << 16) | ((uint)buf[offset + 6] << 8) | buf[offset + 7];
            int dataOff = ((buf[offset + 12] >> 4) & 0x0F) * 4;
            byte flags = buf[offset + 13];
            ushort win = (ushort)((buf[offset + 14] << 8) | buf[offset + 15]);

            bool syn = (flags & 0x02) != 0;
            bool ack = (flags & 0x10) != 0;
            bool rst = (flags & 0x04) != 0;
            bool fin = (flags & 0x01) != 0;

            int tcpDataLen = len > dataOff ? len - dataOff : 0;

            if (srcHost != null)
            {
                bool dstIsLan = IsInCurrentSubnet(dstIp);
                bool involvesProbeWeb = (srcPort == 8088 || dstPort == 8088);
                bool countForLanLink = dstIsLan && !involvesProbeWeb;

                Interlocked.Increment(ref srcHost.TcpTotalPkts);
                if (countForLanLink) Interlocked.Increment(ref srcHost.LanTcpTotalPkts);
                if (syn && !ack)
                {
                    Interlocked.Increment(ref srcHost.SynPkts);
                    Interlocked.Increment(ref srcHost.WinSynPkts);
                    if (IsInCurrentSubnet(dstIp) && dstIp != ActiveAdapter.Gateway)
                    {
                        srcHost.RecentSynTargets[dstIp + ":" + dstPort] = DateTime.Now;
                    }
                    srcHost.AddActivity("TCP -> " + dstIp + ":" + dstPort);
                }
                if (rst)
                {
                    Interlocked.Increment(ref srcHost.RstPkts);
                    Interlocked.Increment(ref srcHost.WinRstPkts);
                }
                if (win == 0 && !rst && !syn && !fin)
                {
                    Interlocked.Increment(ref srcHost.TcpZeroWinPkts);
                }

                // Lightweight TCP Retransmission detection for data packets (separate LAN physical link vs WAN)
                if (tcpDataLen > 0 && !involvesProbeWeb)
                {
                    ulong flowKey = ComputeFlowKey(srcIp, dstIp, srcPort, dstPort);
                    uint prevMax;
                    if (srcHost.FlowMaxSeq.TryGetValue(flowKey, out prevMax))
                    {
                        int diff = (int)(seq - prevMax);
                        if (diff < 0 && diff > -65536)
                        {
                            Interlocked.Increment(ref srcHost.TcpRetransPkts);
                            if (countForLanLink) Interlocked.Increment(ref srcHost.LanTcpRetransPkts);
                        }
                        else if (diff > 0)
                        {
                            srcHost.FlowMaxSeq[flowKey] = seq;
                        }
                    }
                    else
                    {
                        if (srcHost.FlowMaxSeq.Count > 512) srcHost.FlowMaxSeq.Clear();
                        srcHost.FlowMaxSeq[flowKey] = seq;
                    }

                    // Extract TLS ClientHello SNI or HTTP Host
                    if (dstPort == 443 || dstPort == 8443)
                    {
                        string sni = TryExtractTlsSni(buf, offset + dataOff, tcpDataLen);
                        if (!string.IsNullOrEmpty(sni))
                        {
                            srcHost.AddActivity("HTTPS: " + sni);
                        }
                    }
                    else if (dstPort == 80 || dstPort == 8080)
                    {
                        string httpHost = TryExtractHttpHost(buf, offset + dataOff, tcpDataLen);
                        if (!string.IsNullOrEmpty(httpHost))
                        {
                            srcHost.AddActivity("HTTP: " + httpHost);
                        }
                    }
                }
            }
        }

        private void ProcessUdp(byte[] buf, int offset, int len, string srcIp, string dstIp, string srcMac, HostStats srcHost, HostStats dstHost)
        {
            ushort srcPort = (ushort)((buf[offset] << 8) | buf[offset + 1]);
            ushort dstPort = (ushort)((buf[offset + 2] << 8) | buf[offset + 3]);
            int udpDataOffset = offset + 8;
            int udpDataLen = len - 8;

            // 1. DHCP Server response check (Rogue DHCP detector! Server sends from port 67 to 68)
            if (srcPort == 67 && (dstPort == 68 || dstPort == 67) && udpDataLen >= 240)
            {
                ProcessDhcpPacket(buf, udpDataOffset, udpDataLen, srcIp, srcMac, srcHost);
            }

            // 2. DNS / mDNS query extraction (port 53 or 5353)
            if ((dstPort == 53 || dstPort == 5353 || srcPort == 5353) && udpDataLen >= 12)
            {
                string qname = TryExtractDnsQName(buf, udpDataOffset, udpDataLen);
                if (!string.IsNullOrEmpty(qname) && srcHost != null)
                {
                    Interlocked.Increment(ref srcHost.DnsQueryPkts);
                    if (dstPort == 5353 && qname.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                    {
                        string baseName = qname.Substring(0, qname.Length - 6);
                        if (!baseName.StartsWith("_") && !baseName.Contains("._tcp") && !baseName.Contains("._udp") && string.IsNullOrEmpty(srcHost.Hostname))
                        {
                            srcHost.Hostname = baseName;
                        }
                    }
                    else
                    {
                        srcHost.AddActivity("DNS: " + qname);
                    }
                }
            }
        }

        private void ProcessDhcpPacket(byte[] buf, int offset, int len, string srcIp, string srcMac, HostStats srcHost)
        {
            if (len < 240) return;
            byte op = buf[offset]; // 1 = BOOTREQUEST, 2 = BOOTREPLY (Offer / ACK)
            if (op != 2) return;

            string offeredIp = string.Format("{0}.{1}.{2}.{3}", buf[offset + 16], buf[offset + 17], buf[offset + 18], buf[offset + 19]);
            if (srcHost != null)
            {
                Interlocked.Increment(ref srcHost.DhcpServerPkts);
                srcHost.AddActivity("DHCP分配 -> " + offeredIp);
            }

            // Check if this DHCP reply came from a non-gateway device!
            if (!string.IsNullOrEmpty(ActiveAdapter.Gateway) &&
                !string.Equals(srcIp, ActiveAdapter.Gateway, StringComparison.OrdinalIgnoreCase) &&
                srcIp != "0.0.0.0")
            {
                RaiseAlert(
                    "ROGUE_DHCP_" + srcIp,
                    "ROGUE_DHCP",
                    "critical",
                    "检测到私接路由器 / 非法 DHCP 服务器抢答！",
                    srcIp,
                    srcMac,
                    OuiDb.Lookup(srcMac),
                    string.Format("非网关设备 {0} ({1}) 正在向局域网广播发送 DHCP Offer/ACK 响应，试图向终端分配 IP 地址 {2}（主网关应为 {3}）。", srcIp, srcMac, offeredIp, ActiveAdapter.Gateway),
                    "内网有人将家用无线路由器的 LAN 口直接插进了局域网交换机，且未关闭其自带的 DHCP 服务。这会导致内网电脑拿到错误的网关和 DNS，出现间歇性断网或网速极慢。",
                    "1. 顺着该设备的 MAC 地址 (" + srcMac + ") 排查私接的小路由器；2. 拔掉插在它 LAN 口上的进线，改为插 WAN 口或将其设为 AP 模式（关闭 DHCP）。",
                    "进入维盟后台：【防御配置】->【防御二级路由】或【MAC地址过滤】临时封禁 " + srcMac + "；同时可在【网络配置】->【DHCP服务】中开启 DHCP 检测。",
                    "进入 TP-LINK 后台：【终端管理】找到 IP " + srcIp + " (" + srcMac + ") 点击【黑名单】一键拉黑，或在【安全管理】->【MAC地址过滤】中封禁该 MAC。"
                );
            }
        }

        private void TickerLoop()
        {
            while (_running)
            {
                Thread.Sleep(1000);
                if (IsPaused) continue;
                try
                {
                    double sumBps = 0;
                    double sumPps = 0;
                    double sumBcastPps = 0;

                    foreach (var kv in Hosts)
                    {
                        var h = kv.Value;
                        long txB = Interlocked.Exchange(ref h.WinTxBytes, 0);
                        long rxB = Interlocked.Exchange(ref h.WinRxBytes, 0);
                        long txP = Interlocked.Exchange(ref h.WinTxPkts, 0);
                        long rxP = Interlocked.Exchange(ref h.WinRxPkts, 0);
                        long bcP = Interlocked.Exchange(ref h.WinBcastPkts, 0);
                        long arpP = Interlocked.Exchange(ref h.WinArpReqPkts, 0);
                        long synP = Interlocked.Exchange(ref h.WinSynPkts, 0);
                        long rstP = Interlocked.Exchange(ref h.WinRstPkts, 0);

                        h.TxBps = txB;
                        h.RxBps = rxB;
                        double totBps = txB + rxB;
                        h.EwmaTotalBps = h.EwmaTotalBps <= 0 ? totBps : (h.EwmaTotalBps * 0.85 + totBps * 0.15);
                        h.Pps = txP + rxP;
                        h.BcastPps = bcP;
                        h.ArpPps = arpP;
                        h.SynRate = synP;

                        if (h.LanTcpTotalPkts >= 50)
                        {
                            h.RetransRatePct = Math.Round((double)h.LanTcpRetransPkts * 100.0 / h.LanTcpTotalPkts, 2);
                        }
                        else
                        {
                            h.RetransRatePct = 0;
                        }

                        sumBps += totBps;
                        sumPps += h.Pps;
                        sumBcastPps += bcP;

                        EvaluateHostAnomalies(h);
                    }

                    // Capture total goes at least to sumBps/2 (avoid double count for local-to-local)
                    CurrentTotalKBps = Math.Round(sumBps / 1024.0, 1);
                    CurrentTotalPps = sumPps;
                    CurrentBcastPps = sumBcastPps;

                    // Update per-NIC live stats & evaluate dual-NIC cross-wire leakage
                    foreach (var ns in NicStats.Values)
                    {
                        long wp = Interlocked.Exchange(ref ns.WinPkts, 0);
                        long wb = Interlocked.Exchange(ref ns.WinBytes, 0);
                        ns.Pps = wp;
                        ns.KBps = Math.Round(wb / 1024.0, 1);
                    }
                    EvaluateCrossWireLeak();

                    // Update active flow link rates and prune stale links (>45s)
                    var linkCutoff = DateTime.Now.AddSeconds(-45);
                    foreach (var lk in ActiveLinks.ToArray())
                    {
                        long wb = Interlocked.Exchange(ref lk.Value.WinBytes, 0);
                        lk.Value.KBps = Math.Round(wb / 1024.0, 1);
                        if (lk.Value.LastSeen < linkCutoff)
                        {
                            FlowLink _;
                            ActiveLinks.TryRemove(lk.Key, out _);
                        }
                    }

                    History.Enqueue(new TrafficPoint
                    {
                        Time = DateTime.Now.ToString("HH:mm:ss"),
                        TotalKBps = CurrentTotalKBps,
                        TotalPps = CurrentTotalPps,
                        BcastPps = CurrentBcastPps
                    });
                    while (History.Count > 60)
                    {
                        TrafficPoint _;
                        History.TryDequeue(out _);
                    }
                }
                catch { }
            }
        }

        private void EvaluateHostAnomalies(HostStats h)
        {
            // 1. Cross-Subnet / Foreign IP node on local LAN
            if (!h.IsLocalSubnet && IsPrivateOrLocalIp(h.Ip) && !h.Ip.StartsWith("169.254."))
            {
                RaiseAlert(
                    "CROSS_SUBNET_" + h.Ip,
                    "CROSS_SUBNET",
                    "critical",
                    "发现跨网段异常节点 (" + h.Ip + ")",
                    h.Ip,
                    h.Mac,
                    h.Vendor,
                    string.Format("当前局域网网段为 {0}，但在二层网络中检测到异网段节点 IP: {1}，MAC: {2} ({3})。", ActiveCidr, h.Ip, h.Mac, h.Vendor),
                    "通常是因为内网下级串联了未改为 AP 模式的小路由器（如默认 192.168.0.1 / 192.168.1.1），或某台设备手动配置了错误的静态 IP。这极易引发私接 DHCP 冲突或二层广播干扰。",
                    "1. 根据 MAC 地址 (" + h.Mac + ") 和厂商 (" + h.Vendor + ") 定位该设备；2. 若为下级家用路由器，关闭其 DHCP 并改为无线 AP 模式；若不用则可在主路由封禁其 MAC。",
                    "在维盟路由器：【防御配置】->【ARP管理】->【ARP列表】核对该 MAC，并在【MAC地址过滤】中添加 " + h.Mac + " 进行阻断。",
                    "在 TP-LINK 路由器：【终端管理】找到 " + h.Ip + " (" + h.Mac + ") 点击右侧【黑名单】，或在【安全管理】->【MAC地址过滤】中禁止该 MAC。"
                );
            }

            // 2. ARP Spoofing / IP Conflict (Multiple MACs claiming the same IP)
            if (h.SeenMacs.Count > 1)
            {
                string macList = string.Join(", ", h.SeenMacs.Keys);
                RaiseAlert(
                    "ARP_CONFLICT_" + h.Ip,
                    "ARP_CONFLICT",
                    "critical",
                    "检测到 IP 地址冲突或 ARP 欺骗 (" + h.Ip + ")",
                    h.Ip,
                    h.Mac,
                    h.Vendor,
                    string.Format("IP 地址 {0} 在局域网中同时对应了多个不同的 MAC 地址: {1}。", h.Ip, macList),
                    "两台机器配置了相同的静态 IP，或内网存在私接 DHCP / ARP 欺骗攻击程序。如果冲突的 IP 是网关 (" + ActiveAdapter.Gateway + ")，会导致全网间歇性断网！",
                    "1. 检查上述 MAC 对应的终端，将静态 IP 改为自动获取 (DHCP)；2. 在主路由器上开启 IP-MAC 绑定与免费 ARP 广播防护。",
                    "进入维盟后台：【防御配置】->【ARP管理】->【ARP绑定】将正常设备的 IP 与 MAC 设为静态绑定，并在【ARP防御】开启自动发送免费 ARP。",
                    "进入 TP-LINK 后台：【安全管理】->【ARP防护】->【IP-MAC绑定】勾选正常设备一键导入绑定，并开启【ARP防护】。"
                );
            }

            // 3. Broadcast / ARP Scan Storm (skip probe's own physical IPs so self-discovery never self-alerts)
            if (!LocalHostIps.Contains(h.Ip) && (h.BcastPps >= 120 || h.ArpPps >= 60))
            {
                RaiseAlert(
                    "BCAST_STORM_" + h.Ip,
                    "BROADCAST_STORM",
                    "critical",
                    "检测到广播风暴 / 高频 ARP 扫描 (" + h.Ip + ")",
                    h.Ip,
                    h.Mac,
                    h.Vendor,
                    string.Format("节点 {0} ({1}) 当前每秒发送 {2:F0} 个广播包（其中 ARP 请求 {3:F0} 个/秒），远超正常局域网阈值。", h.Ip, h.Hostname, h.BcastPps, h.ArpPps),
                    "可能原因：① 下级交换机之间插错网线形成二层环路；② 该机器中了内网扫描木马或正在运行网段扫描工具；③ 网卡硬件故障持续发广播杂包，拖慢全网交换机转发。",
                    "1. 观察该主机近期活动: " + string.Join(" / ", h.RecentActivities) + "；2. 若为环路，逐一拔除下级交换机级联线测试；3. 若为单机异常，临时断开该主机网线并查杀进程。",
                    "进入维盟后台：【防御配置】->【DDOS防御】开启防扫描与广播抑制，或在【系统状态】->【主机监控】中将该主机临时设为禁止上网。",
                    "进入 TP-LINK 后台：【安全管理】->【攻击防护】开启防 Flood 与防扫描保护，或在【终端管理】将该设备临时拉入黑名单。"
                );
            }

            // 4. Sudden Traffic Burst (Bandwidth Hog)
            double totalMBps = (h.TxBps + h.RxBps) / (1024.0 * 1024.0);
            if (totalMBps >= 4.0 && (h.TxBps + h.RxBps) > Math.Max(h.EwmaTotalBps * 2.2, 4 * 1024 * 1024))
            {
                string acts = string.Join(", ", h.RecentActivities);
                RaiseAlert(
                    "TRAFFIC_BURST_" + h.Ip,
                    "TRAFFIC_BURST",
                    "warning",
                    string.Format("突发大流量尖峰: {0} ({1:F1} MB/s)", string.IsNullOrEmpty(h.Hostname) ? h.Ip : h.Hostname, totalMBps),
                    h.Ip,
                    h.Mac,
                    h.Vendor,
                    string.Format("节点 {0} 当前突发速率达 {1:F2} MB/s (上传 {2:F0} KB/s, 下载 {3:F0} KB/s)，近期通信目标: {4}。", h.Ip, totalMBps, h.TxBps / 1024.0, h.RxBps / 1024.0, string.IsNullOrEmpty(acts) ? "未捕获域名" : acts),
                    "单台主机进行多线程高速下载（如网盘、Steam、系统更新、视频缓存）或大文件传输。在未配置带宽控制 (QoS) 或下级串有百兆交换机/小路由时，会瞬间占满链路导致其他人卡顿。",
                    "1. 检查该主机是否在进行大流量下载；2. 在主路由器开启智能流控 / 带宽控制，限制单机最大可用带宽不超过总宽带的 50%~70%。",
                    "进入维盟后台：【智能流控】启用智能 QoS 流控，或对该 IP (" + h.Ip + ") 设置手动限速；若为迅雷等软件可在【P2P管理】中限制。",
                    "进入 TP-LINK 后台：【行为管控】->【带宽控制】启用带宽控制（如总带宽利用率达 80% 时生效），限制单 IP 最大上下行带宽。"
                );
            }

            // 5. Connection Flood / SYN Flood (P2P or Malware exhausting NAT sessions)
            if (h.SynRate >= 45)
            {
                RaiseAlert(
                    "CONN_FLOOD_" + h.Ip,
                    "CONN_FLOOD",
                    "warning",
                    string.Format("单机新建连接速率过高: {0} ({1:F0} 连接/秒)", h.Ip, h.SynRate),
                    h.Ip,
                    h.Mac,
                    h.Vendor,
                    string.Format("节点 {0} 每秒发起 {1:F0} 个新建 TCP SYN 连接（累计已捕获 {2} 个 SYN）。", h.Ip, h.SynRate, h.SynPkts),
                    "P2P 下载软件（迅雷、BT、PT、P2P 视频加速）或木马程序在短时间内发起数千个并发连接，极易把主路由器或上级光猫的 NAT 会话表打满，造成全网打不开网页（表现为能聊已连上的微信但打不开新网页）。",
                    "1. 关闭该电脑后台的 P2P 下载或加速进程；2. 强烈建议在路由器后台配置【单机最大连接数限制】（建议设为 1500~2000）。",
                    "进入维盟后台：【防御配置】->【连接限制】/【连接数设置】，将单机最大 TCP/UDP 联机数限制为 1500~2000。",
                    "进入 TP-LINK 后台：【行为管控】->【连接数限制】新增规则，限制内网地址组单机最大连接数为 1500~2000。"
                );
            }

            // 6. Internal LAN Port Scan
            if (h.RecentSynTargets.Count >= 20)
            {
                // Prune targets older than 30s
                var cutoff = DateTime.Now.AddSeconds(-30);
                foreach (var tk in h.RecentSynTargets.Keys.ToList())
                {
                    DateTime dt;
                    if (h.RecentSynTargets.TryGetValue(tk, out dt) && dt < cutoff)
                    {
                        DateTime _;
                        h.RecentSynTargets.TryRemove(tk, out _);
                    }
                }
                if (h.RecentSynTargets.Count >= 20)
                {
                    RaiseAlert(
                        "PORT_SCAN_" + h.Ip,
                        "PORT_SCAN",
                        "critical",
                        "检测到内网横向端口扫描行为 (" + h.Ip + ")",
                        h.Ip,
                        h.Mac,
                        h.Vendor,
                        string.Format("节点 {0} 在 30 秒内向局域网内部发起了 {1} 个不同目标 IP:端口 的连接探测，且伴随 {2} 个 TCP RST 拒绝响应。", h.Ip, h.RecentSynTargets.Count, h.RstPkts),
                        "该主机可能正在运行端口扫描工具，或感染了蠕虫/勒索病毒正在尝试向局域网其他机器（如 445/3389/22 端口）横向扩散。",
                        "立即核实该主机 (" + h.Ip + ") 使用者是否在做正常运维扫描；若非本人操作，请立即拔掉网线隔离并全盘杀毒！",
                        "进入维盟后台：【系统状态】->【主机监控】找到 " + h.Ip + " 立即点击禁止上网，并在【防御配置】开启访问控制阻断高危端口（135~139, 445）。",
                        "进入 TP-LINK 后台：【终端管理】找到 " + h.Ip + " 立即加入【黑名单】隔离，并在【行为管控】->【访问控制】封锁内网高危端口。"
                    );
                }
            }

            // 7. High LAN TCP Retransmission Rate (Actual packet loss on physical LAN cable/switch; excludes WAN & probe 8088 traffic)
            if (h.LanTcpTotalPkts >= 150 && h.LanTcpRetransPkts >= 10 && h.RetransRatePct >= 4.5)
            {
                RaiseAlert(
                    "HIGH_RETRANS_" + h.Ip,
                    "HIGH_RETRANSMIT",
                    "warning",
                    string.Format("内网物理链路丢包重传偏高: {0} (内网重传率 {1:F1}%)", h.Ip, h.RetransRatePct),
                    h.Ip,
                    h.Mac,
                    h.Vendor,
                    string.Format("节点 {0} 的局域网内网 TCP 报文总数 {1}，其中检出重传报文 {2} 个（内网重传率 {3:F1}%；已排除外网链路与探针管理端口干扰）。", h.Ip, h.LanTcpTotalPkts, h.LanTcpRetransPkts, h.RetransRatePct),
                    "正常局域网内网 TCP 重传率应低于 0.5%。重传率高说明数据包在局域网物理链路途中被丢弃，常见原因：① 该机器或上级交换机网线水晶头接触不良/线序劣化；② 链路中间串接了老旧百兆（100Mbps）小路由器（如 TL-WR886N）或百兆交换机导致端口缓冲溢出丢包。",
                    "1. 检查该设备到交换机的网线，以及网卡协商速率是否为 1.0 Gbps 全双工；2. 若下级串了百兆小路由器，建议更换为千兆交换机或千兆 AP。",
                    "在维盟后台：【系统维护】->【ping检测】测试到该内网主机的丢包情况，并检查对应 LAN 口物理连接。",
                    "在 TP-LINK 后台：检查该终端是否挂在百兆下级路由（如 TL-WR886N）后面，建议将重度用网电脑直接接在千兆交换机上。"
                );
            }
            else if (h.RetransRatePct < 2.5)
            {
                AnomalyAlert removed;
                Alerts.TryRemove("HIGH_RETRANS_" + h.Ip, out removed);
            }

            // 8. High TCP Zero Window Rate (Application receive buffer full / disk or CPU bottleneck on endpoint)
            double zeroWinPct = h.TcpTotalPkts >= 500 ? (h.TcpZeroWinPkts * 100.0 / h.TcpTotalPkts) : 0;
            if (h.TcpTotalPkts >= 500 && h.TcpZeroWinPkts >= 80 && zeroWinPct >= 3.0)
            {
                RaiseAlert(
                    "ZERO_WIN_" + h.Ip,
                    "TCP_ZERO_WINDOW",
                    "warning",
                    string.Format("主机接收缓冲区满 (TCP 零窗口占比 {1:F1}%): {0}", h.Ip, zeroWinPct),
                    h.Ip,
                    h.Mac,
                    h.Vendor,
                    string.Format("节点 {0} 在 {1} 个 TCP 报文中发出了 {2} 个 TCP Zero-Window（零窗口）通告（占比 {3:F1}%），并非网线丢包重传（重传率为 {4:F1}%）。", h.Ip, h.TcpTotalPkts, h.TcpZeroWinPkts, zeroWinPct, h.RetransRatePct),
                    "TCP 零窗口（Zero Window）不是网络丢包，而是指该主机的【应用程序或磁盘/CPU 处理不过来】，导致系统的 TCP 接收缓冲区被塞满，不得不通知对端暂停发包。",
                    "检查该主机 (" + h.Ip + ") 的 CPU 占用率、磁盘读写队列（如机械硬盘满载）或正在接收大量数据的服务进程状态。",
                    "网络层无需改动维盟路由器配置，重点排查该终端自身的 CPU 与磁盘 I/O 负载。",
                    "网络层无需改动 TP-LINK 路由器配置，重点排查该终端自身的 CPU 与磁盘 I/O 负载。"
                );
            }
        }

        private void HealthAndDiscoveryLoop()
        {
            int cycle = 0;
            while (_running)
            {
                if (IsPaused)
                {
                    Thread.Sleep(1000);
                    continue;
                }
                try
                {
                    // 0. If adapters were not ready at boot time, re-discover until active CIDR & adapter are ready
                    if (Adapters.Count == 0 || string.IsNullOrEmpty(ActiveCidr) || string.IsNullOrEmpty(ActiveAdapter.Id))
                    {
                        RefreshAdapters();
                        if (Adapters.Count > 0)
                        {
                            SelectBestAdapter(_preferredAdapterHint);
                            if (!string.IsNullOrEmpty(ActiveAdapter.Id))
                            {
                                RestartPacketCapture();
                            }
                        }
                    }

                    // 1. Check Gateway, DNS, and External WAN Latency & Loss
                    if (!string.IsNullOrEmpty(ActiveAdapter.Gateway))
                    {
                        GatewayLatencyMs = PingHost(ActiveAdapter.Gateway, 1000, out GatewayLossPct);
                    }
                    string dnsTarget = !string.IsNullOrEmpty(ActiveAdapter.Dns) ? ActiveAdapter.Dns : "223.5.5.5";
                    double dnsLoss;
                    DnsLatencyMs = PingHost(dnsTarget, 1200, out dnsLoss);

                    double wanLoss;
                    WanLatencyMs = PingHost("223.5.5.5", 1500, out wanLoss);
                    WanLossPct = wanLoss;

                    // Discover Hop-2 Upstream Router / Optical Modem (Double NAT detection)
                    if (cycle % 3 == 0)
                    {
                        ProbeUpstreamHop();
                    }
                    if (!string.IsNullOrEmpty(UpstreamGatewayIp))
                    {
                        double upLoss;
                        UpstreamLatencyMs = PingHost(UpstreamGatewayIp, 1000, out upLoss);
                    }

                    // Alert if Gateway or WAN is degraded
                    if (GatewayLatencyMs > 30 || GatewayLossPct >= 25)
                    {
                        RaiseAlert(
                            "GW_DEGRADED",
                            "GATEWAY_DEGRADED",
                            "critical",
                            string.Format("内网到主路由器延迟/丢包异常 ({0:F0}ms, 丢包 {1:F0}%)", GatewayLatencyMs, GatewayLossPct),
                            ActiveAdapter.Gateway,
                            "",
                            "主路由器",
                            string.Format("本机到内网网关 {0} 的 Ping 延迟为 {1:F1}ms，丢包率 {2:F0}%（正常局域网应 <2ms 且 0% 丢包）。", ActiveAdapter.Gateway, GatewayLatencyMs, GatewayLossPct),
                            "连到内网主路由器都已经开始高延迟或丢包，说明卡顿发生在【局域网内部】（如内网下级交换机环路、百兆级联口被占满、或路由器 CPU 100% 满载），而不是外网运营商故障。",
                            "1. 查看下方活跃节点列表中是否有某台机器正在突发满速下载或狂发广播包；2. 检查下级交换机指示灯是否在全口高频狂闪。",
                            "进入维盟后台：【系统状态】->【运行状态】查看路由器 CPU 负载，并在【主机监控】查看是谁占满了内网带宽或连接数。",
                            "进入 TP-LINK 后台：【运行状态】查看 CPU/内存使用率，并在【高级功能】->【IP流量统计】按发送/接收速率排序找出占网元凶。"
                        );
                    }
                    else if (WanLatencyMs > 180 || WanLossPct >= 50)
                    {
                        RaiseAlert(
                            "WAN_DEGRADED",
                            "WAN_DEGRADED",
                            "warning",
                            string.Format("内网正常，但外网宽带出口延迟高/丢包 ({0:F0}ms, 丢包 {1:F0}%)", WanLatencyMs, WanLossPct),
                            "223.5.5.5",
                            "",
                            "外网出口",
                            string.Format("内网网关 {0} 延迟仅 {1:F1}ms（内网畅通），但访问公网 223.5.5.5 延迟达 {2:F0}ms，丢包率 {3:F0}%。", ActiveAdapter.Gateway, GatewayLatencyMs, WanLatencyMs, WanLossPct),
                            "内网交换机到主路由器之间非常顺畅，瓶颈出在【主路由器 WAN 口以外】（如外网宽带被跑满、上级光猫 192.168.1.1 会话表过载、或运营商线路抖动）。",
                            "1. 检查主路由器 WAN 口总上下行带宽是否已达宽带上限；2. 重启上级光猫 (192.168.1.1) 或开启路由器带宽控制与连接数限制。",
                            "进入维盟后台：【系统状态】->【流量分析】查看 WAN1 口实时带宽，并在【智能流控】开启限速保护。",
                            "进入 TP-LINK 后台：【运行状态】查看 WAN1 实时上下行速度，并在【行为管控】开启带宽控制与连接数限制。"
                        );
                    }

                    // 2. Parse system ARP table (`arp -a`) every cycle to catch all L2 neighbors even without Npcap
                    ReadSystemArpTable();

                    // 3. In L2 mirror mode, passive capture sees all LAN traffic; only sweep once at startup to avoid self-generated ARP noise
                    if (cycle == 0 || (!ActiveAdapter.IsMirrorCandidate && cycle % 12 == 0))
                    {
                        Task.Run(() => SweepCurrentSubnet());
                    }
                    cycle++;
                }
                catch { }
                Thread.Sleep(5000);
            }
        }

        public void ReadSystemArpTable()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "arp",
                    Arguments = "-a",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(3000);
                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    // Determine physical interface IP to filter `arp -a` sections (avoid reading ZeroTier / VPN sections when active NIC is IP-less mirror)
                    string targetArpIfaceIp = !string.IsNullOrEmpty(ActiveAdapter.Ip)
                        ? ActiveAdapter.Ip
                        : (Adapters.FirstOrDefault(a => !string.IsNullOrEmpty(a.Ip) && string.Equals(a.Cidr, ActiveCidr, StringComparison.OrdinalIgnoreCase))?.Ip
                           ?? Adapters.FirstOrDefault(a => !string.IsNullOrEmpty(a.Ip))?.Ip
                           ?? "");
                    bool inActiveInterfaceSection = false;

                    foreach (var line in lines)
                    {
                        string trimmed = line.Trim();
                        // Windows arp -a groups by "接口: 10.0.0.179 --- 0x5" or "Interface: 10.0.0.179 --- 0x5"
                        if (trimmed.Contains("---") && (trimmed.Contains(":") || trimmed.StartsWith("Interface") || trimmed.StartsWith("接口")))
                        {
                            inActiveInterfaceSection = !string.IsNullOrEmpty(targetArpIfaceIp) && trimmed.Contains(targetArpIfaceIp + " ");
                            continue;
                        }
                        if (!inActiveInterfaceSection) continue;

                        var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2)
                        {
                            string ip = "";
                            string mac = "";
                            if (parts[0].StartsWith("(") || parts[0] == "?")
                            {
                                if (parts.Length >= 4 && parts[1].StartsWith("(") && parts[1].EndsWith(")"))
                                {
                                    ip = parts[1].Trim('(', ')');
                                    mac = parts[3];
                                }
                            }
                            else
                            {
                                ip = parts[0];
                                mac = parts[1];
                            }

                            IPAddress parsed;
                            if (IPAddress.TryParse(ip, out parsed) && IsValidUnicastMac(mac))
                            {
                                uint ipU = IpToUint(ip);
                                if (ipU == (SubnetNetUint | ~SubnetMaskUint)) continue; // skip subnet broadcast
                                if (ip.EndsWith(".255") || ip == "25.255.255.254") continue;
                                if (IsInOtherLocalAdapterSubnet(ip)) continue;
                                GetOrAddHost(ip, NormalizeMac(mac));
                            }
                        }
                    }
                }
            }
            catch { }
        }

        public bool IsInOtherLocalAdapterSubnet(string ip)
        {
            if (IsInCurrentSubnet(ip)) return false;
            uint u = IpToUint(ip);
            if (u == 0) return false;
            foreach (var cid in IgnoredLocalSubnets)
            {
                uint netU, maskU;
                ParseCidr(cid, out netU, out maskU);
                if (netU != 0 && maskU != 0 && (u & maskU) == netU) return true;
            }
            foreach (var a in Adapters)
            {
                if (a.Id == ActiveAdapter.Id || string.IsNullOrEmpty(a.Cidr)) continue;
                uint netU, maskU;
                ParseCidr(a.Cidr, out netU, out maskU);
                if (netU != 0 && maskU != 0 && (u & maskU) == netU) return true;
            }
            return false;
        }

        public void SweepCurrentSubnet()
        {
            if (SubnetNetUint == 0 || SubnetMaskUint == 0) return;
            uint hostCount = ~SubnetMaskUint;
            if (hostCount > 512) hostCount = 254; // cap sweep to /24 around local IP

            uint baseIp = SubnetNetUint;
            if (~SubnetMaskUint > 255 && !string.IsNullOrEmpty(ActiveAdapter.Ip))
            {
                baseIp = IpToUint(ActiveAdapter.Ip) & 0xFFFFFF00u;
                hostCount = 254;
            }

            // Gentle paced sweep (~25ms per IP) so probe never causes ARP bursts on mirror port
            for (int i = 1; i < (int)hostCount; i++)
            {
                if (!_running || IsPaused) break;
                string targetIp = UintToIp(baseIp + (uint)i);
                try
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        byte[] macBuf = new byte[6];
                        int len = macBuf.Length;
                        uint dest = BitConverter.ToUInt32(IPAddress.Parse(targetIp).GetAddressBytes(), 0);
                        int res = NativeWin.SendARP(dest, 0, macBuf, ref len);
                        if (res == 0 && len == 6)
                        {
                            string mac = FormatMac(macBuf);
                            if (IsValidUnicastMac(mac))
                            {
                                GetOrAddHost(targetIp, mac);
                            }
                        }
                        Thread.Sleep(25);
                    }
                    else
                    {
                        using (var ping = new Ping())
                        {
                            var reply = ping.Send(targetIp, 350);
                            if (reply != null && reply.Status == IPStatus.Success)
                            {
                                var h = GetOrAddHost(targetIp, "");
                                h.LastPingMs = reply.RoundtripTime;
                            }
                        }
                    }
                }
                catch { }
            }

            // Resolve hostnames for discovered hosts missing a hostname (NetBIOS UDP 137 + Reverse DNS)
            foreach (var h in Hosts.Values)
            {
                if (string.IsNullOrEmpty(h.Hostname))
                {
                    string nbName = QueryNetBiosName(h.Ip);
                    if (!string.IsNullOrEmpty(nbName))
                    {
                        h.Hostname = nbName;
                        continue;
                    }
                    try
                    {
                        var entry = Dns.GetHostEntry(h.Ip);
                        if (entry != null && !string.IsNullOrEmpty(entry.HostName) && entry.HostName != h.Ip)
                        {
                            h.Hostname = entry.HostName.Split('.')[0];
                        }
                    }
                    catch { }
                }
            }
        }

        private void ProbeUpstreamHop()
        {
            try
            {
                using (var p = new Ping())
                {
                    byte[] data = Encoding.ASCII.GetBytes("LanGuardianHopProbe");
                    var opts = new PingOptions(2, true);
                    var r = p.Send("223.5.5.5", 1200, data, opts);
                    if (r != null && (r.Status == IPStatus.TtlExpired || r.Status == IPStatus.Success) && r.Address != null)
                    {
                        string hopIp = r.Address.ToString();
                        if (!string.IsNullOrEmpty(hopIp) && hopIp != "0.0.0.0" && hopIp != ActiveAdapter.Gateway && hopIp != "223.5.5.5")
                        {
                            UpstreamGatewayIp = hopIp;
                        }
                    }
                }
            }
            catch { }
        }

        private static string QueryNetBiosName(string ip)
        {
            try
            {
                using (var udp = new UdpClient())
                {
                    udp.Client.ReceiveTimeout = 300;
                    udp.Client.SendTimeout = 300;
                    // Standard 50-byte NetBIOS Node Status Request (NBSTAT *)
                    byte[] req = new byte[] {
                        0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
                        0x00, 0x21, 0x00, 0x01
                    };
                    var ep = new IPEndPoint(IPAddress.Parse(ip), 137);
                    udp.Send(req, req.Length, ep);
                    IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    byte[] resp = udp.Receive(ref remote);
                    if (resp != null && resp.Length > 57)
                    {
                        int numNames = resp[56];
                        int pos = 57;
                        for (int i = 0; i < numNames && pos + 18 <= resp.Length; i++)
                        {
                            string name = Encoding.ASCII.GetString(resp, pos, 15).Trim();
                            byte type = resp[pos + 15];
                            byte flags = resp[pos + 16];
                            bool isGroup = (flags & 0x80) != 0;
                            if (!isGroup && (type == 0x00 || type == 0x20) && !string.IsNullOrEmpty(name) && !name.StartsWith("__"))
                            {
                                return name;
                            }
                            pos += 18;
                        }
                    }
                }
            }
            catch { }
            return "";
        }

        public void RecordLink(string srcIp, string dstIp, string label, int bytes)
        {
            string a = string.CompareOrdinal(srcIp, dstIp) <= 0 ? srcIp : dstIp;
            string b = string.CompareOrdinal(srcIp, dstIp) <= 0 ? dstIp : srcIp;
            string key = a + "<->" + b;
            var link = ActiveLinks.GetOrAdd(key, k => new FlowLink
            {
                Key = k,
                SrcIp = a,
                DstIp = b,
                Label = label,
                LastSeen = DateTime.Now
            });
            link.LastSeen = DateTime.Now;
            if (!string.IsNullOrEmpty(label)) link.Label = label;
            Interlocked.Add(ref link.WinBytes, bytes);
            Interlocked.Add(ref link.TotalBytes, bytes);
        }

        private void EvaluateCrossWireLeak()
        {
            var nics = NicStats.Values.ToList();
            if (nics.Count < 2) return;
            var a = nics[0];
            var b = nics[1];

            // Determine primary observed /24 subnet on each NIC
            string subA = a.ObservedSubnets.OrderByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault() ?? a.Cidr;
            string subB = b.ObservedSubnets.OrderByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault() ?? b.Cidr;
            DualNicSameSegment = !string.IsNullOrEmpty(subA) && string.Equals(subA, subB, StringComparison.OrdinalIgnoreCase);

            var shared = new List<string>();
            foreach (var mac in a.SeenMacToIp.Keys)
            {
                if (b.SeenMacToIp.ContainsKey(mac) && !LocalHostMacs.Contains(mac))
                {
                    string ipA = a.SeenMacToIp[mac];
                    string ipB = b.SeenMacToIp[mac];
                    string label = mac + (!string.IsNullOrEmpty(ipA) ? (" (" + ipA + ")") : (!string.IsNullOrEmpty(ipB) ? (" (" + ipB + ")") : ""));
                    shared.Add(label);
                }
            }
            CrossWireSharedMacs = shared;

            // Only raise critical CROSS_WIRE_LEAK if NICs belong to different physical subnets OR user explicitly enabled isolated cross-wire check
            bool shouldAlert = (!DualNicSameSegment || IsolateCrossWireCheck) && (CrossWireSyncHits >= 3 || shared.Count >= 1);
            if (shouldAlert)
            {
                string sample = string.Join(", ", shared.Take(5));
                RaiseAlert(
                    "CROSS_WIRE_LEAK",
                    "CROSS_WIRE_LEAK",
                    "critical",
                    string.Format("检测到双物理网段串线 / 二层泄露！(同帧碰撞 {0} 次, 跨接设备 {1} 台)", CrossWireSyncHits, shared.Count),
                    a.Name + " <-> " + b.Name,
                    "",
                    "双网段串线",
                    string.Format("物理网卡 [{0}] (网段 {1}) 与 [{2}] (网段 {3}) 同时捕获到了相同的二层流量：200ms 内同步广播帧碰撞 {4} 次，双边同时现身的非本机 MAC 共 {5} 个：{6}。",
                        a.Name, string.IsNullOrEmpty(subA) ? "未知" : subA,
                        b.Name, string.IsNullOrEmpty(subB) ? "未知" : subB,
                        CrossWireSyncHits, shared.Count, string.IsNullOrEmpty(sample) ? "见同步广播帧" : sample),
                    "两个本应物理隔离的局域网之间存在二层串通，常见原因：① 有人误用网线将两套网络的交换机直接插在一起；② 某台无线 AP/路由器同时桥接了两个网段；③ 某台双网卡终端开启了 Windows 网桥。",
                    "1. 核对上述双边同时现身的 MAC 对应设备位置；2. 逐一拔除两套核心交换机上的可疑级联线，观察同帧碰撞次数是否停止增长；3. 若当前两网卡本就是接在同一台路由器的主口+镜像口，请关闭顶部【物理隔离串线检测】开关。",
                    "进入维盟后台：【防御配置】->【ARP列表】查对上述 MAC 所在接口并排查物理网线。",
                    "进入 TP-LINK 后台：【终端管理】查找上述 MAC 对应终端并核实交换机级联口。"
                );
            }
            else
            {
                AnomalyAlert removed;
                Alerts.TryRemove("CROSS_WIRE_LEAK", out removed);
            }
        }

        public string InferRole(HostStats h)
        {
            if (!h.IsLocalSubnet) return "rogue";
            if (h.IsGateway || string.Equals(h.Ip, ActiveAdapter.Gateway, StringComparison.OrdinalIgnoreCase)) return "gateway";
            if (LocalHostIps.Contains(h.Ip) || string.Equals(h.Ip, ActiveAdapter.Ip, StringComparison.OrdinalIgnoreCase)) return "probe";

            string v = (h.Vendor ?? "").ToUpperInvariant();
            string n = (h.Hostname ?? "").ToUpperInvariant();

            if (v.Contains("QNAP") || v.Contains("SYNOLOGY") || v.Contains("NAS") || n.Contains("NAS")) return "nas";
            if (v.Contains("NETGEAR") || v.Contains("网件") || v.Contains("TP-LINK") || v.Contains("WAYOS") || n.Contains("WNDR") || n.Contains("TL-W")) return "netdev";
            if (v.Contains("创米") || v.Contains("领普") || v.Contains("海康") || n.Contains("CAMERA") || n.Contains("DOORBELL") || n.Contains("IPC")) return "camera";
            if (v.Contains("移动终端") || v.Contains("小米") || v.Contains("华为") || n.Contains("REDMI") || n.Contains("XIAOMI") || n.Contains("OPPO") || n.Contains("IPHONE")) return "mobile";
            return "pc";
        }

        private double PingHost(string ip, int timeoutMs, out double lossPct)
        {
            lossPct = 0;
            int ok = 0;
            long totalMs = 0;
            int tries = 2;
            for (int i = 0; i < tries; i++)
            {
                try
                {
                    using (var p = new Ping())
                    {
                        var r = p.Send(ip, timeoutMs);
                        if (r != null && r.Status == IPStatus.Success)
                        {
                            ok++;
                            totalMs += r.RoundtripTime;
                        }
                    }
                }
                catch { }
            }
            lossPct = (tries - ok) * 100.0 / tries;
            return ok > 0 ? (double)totalMs / ok : -1;
        }

        public HostStats GetOrAddHost(string ip, string mac)
        {
            string normMac = NormalizeMac(mac);
            var h = Hosts.GetOrAdd(ip, k => new HostStats
            {
                Ip = k,
                FirstSeen = DateTime.Now,
                LastSeen = DateTime.Now,
                IsLocalSubnet = IsInCurrentSubnet(k),
                IsGateway = string.Equals(k, ActiveAdapter.Gateway, StringComparison.OrdinalIgnoreCase)
            });

            h.LastSeen = DateTime.Now;
            h.IsLocalSubnet = IsInCurrentSubnet(ip);
            bool isGwHost = h.IsGateway || string.Equals(ip, ActiveAdapter.Gateway, StringComparison.OrdinalIgnoreCase);
            if (IsValidUnicastMac(normMac))
            {
                if (isGwHost)
                {
                    GatewayMac = normMac;
                }
                // In port-mirroring mode, router-forwarded L3 packets carry the gateway MAC; do not attribute them to LAN hosts
                bool isForeignGwMac = !isGwHost && !string.IsNullOrEmpty(GatewayMac) &&
                    string.Equals(normMac, GatewayMac, StringComparison.OrdinalIgnoreCase);
                if (!isForeignGwMac)
                {
                    h.Mac = normMac;
                    h.Vendor = OuiDb.Lookup(normMac);
                    // Only record MAC for ARP conflict check if this IP is in our local subnet
                    if (h.IsLocalSubnet)
                    {
                        h.SeenMacs[normMac] = DateTime.Now;
                    }
                }
            }
            return h;
        }

        private void RaiseAlert(string id, string code, string severity, string title, string ip, string mac, string vendor, string evidence, string cause, string fixGen, string fixWayos, string fixTplink)
        {
            Alerts.AddOrUpdate(id,
                k => new AnomalyAlert
                {
                    Id = id,
                    Code = code,
                    Severity = severity,
                    Title = title,
                    TargetIp = ip,
                    TargetMac = mac,
                    TargetVendor = vendor,
                    Evidence = evidence,
                    Cause = cause,
                    FixGeneral = fixGen,
                    FixWayOS = fixWayos,
                    FixTpLink = fixTplink,
                    FirstTime = DateTime.Now,
                    LastTime = DateTime.Now,
                    Count = 1
                },
                (k, old) =>
                {
                    old.LastTime = DateTime.Now;
                    old.Count++;
                    old.Evidence = evidence;
                    if (!string.IsNullOrEmpty(mac)) old.TargetMac = mac;
                    if (!string.IsNullOrEmpty(vendor)) old.TargetVendor = vendor;
                    return old;
                });
        }

        // Helpers
        private static string TryExtractDnsQName(byte[] buf, int offset, int len)
        {
            try
            {
                if (len < 16) return "";
                ushort qdcount = (ushort)((buf[offset + 4] << 8) | buf[offset + 5]);
                if (qdcount == 0 || qdcount > 10) return "";
                int pos = offset + 12;
                int end = offset + len;
                var sb = new StringBuilder();
                int jumps = 0;
                while (pos < end && buf[pos] != 0 && jumps < 15)
                {
                    byte labelLen = buf[pos];
                    if ((labelLen & 0xC0) == 0xC0) break;
                    if (labelLen > 63 || pos + 1 + labelLen >= end) return "";
                    if (sb.Length > 0) sb.Append('.');
                    sb.Append(Encoding.ASCII.GetString(buf, pos + 1, labelLen));
                    pos += 1 + labelLen;
                    jumps++;
                }
                string d = sb.ToString();
                if (d.Length >= 4 && d.IndexOf('.') > 0 && !d.EndsWith(".arpa", StringComparison.OrdinalIgnoreCase))
                {
                    return d;
                }
            }
            catch { }
            return "";
        }

        private static string TryExtractTlsSni(byte[] buf, int offset, int len)
        {
            try
            {
                // TLS Handshake record: 0x16, version 0x0301..0x0303, Handshake type 0x01 (ClientHello)
                if (len < 45 || buf[offset] != 0x16 || buf[offset + 5] != 0x01) return "";
                int pos = offset + 43; // Skip fixed ClientHello header
                int end = offset + len;
                if (pos >= end) return "";
                int sessionIdLen = buf[pos];
                pos += 1 + sessionIdLen;
                if (pos + 2 >= end) return "";
                int cipherLen = (buf[pos] << 8) | buf[pos + 1];
                pos += 2 + cipherLen;
                if (pos + 1 >= end) return "";
                int compLen = buf[pos];
                pos += 1 + compLen;
                if (pos + 2 >= end) return "";
                int extTotalLen = (buf[pos] << 8) | buf[pos + 1];
                pos += 2;
                int extEnd = Math.Min(end, pos + extTotalLen);
                while (pos + 4 < extEnd)
                {
                    int extType = (buf[pos] << 8) | buf[pos + 1];
                    int extLen = (buf[pos + 2] << 8) | buf[pos + 3];
                    pos += 4;
                    if (extType == 0 && pos + 5 < extEnd) // server_name extension
                    {
                        int nameType = buf[pos + 2];
                        int nameLen = (buf[pos + 3] << 8) | buf[pos + 4];
                        if (nameType == 0 && nameLen > 3 && nameLen < 120 && pos + 5 + nameLen <= extEnd)
                        {
                            return Encoding.ASCII.GetString(buf, pos + 5, nameLen);
                        }
                    }
                    pos += extLen;
                }
            }
            catch { }
            return "";
        }

        private static string TryExtractHttpHost(byte[] buf, int offset, int len)
        {
            try
            {
                int checkLen = Math.Min(len, 512);
                if (checkLen < 16) return "";
                string s = Encoding.ASCII.GetString(buf, offset, checkLen);
                if (!s.StartsWith("GET ") && !s.StartsWith("POST ") && !s.StartsWith("HEAD ")) return "";
                int idx = s.IndexOf("Host:", StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    int lineEnd = s.IndexOf('\r', idx);
                    if (lineEnd > idx + 5)
                    {
                        return s.Substring(idx + 5, lineEnd - (idx + 5)).Trim();
                    }
                }
            }
            catch { }
            return "";
        }

        private static ulong ComputeFlowKey(string srcIp, string dstIp, ushort srcPort, ushort dstPort)
        {
            ulong h1 = IpToUint(srcIp);
            ulong h2 = IpToUint(dstIp);
            return (h1 << 32) ^ (h2 << 16) ^ ((ulong)srcPort << 8) ^ dstPort;
        }

        public bool IsInCurrentSubnet(string ip)
        {
            if (SubnetNetUint == 0 || SubnetMaskUint == 0) return true;
            uint u = IpToUint(ip);
            return (u & SubnetMaskUint) == SubnetNetUint;
        }

        public static bool IsPrivateOrLocalIp(string ip)
        {
            uint u = IpToUint(ip);
            if (u == 0) return false;
            byte b1 = (byte)(u >> 24);
            byte b2 = (byte)((u >> 16) & 0xFF);
            if (b1 == 10) return true;
            if (b1 == 172 && b2 >= 16 && b2 <= 31) return true;
            if (b1 == 192 && b2 == 168) return true;
            if (b1 == 169 && b2 == 254) return true;
            return false;
        }

        public static uint IpToUint(string ip)
        {
            IPAddress addr;
            if (!IPAddress.TryParse(ip, out addr) || addr.AddressFamily != AddressFamily.InterNetwork) return 0;
            byte[] b = addr.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        public static string UintToIp(uint u)
        {
            return string.Format("{0}.{1}.{2}.{3}", (u >> 24) & 0xFF, (u >> 16) & 0xFF, (u >> 8) & 0xFF, u & 0xFF);
        }

        public static string ComputeCidr(string ip, string mask)
        {
            if (string.IsNullOrEmpty(ip)) return "10.0.0.0/24";
            uint ipU = IpToUint(ip);
            uint maskU = IpToUint(mask);
            if (maskU == 0) maskU = 0xFFFFFF00u;
            uint netU = ipU & maskU;
            int bits = 0;
            uint m = maskU;
            while ((m & 0x80000000u) != 0)
            {
                bits++;
                m <<= 1;
            }
            return UintToIp(netU) + "/" + bits;
        }

        public static void ParseCidr(string cidr, out uint netU, out uint maskU)
        {
            netU = 0;
            maskU = 0xFFFFFF00u;
            try
            {
                var parts = cidr.Split('/');
                uint ip = IpToUint(parts[0]);
                int bits = parts.Length > 1 ? int.Parse(parts[1]) : 24;
                maskU = bits <= 0 ? 0 : (0xFFFFFFFFu << (32 - bits));
                netU = ip & maskU;
            }
            catch { }
        }

        public static string FormatMac(byte[] b, int offset = 0)
        {
            if (b == null || b.Length < offset + 6) return "";
            return string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                b[offset], b[offset + 1], b[offset + 2], b[offset + 3], b[offset + 4], b[offset + 5]);
        }

        public static string NormalizeMac(string mac)
        {
            if (string.IsNullOrEmpty(mac)) return "";
            string s = mac.Trim().Replace("-", ":").ToUpperInvariant();
            var parts = s.Split(':');
            if (parts.Length == 6)
            {
                for (int i = 0; i < 6; i++)
                {
                    if (parts[i].Length == 1) parts[i] = "0" + parts[i];
                }
                return string.Join(":", parts);
            }
            return s;
        }

        public static bool IsValidUnicastMac(string mac)
        {
            if (string.IsNullOrEmpty(mac) || mac.Length < 11) return false;
            string n = NormalizeMac(mac);
            if (n == "00:00:00:00:00:00" || n == "FF:FF:FF:FF:FF:FF") return false;
            if (n.StartsWith("01:00:5E") || n.StartsWith("33:33:")) return false;
            return n.Length == 17;
        }
    }

    public class WebDashboardServer
    {
        private readonly MonitorEngine _engine;
        private readonly int _port;
        private TcpListener _listener;

        public WebDashboardServer(MonitorEngine engine, int port)
        {
            _engine = engine;
            _port = port;
        }

        public void Start()
        {
            _listener = new TcpListener(IPAddress.Any, _port);
            _listener.Start();
            Task.Run(() => AcceptLoop());
        }

        private async Task AcceptLoop()
        {
            while (true)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    var _ = Task.Run(() => HandleClient(client));
                }
                catch { }
            }
        }

        private void HandleClient(TcpClient client)
        {
            using (client)
            {
                try
                {
                    client.ReceiveTimeout = 5000;
                    client.SendTimeout = 5000;
                    using (var stream = client.GetStream())
                    {
                        byte[] reqBuf = new byte[8192];
                        int r = stream.Read(reqBuf, 0, reqBuf.Length);
                        if (r <= 0) return;
                        string req = Encoding.UTF8.GetString(reqBuf, 0, r);
                        string firstLine = req.Split('\r', '\n')[0];
                        var tokens = firstLine.Split(' ');
                        if (tokens.Length < 2) return;
                        string method = tokens[0];
                        string rawPath = tokens[1];
                        string path = rawPath.Split('?')[0];
                        string query = rawPath.Contains("?") ? rawPath.Substring(rawPath.IndexOf('?') + 1) : "";

                        if (path == "/api/status")
                        {
                            SendJson(stream, BuildStatusJson());
                        }
                        else if (path == "/api/scan")
                        {
                            Task.Run(() =>
                            {
                                _engine.ReadSystemArpTable();
                                _engine.SweepCurrentSubnet();
                            });
                            SendJson(stream, "{\"ok\":true,\"msg\":\"已触发全网段主动扫描\"}");
                        }
                        else if (path == "/api/switch")
                        {
                            var q = ParseQuery(query);
                            string ifaceId = q.ContainsKey("id") ? q["id"] : "";
                            string cidr = q.ContainsKey("cidr") ? q["cidr"] : "";
                            var found = _engine.Adapters.FirstOrDefault(a => a.Id == ifaceId || a.Ip == ifaceId);
                            if (found != null)
                            {
                                MonitorEngine.SaveAdapterPreference(found.Id);
                                _engine.SetActiveAdapter(found, cidr);
                                _engine.RestartPacketCapture();
                            }
                            else if (!string.IsNullOrEmpty(cidr))
                            {
                                _engine.SetActiveAdapter(_engine.ActiveAdapter, cidr);
                            }
                            SendJson(stream, "{\"ok\":true}");
                        }
                        else if (path == "/api/clear-alerts")
                        {
                            _engine.Alerts.Clear();
                            SendJson(stream, "{\"ok\":true}");
                        }
                        else if (path == "/api/toggle-pause")
                        {
                            _engine.TogglePause();
                            SendJson(stream, "{\"ok\":true,\"paused\":" + (_engine.IsPaused ? "true" : "false") + "}");
                        }
                        else if (path == "/api/toggle-crosswire")
                        {
                            _engine.IsolateCrossWireCheck = !_engine.IsolateCrossWireCheck;
                            SendJson(stream, "{\"ok\":true,\"isolate\":" + (_engine.IsolateCrossWireCheck ? "true" : "false") + "}");
                        }
                        else if (path == "/api/reset-all")
                        {
                            _engine.ResetAllStats();
                            SendJson(stream, "{\"ok\":true}");
                        }
                        else if (path == "/download/LanGuardian.exe")
                        {
                            string exePath = Process.GetCurrentProcess().MainModule.FileName;
                            byte[] exeBytes = File.ReadAllBytes(exePath);
                            string hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"LanGuardian.exe\"\r\nContent-Length: " + exeBytes.Length + "\r\nConnection: close\r\n\r\n";
                            byte[] hdrBytes = Encoding.ASCII.GetBytes(hdr);
                            stream.Write(hdrBytes, 0, hdrBytes.Length);
                            stream.Write(exeBytes, 0, exeBytes.Length);
                        }
                        else
                        {
                            SendHtml(stream, GetDashboardHtml());
                        }
                    }
                }
                catch { }
            }
        }

        private static Dictionary<string, string> ParseQuery(string q)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(q)) return d;
            foreach (var part in q.Split('&'))
            {
                var kv = part.Split('=');
                if (kv.Length == 2)
                {
                    d[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1]);
                }
            }
            return d;
        }

        private string BuildStatusJson()
        {
            var sb = new StringBuilder(16384);
            int critCount = _engine.Alerts.Values.Count(a => a.Severity == "critical");
            int warnCount = _engine.Alerts.Values.Count(a => a.Severity == "warning");
            int score = Math.Max(20, 100 - critCount * 22 - warnCount * 8);

            sb.Append("{");
            sb.AppendFormat("\"version\":\"{0}\",", Esc(MonitorEngine.AppVersion));
            sb.AppendFormat("\"time\":\"{0}\",", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendFormat("\"healthScore\":{0},", score);
            sb.AppendFormat("\"paused\":{0},", _engine.IsPaused ? "true" : "false");
            sb.AppendFormat("\"captureEngine\":\"{0}\",", Esc(_engine.CaptureEngineName));
            sb.AppendFormat("\"npcap\":{0},", _engine.NpcapAvailable ? "true" : "false");
            sb.AppendFormat("\"activeCidr\":\"{0}\",", Esc(_engine.ActiveCidr));
            sb.AppendFormat("\"gatewayLatencyMs\":{0:F1},", _engine.GatewayLatencyMs);
            sb.AppendFormat("\"gatewayLossPct\":{0:F0},", _engine.GatewayLossPct);
            sb.AppendFormat("\"upstreamGwIp\":\"{0}\",", Esc(_engine.UpstreamGatewayIp));
            sb.AppendFormat("\"upstreamLatencyMs\":{0:F1},", _engine.UpstreamLatencyMs);
            sb.AppendFormat("\"isDoubleNat\":{0},", (!string.IsNullOrEmpty(_engine.UpstreamGatewayIp) && MonitorEngine.IsPrivateOrLocalIp(_engine.UpstreamGatewayIp)) ? "true" : "false");
            sb.AppendFormat("\"dnsLatencyMs\":{0:F1},", _engine.DnsLatencyMs);
            sb.AppendFormat("\"wanLatencyMs\":{0:F1},", _engine.WanLatencyMs);
            sb.AppendFormat("\"wanLossPct\":{0:F0},", _engine.WanLossPct);
            sb.AppendFormat("\"totalPackets\":{0},", _engine.TotalCapturedPackets);
            sb.AppendFormat("\"totalBytes\":{0},", _engine.TotalCapturedBytes);
            sb.AppendFormat("\"currentKBps\":{0:F1},", _engine.CurrentTotalKBps);
            sb.AppendFormat("\"currentPps\":{0:F0},", _engine.CurrentTotalPps);
            sb.AppendFormat("\"currentBcastPps\":{0:F0},", _engine.CurrentBcastPps);

            // Active adapter
            var aa = _engine.ActiveAdapter;
            sb.Append("\"activeAdapter\":{");
            sb.AppendFormat("\"id\":\"{0}\",\"name\":\"{1}\",\"desc\":\"{2}\",\"ip\":\"{3}\",\"mask\":\"{4}\",\"cidr\":\"{5}\",\"gw\":\"{6}\",\"dns\":\"{7}\",\"mac\":\"{8}\",\"speedMbps\":{9}",
                Esc(aa.Id), Esc(aa.Name), Esc(aa.Description), Esc(aa.Ip), Esc(aa.Mask), Esc(aa.Cidr), Esc(aa.Gateway), Esc(aa.Dns), Esc(aa.Mac), aa.SpeedMbps);
            sb.Append("},");

            // All adapters
            sb.Append("\"adapters\":[");
            for (int i = 0; i < _engine.Adapters.Count; i++)
            {
                var a = _engine.Adapters[i];
                if (i > 0) sb.Append(",");
                sb.AppendFormat("{{\"id\":\"{0}\",\"name\":\"{1}\",\"desc\":\"{2}\",\"ip\":\"{3}\",\"cidr\":\"{4}\",\"gw\":\"{5}\",\"mac\":\"{6}\",\"isUp\":{7},\"isMirror\":{8}}}",
                    Esc(a.Id), Esc(a.Name), Esc(a.Description), Esc(a.Ip), Esc(a.Cidr), Esc(a.Gateway), Esc(a.Mac), a.IsUp ? "true" : "false", a.IsMirrorCandidate ? "true" : "false");
            }
            sb.Append("],");

            // History
            sb.Append("\"history\":[");
            var hist = _engine.History.ToArray();
            for (int i = 0; i < hist.Length; i++)
            {
                if (i > 0) sb.Append(",");
                sb.AppendFormat("{{\"t\":\"{0}\",\"kbps\":{1:F1},\"pps\":{2:F0},\"bcast\":{3:F0} }}",
                    Esc(hist[i].Time), hist[i].TotalKBps, hist[i].TotalPps, hist[i].BcastPps);
            }
            sb.Append("],");

            // Alerts
            sb.Append("\"alerts\":[");
            var alerts = _engine.Alerts.Values
                .OrderBy(a => a.Severity == "critical" ? 0 : 1)
                .ThenByDescending(a => a.LastTime)
                .ToList();
            for (int i = 0; i < alerts.Count; i++)
            {
                var al = alerts[i];
                if (i > 0) sb.Append(",");
                sb.Append("{");
                sb.AppendFormat("\"id\":\"{0}\",\"code\":\"{1}\",\"severity\":\"{2}\",\"title\":\"{3}\",",
                    Esc(al.Id), Esc(al.Code), Esc(al.Severity), Esc(al.Title));
                sb.AppendFormat("\"ip\":\"{0}\",\"mac\":\"{1}\",\"vendor\":\"{2}\",",
                    Esc(al.TargetIp), Esc(al.TargetMac), Esc(al.TargetVendor));
                sb.AppendFormat("\"evidence\":\"{0}\",\"cause\":\"{1}\",\"fixGen\":\"{2}\",\"fixWayos\":\"{3}\",\"fixTplink\":\"{4}\",",
                    Esc(al.Evidence), Esc(al.Cause), Esc(al.FixGeneral), Esc(al.FixWayOS), Esc(al.FixTpLink));
                sb.AppendFormat("\"lastTime\":\"{0}\",\"count\":{1}",
                    al.LastTime.ToString("HH:mm:ss"), al.Count);
                sb.Append("}");
            }
            sb.Append("],");

            // Hosts
            sb.Append("\"hosts\":[");
            var hosts = _engine.Hosts.Values
                .OrderByDescending(h => !h.IsLocalSubnet)
                .ThenByDescending(h => h.TxBps + h.RxBps)
                .ThenByDescending(h => h.TotalTxBytes + h.TotalRxBytes)
                .ToList();
            for (int i = 0; i < hosts.Count; i++)
            {
                var h = hosts[i];
                if (i > 0) sb.Append(",");
                string acts = string.Join(" | ", h.RecentActivities);
                string role = _engine.InferRole(h);
                sb.Append("{");
                sb.AppendFormat("\"ip\":\"{0}\",\"mac\":\"{1}\",\"vendor\":\"{2}\",\"hostname\":\"{3}\",\"role\":\"{4}\",",
                    Esc(h.Ip), Esc(h.Mac), Esc(h.Vendor), Esc(h.Hostname), Esc(role));
                sb.AppendFormat("\"isLocal\":{0},\"isGw\":{1},",
                    h.IsLocalSubnet ? "true" : "false", h.IsGateway ? "true" : "false");
                sb.AppendFormat("\"txKBps\":{0:F1},\"rxKBps\":{1:F1},\"totalMB\":{2:F2},",
                    h.TxBps / 1024.0, h.RxBps / 1024.0, (h.TotalTxBytes + h.TotalRxBytes) / (1024.0 * 1024.0));
                sb.AppendFormat("\"pps\":{0:F0},\"bcastPps\":{1:F0},\"synRate\":{2:F0},\"retransPct\":{3:F1},",
                    h.Pps, h.BcastPps, h.SynRate, h.RetransRatePct);
                sb.AppendFormat("\"totalPkts\":{0},\"bcastPkts\":{1},\"synPkts\":{2},\"macCount\":{3},",
                    h.TotalTxPkts + h.TotalRxPkts, h.BroadcastPkts, h.SynPkts, h.SeenMacs.Count);
                sb.AppendFormat("\"activities\":\"{0}\",\"lastSeen\":\"{1}\"",
                    Esc(acts), h.LastSeen.ToString("HH:mm:ss"));
                sb.Append("}");
            }
            sb.Append("],");

            // Dual-NIC concurrent monitoring & cross-wire detection summary
            sb.Append("\"dualNic\":{");
            sb.AppendFormat("\"isolateCheck\":{0},\"sameSegment\":{1},\"syncHits\":{2},\"sharedCount\":{3},\"ignoredVirtual\":{4},\"nics\":[",
                _engine.IsolateCrossWireCheck ? "true" : "false",
                _engine.DualNicSameSegment ? "true" : "false",
                _engine.CrossWireSyncHits,
                _engine.CrossWireSharedMacs.Count,
                _engine.IgnoredLocalSubnets.Count);
            var nicList = _engine.NicStats.Values.ToList();
            for (int i = 0; i < nicList.Count; i++)
            {
                var ns = nicList[i];
                if (i > 0) sb.Append(",");
                string topSub = ns.ObservedSubnets.OrderByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault() ?? ns.Cidr;
                sb.AppendFormat("{{\"id\":\"{0}\",\"name\":\"{1}\",\"ip\":\"{2}\",\"subnet\":\"{3}\",\"kbps\":{4:F1},\"pps\":{5:F0},\"macs\":{6},\"isMirror\":{7},\"active\":{8} }}",
                    Esc(ns.Id), Esc(ns.Name), Esc(ns.Ip), Esc(topSub), ns.KBps, ns.Pps, ns.SeenMacToIp.Count,
                    ns.IsMirror ? "true" : "false",
                    string.Equals(ns.Id, _engine.ActiveAdapter.Id, StringComparison.OrdinalIgnoreCase) ? "true" : "false");
            }
            sb.Append("]},");

            // Active Topology Links
            sb.Append("\"links\":[");
            var links = _engine.ActiveLinks.Values
                .OrderByDescending(l => l.KBps)
                .ThenByDescending(l => l.TotalBytes)
                .Take(60)
                .ToList();
            for (int i = 0; i < links.Count; i++)
            {
                var lk = links[i];
                if (i > 0) sb.Append(",");
                sb.AppendFormat("{{\"src\":\"{0}\",\"dst\":\"{1}\",\"label\":\"{2}\",\"kbps\":{3:F1},\"totalKB\":{4:F1} }}",
                    Esc(lk.SrcIp), Esc(lk.DstIp), Esc(lk.Label), lk.KBps, lk.TotalBytes / 1024.0);
            }
            sb.Append("]}");
            return sb.ToString();
        }

        private static string Esc(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", " ").Replace("\n", " ");
        }

        private static void SendJson(NetworkStream stream, string json)
        {
            byte[] body = Encoding.UTF8.GetBytes(json);
            string hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n";
            byte[] hdrBytes = Encoding.ASCII.GetBytes(hdr);
            stream.Write(hdrBytes, 0, hdrBytes.Length);
            stream.Write(body, 0, body.Length);
        }

        private static void SendHtml(NetworkStream stream, string html)
        {
            byte[] body = Encoding.UTF8.GetBytes(html);
            string hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-cache\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n";
            byte[] hdrBytes = Encoding.ASCII.GetBytes(hdr);
            stream.Write(hdrBytes, 0, hdrBytes.Length);
            stream.Write(body, 0, body.Length);
        }

        private static string GetDashboardHtml()
        {
            return @"<!DOCTYPE html>
<html lang='zh-CN'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>LanGuardian 局域网实时检测与故障诊断中心</title>
<style>
:root {
  --bg: #14161a;
  --card: #1c1f26;
  --card2: #181a20;
  --border: #2a2f3a;
  --text: #e8eaed;
  --muted: #9aa0a6;
  --accent: #6c6cf5;
  --accent2: #8e8eff;
  --purple: #a855f7;
  --ok: #10b981;
  --warn: #f59e0b;
  --crit: #ef4444;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Microsoft YaHei', sans-serif; background: var(--bg); color: var(--text); padding: 16px 22px; line-height: 1.5; }
.header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; padding-bottom: 14px; border-bottom: 1px solid var(--border); margin-bottom: 14px; }
.title-box h1 { font-size: 20px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.badge-version { font-size: 12px; background: #6c6cf5; color: #fff; padding: 2px 9px; border-radius: 999px; font-weight: 600; letter-spacing: 0.3px; }
.badge-engine { font-size: 12px; background: rgba(108,108,245,0.16); color: #a5a5ff; border: 1px solid rgba(108,108,245,0.4); padding: 3px 10px; border-radius: 999px; font-weight: 500; }
.controls { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
select, input, button { background: #20242c; color: var(--text); border: 1px solid var(--border); padding: 6px 12px; border-radius: 6px; font-size: 13px; }
button { cursor: pointer; background: #6c6cf5; border-color: #5b5be0; color: #fff; font-weight: 500; transition: 0.15s; }
button:hover { background: #5a5ae2; }
button.secondary { background: #20242c; border-color: var(--border); color: var(--text); }
button.secondary:hover { background: #2b303b; border-color: #3d4454; }
button.secondary.active { background: rgba(108,108,245,0.22); border-color: #6c6cf5; color: #fff; }

/* Concave Radio Tabs Navigation (From Uiverse.io by german_7619, integrated into Dark Theme) */
.nav-shell { position: relative; margin-bottom: 16px; }
.nav-header-row { display: flex; align-items: flex-end; justify-content: space-between; flex-wrap: wrap; gap: 10px; background: #6c6cf5; border-top-left-radius: 0.5rem; border-top-right-radius: 0.5rem; padding: 0 1rem 0 0; }
.radio-inputs {
  position: relative;
  display: flex;
  border-top-left-radius: 0.5rem;
  border-top-right-radius: 0.5rem;
  background-color: #6c6cf5;
  font-size: 14px;
  padding: 0.5rem 1.5rem 0 1.5rem;
  gap: 4px;
}
.radio-inputs .radio input { display: none; }
.radio-inputs .radio .name {
  display: flex;
  cursor: pointer;
  align-items: center;
  justify-content: center;
  border: none;
  transition: all 0.15s ease-in-out;
  position: relative;
  border-top-left-radius: 0.5rem;
  border-top-right-radius: 0.5rem;
  color: rgba(255,255,255,0.88);
}
.radio-inputs .radio input + .name:hover { color: #fff; }
.radio-inputs .radio input + .name .pre-name,
.radio-inputs .radio input + .name .pos-name {
  content: '';
  position: absolute;
  width: 10px;
  height: 10px;
  background-color: #6c6cf5;
  bottom: 0;
  opacity: 0;
  pointer-events: none;
}
.radio-inputs .radio input + .name .pre-name {
  right: -10px;
  border-bottom-left-radius: 300px;
  box-shadow: -3px 3px 0px 3px #e8e8e8;
}
.radio-inputs .radio input + .name .pos-name {
  left: -10px;
  border-bottom-right-radius: 300px;
  box-shadow: 3px 3px 0px 3px #e8e8e8;
}
.radio-inputs .radio input:checked + .name {
  animation: name-activated;
  animation-duration: 0.1s;
  animation-fill-mode: forwards;
}
@keyframes name-activated {
  from { background-color: #6c6cf5; font-weight: 400; cursor: pointer; color: white; }
  to { background-color: #e8e8e8; font-weight: 600; cursor: default; color: black; }
}
.radio-inputs .radio input:checked + .name .pre-name,
.radio-inputs .radio input:checked + .name .pos-name {
  animation: name-border-activated;
  animation-duration: 0.1s;
  animation-fill-mode: forwards;
  z-index: 0;
}
@keyframes name-border-activated {
  from { opacity: 0; }
  to { opacity: 1; }
}
.radio-inputs .radio .name span:last-child {
  z-index: 1;
  padding: 0.5rem 0.9rem;
  border-top-left-radius: 0.5rem;
  border-top-right-radius: 0.5rem;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.radio-inputs .radio input:checked + .name span:last-child {
  animation: name-text-activated;
  animation-duration: 0.1s;
  animation-fill-mode: forwards;
}
@keyframes name-text-activated {
  from { background-color: #6c6cf5; }
  to { background-color: #e8e8e8; }
}
@keyframes content-activated {
  from { opacity: 0; }
  to { opacity: 1; }
}
.tab-badge { font-size: 11px; padding: 1px 7px; border-radius: 99px; background: rgba(0,0,0,0.22); color: #fff; font-weight: 600; }
.radio-inputs .radio input:checked + .name .tab-badge { background: #6c6cf5; color: #fff; }
.tab-badge.crit { background: var(--crit) !important; color: #fff !important; }
.nav-tip { font-size: 12px; color: rgba(255,255,255,0.9); padding-bottom: 10px; }
.nav-panel-frame { border: 3px solid #6c6cf5; border-top: 4px solid #e8e8e8; border-bottom-left-radius: 0.5rem; border-bottom-right-radius: 0.5rem; background: var(--bg); padding: 14px; }
.tab-pane-anim { animation: content-activated 0.45s ease-out forwards; }

/* Quick Topology Chain Bar */
.chain-bar { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 10px 16px; margin-bottom: 16px; font-size: 12.5px; }
.chain-node { display: flex; align-items: center; gap: 7px; background: rgba(15,23,42,0.8); border: 1px solid var(--border); padding: 5px 11px; border-radius: 8px; cursor: pointer; transition: 0.15s; }
.chain-node:hover { border-color: var(--accent); transform: translateY(-1px); }
.chain-arrow { color: var(--accent); font-family: monospace; font-size: 12px; display: flex; flex-direction: column; align-items: center; line-height: 1.1; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot.ok { background: var(--ok); box-shadow: 0 0 6px var(--ok); }
.dot.warn { background: var(--warn); box-shadow: 0 0 6px var(--warn); }
.dot.crit { background: var(--crit); box-shadow: 0 0 8px var(--crit); }

.grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 16px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.card-label { font-size: 12px; color: var(--muted); margin-bottom: 4px; }
.card-val { font-size: 23px; font-weight: 700; }
.card-sub { font-size: 12px; color: var(--muted); margin-top: 4px; }

.section-title { font-size: 15.5px; font-weight: 600; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
.alert-list { display: flex; flex-direction: column; gap: 12px; margin-bottom: 20px; }
.alert-item { background: var(--card); border-left: 5px solid var(--warn); border-top: 1px solid var(--border); border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
.alert-item.critical { border-left-color: var(--crit); background: linear-gradient(90deg, rgba(239,68,68,0.1) 0%, var(--card) 35%); }
.alert-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px; }
.alert-title { font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
.tag { font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 600; }
.tag.critical { background: rgba(239,68,68,0.2); color: #fca5a5; }
.tag.warning { background: rgba(245,158,11,0.2); color: #fcd34d; }
.tag.ok { background: rgba(16,185,129,0.2); color: #6ee7b7; }
.alert-body { font-size: 13px; color: #cbd5e1; display: grid; gap: 6px; }
.fix-box { background: rgba(15,23,42,0.75); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; margin-top: 6px; display: grid; gap: 5px; font-size: 12.5px; }
.fix-row b { color: var(--accent); }

.chart-box { height: 145px; width: 100%; position: relative; }
canvas#trafficCanvas { width: 100%; height: 140px; display: block; }

/* Topology Tab Layout */
.topo-wrapper { display: grid; grid-template-columns: 1fr 330px; gap: 14px; align-items: stretch; }
@media (max-width: 1024px) { .topo-wrapper { grid-template-columns: 1fr; } }
.topo-wrapper:fullscreen, .topo-wrapper:-webkit-full-screen, .topo-wrapper.topo-fs-fallback {
  position: fixed !important; inset: 0 !important; width: 100vw !important; height: 100vh !important;
  z-index: 9999 !important; background: #14161a !important; padding: 12px !important; margin: 0 !important;
  grid-template-columns: 1fr 340px !important;
}
.topo-wrapper:fullscreen .topo-stage, .topo-wrapper:-webkit-full-screen .topo-stage, .topo-wrapper.topo-fs-fallback .topo-stage {
  min-height: 0 !important; height: 100% !important;
}
.topo-wrapper:fullscreen canvas#topoCanvas, .topo-wrapper:-webkit-full-screen canvas#topoCanvas, .topo-wrapper.topo-fs-fallback canvas#topoCanvas {
  height: 100% !important;
}
.topo-wrapper:fullscreen .inspector-card, .topo-wrapper:-webkit-full-screen .inspector-card, .topo-wrapper.topo-fs-fallback .inspector-card {
  height: 100% !important; overflow-y: auto !important;
}
.topo-stage { background: radial-gradient(circle at 50% 35%, #1d2033 0%, #14161a 85%); border: 1px solid var(--border); border-radius: 12px; position: relative; overflow: hidden; min-height: 620px; display: flex; flex-direction: column; }
.topo-toolbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; padding: 10px 14px; background: rgba(20,22,26,0.88); border-bottom: 1px solid var(--border); z-index: 2; }
.topo-legend { display: flex; flex-wrap: wrap; gap: 12px; padding: 8px 14px; background: rgba(20,22,26,0.82); border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); z-index: 2; }
.legend-item { display: flex; align-items: center; gap: 5px; }
canvas#topoCanvas { width: 100%; height: 540px; display: block; cursor: grab; flex: 1; }
canvas#topoCanvas:active { cursor: grabbing; }
.inspector-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
.kv-grid { display: grid; grid-template-columns: 92px 1fr; gap: 6px 8px; font-size: 12.5px; }
.kv-grid .k { color: var(--muted); }
.kv-grid .v { color: #fff; font-weight: 500; word-break: break-all; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; background: rgba(15,23,42,0.5); user-select: none; }
th.sortable { cursor: pointer; transition: 0.15s; white-space: nowrap; }
th.sortable:hover { color: #fff; background: rgba(56,189,248,0.12); }
th.sortable.active-sort { color: var(--accent); background: rgba(56,189,248,0.16); }
.sort-arrow { font-size: 10px; margin-left: 4px; opacity: 0.85; }
tr { cursor: pointer; }
tr:hover { background: rgba(56,189,248,0.08); }
.foreign-row { background: rgba(239,68,68,0.12) !important; }
.mono { font-family: Consolas, Monaco, monospace; font-size: 12.5px; }
.hidden { display: none !important; }
</style>
</head>
<body>
<div class='header'>
  <div class='title-box'>
    <h1>LanGuardian 局域网实时检测与故障诊断中心 <span id='versionBadge' class='badge-version'>v1.4.2</span> <span id='engineBadge' class='badge-engine'>加载中...</span></h1>
    <div style='font-size:12.5px;color:var(--muted);margin-top:4px;'>
      当前监控网卡: <b id='curAdapter' style='color:#fff'>-</b> | 自动识别网段: <b id='curCidr' style='color:#a5a5ff'>-</b> | 网关: <b id='curGw'>-</b>
    </div>
  </div>
  <div class='controls'>
    <select id='adapterSel' title='切换监控网卡（支持选择第二块端口镜像专用网卡）'></select>
    <input id='cidrInput' type='text' placeholder='网段 CIDR (如 10.0.0.0/24)' style='width:140px;'>
    <button onclick='applyAdapter()'>切换网卡/网段</button>
    <button id='btnPauseToggle' class='secondary' onclick='togglePause()' style='border-color:#f59e0b;color:#fcd34d;'>⏸️ 暂停监控</button>
    <button class='secondary' onclick='resetAllStats()' title='清空旧环境缓存数据并重新识别当前局域网'>🔄 重置数据</button>
    <button class='secondary' onclick='triggerScan()'>立即扫描</button>
    <button class='secondary' onclick='exportReport()'>导出报告</button>
  </div>
</div>

<!-- 实时拓扑链路速览条 -->
<div id='chainBar' class='chain-bar'></div>

<!-- 顶部凹角滑块切换 Tab 栏 + 内容框架 -->
<div class='nav-shell'>
  <div class='nav-header-row'>
    <div class='radio-inputs'>
      <label class='radio'>
        <input type='radio' name='lg-tab-group' id='tabBtnOverview' checked onchange='switchTab(""overview"")' />
        <span class='name'>
          <span class='pre-name'></span>
          <span class='pos-name'></span>
          <span>📊 实时监控与故障诊断</span>
        </span>
      </label>
      <label class='radio'>
        <input type='radio' name='lg-tab-group' id='tabBtnTopo' onchange='switchTab(""topology"")' />
        <span class='name'>
          <span class='pre-name'></span>
          <span class='pos-name'></span>
          <span>🕸️ 网络拓扑与实时态势图 <span id='topoNodeBadge' class='tab-badge'>0</span></span>
        </span>
      </label>
      <label class='radio'>
        <input type='radio' name='lg-tab-group' id='tabBtnAlerts' onchange='switchTab(""alerts"")' />
        <span class='name'>
          <span class='pre-name'></span>
          <span class='pos-name'></span>
          <span>🚨 异常诊断与修正方案 <span id='alertTabBadge' class='tab-badge'>0</span></span>
        </span>
      </label>
    </div>
    <div class='nav-tip'>💡 点击任意主机或拓扑节点可查看单机深度透视与修正建议</div>
  </div>
  <div class='nav-panel-frame'>

<!-- ==================== TAB 1: 综合监控视图 ==================== -->
<div id='viewOverview' class='tab-pane-anim'>
  <div id='dualNicBar' class='card hidden' style='margin-bottom:14px;border-color:rgba(108,108,245,0.45);background:linear-gradient(90deg,rgba(108,108,245,0.12),#1c1f26 45%);'></div>
  <div class='grid-4'>
    <div class='card'>
      <div class='card-label'>局域网健康评分</div>
      <div id='healthScore' class='card-val' style='color:var(--ok)'>100</div>
      <div id='healthSummary' class='card-sub'>正在实时分析网络包...</div>
    </div>
    <div class='card'>
      <div class='card-label'>内网网关 / 外网连通性</div>
      <div id='pingVal' class='card-val'>- ms</div>
      <div id='pingSub' class='card-sub'>DNS延迟: - | 外网丢包: -</div>
    </div>
    <div class='card'>
      <div class='card-label'>实时吞吐率 & 包速率</div>
      <div id='rateVal' class='card-val'>0 KB/s</div>
      <div id='rateSub' class='card-sub'>0 Pkt/s | 广播: 0 Pkt/s</div>
    </div>
    <div class='card' onclick='switchTab(""topology"")' style='cursor:pointer;border-color:rgba(56,189,248,0.4)'>
      <div class='card-label'>发现节点 & 拓扑态势 (点击展开拓扑图 ↗)</div>
      <div id='hostVal' class='card-val'>0 台</div>
      <div id='hostSub' class='card-sub'>累计捕获报文: 0</div>
    </div>
  </div>

  <div class='card' style='margin-bottom:16px;'>
    <div class='section-title'>
      <span>实时流量突发与广播包趋势图 (最近 60 秒)</span>
      <span style='font-size:12px;color:var(--muted)'>青色: 带宽 (KB/s) | 橙色: 广播风暴速率 (Pkt/s)</span>
    </div>
    <div class='chart-box'>
      <canvas id='trafficCanvas' width='1100' height='140'></canvas>
    </div>
  </div>

  <div class='section-title'>
    <span>异常节点诊断与自动修正意见 (<span id='alertCount'>0</span> 项)</span>
    <button class='secondary' style='padding:4px 10px;font-size:12px;' onclick='clearAlerts()'>清空历史告警</button>
  </div>
  <div id='alertContainer' class='alert-list'></div>

  <div class='card'>
    <div class='section-title'>
      <span>局域网活跃节点与流量监控清单 (点击任意行可在拓扑图中定位并透视该节点)</span>
    </div>
    <div style='overflow-x:auto;'>
      <table>
        <thead>
          <tr id='hostTableHead'>
            <th class='sortable' data-col='status' onclick='sortHosts(""status"")'>状态<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='role' onclick='sortHosts(""role"")'>类型<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='ip' onclick='sortHosts(""ip"")'>IP 地址<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='hostname' onclick='sortHosts(""hostname"")'>主机名<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='mac' onclick='sortHosts(""mac"")'>MAC 地址<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='vendor' onclick='sortHosts(""vendor"")'>设备厂商 (OUI)<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='rxKBps' onclick='sortHosts(""rxKBps"")'>实时下载<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='txKBps' onclick='sortHosts(""txKBps"")'>实时上传<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='pps' onclick='sortHosts(""pps"")'>包速率<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='bcastPps' onclick='sortHosts(""bcastPps"")'>广播/秒<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='synRate' onclick='sortHosts(""synRate"")'>新建连接/秒<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='retransPct' onclick='sortHosts(""retransPct"")'>TCP重传率<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='totalMB' onclick='sortHosts(""totalMB"")'>累计流量<span class='sort-arrow'></span></th>
            <th class='sortable' data-col='activities' onclick='sortHosts(""activities"")'>近期访问域名 / 协议活动<span class='sort-arrow'></span></th>
          </tr>
        </thead>
        <tbody id='hostTable'></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ==================== TAB 2: 网络拓扑与实时态势图 ==================== -->
<div id='viewTopology' class='hidden'>
  <div class='topo-wrapper'>
    <div class='topo-stage'>
      <div class='topo-toolbar'>
        <div style='display:flex;align-items:center;gap:6px;flex-wrap:wrap;'>
          <span style='font-size:12.5px;color:var(--muted);margin-right:4px;'>布局模式:</span>
          <button id='btnLayoutTree' class='secondary active' onclick='setTopoLayout(""tree"")'>🏛️ 分层架构拓扑图</button>
          <button id='btnLayoutRadial' class='secondary' onclick='setTopoLayout(""radial"")'>🎯 星型通信态势图</button>
          <span style='font-size:12.5px;color:var(--muted);margin-left:10px;'>筛选:</span>
          <select id='topoFilter' onchange='resetNodePositions()'>
            <option value='all'>全部节点</option>
            <option value='active'>仅看当前有流量节点</option>
            <option value='anomaly'>仅看异常 / 高重传节点</option>
            <option value='pc_nas'>电脑 / 服务器 / NAS</option>
            <option value='net_iot'>网络设备 / 监控 / IoT</option>
          </select>
        </div>
        <div style='display:flex;align-items:center;gap:6px;'>
          <button class='secondary' onclick='zoomTopo(1.18)' title='放大'>＋</button>
          <button class='secondary' onclick='zoomTopo(0.85)' title='缩小'>－</button>
          <button class='secondary' onclick='resetTopoView()'>重置视图与布局</button>
          <button id='btnTopoFs' class='secondary' onclick='toggleTopoFullscreen()' title='进入/退出全屏视图' style='border-color:#6c6cf5;color:#c7c7ff;'>⛶ 全屏模式</button>
        </div>
      </div>

      <canvas id='topoCanvas' width='1100' height='560'></canvas>

      <div class='topo-legend'>
        <div class='legend-item'><span class='dot ok'></span> 链路/节点正常</div>
        <div class='legend-item'><span class='dot warn'></span> 突发流量 / 发包偏高</div>
        <div class='legend-item'><span class='dot crit'></span> 异网段窜入 / IP冲突 / 丢包重传告警</div>
        <div class='legend-item'><span style='color:#38bdf8;font-weight:700;'>•••➤</span> 实时上下行流量粒子 (速度随带宽动态变化)</div>
        <div class='legend-item'><span style='color:#a855f7;font-weight:700;'>---</span> 内网机器间直接互访会话连线</div>
        <div class='legend-item' style='margin-left:auto;'>🖱️ 支持滚轮缩放、拖拽画布、拖拽任意节点位置、点击节点透视</div>
      </div>
    </div>

    <!-- 右侧节点深度透视侧边栏 -->
    <div class='inspector-card'>
      <div style='display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:10px;'>
        <h3 style='font-size:15px;color:#fff;'>🔍 节点深度透视与诊断</h3>
        <span id='inspBadge' class='tag ok'>未选择</span>
      </div>
      <div id='inspectorBody' style='font-size:13px;color:var(--muted);display:flex;flex-direction:column;gap:12px;'>
        请在左侧拓扑图中点击任意设备节点（如路由器、NAS、办公电脑或告警节点），即可查看该节点的实时链路指标、近期通信域名及针对性修正意见。
      </div>
    </div>
  </div>
</div>

<!-- ==================== TAB 3: 异常诊断与修正方案专项视图 ==================== -->
<div id='viewAlerts' class='hidden'>
  <div class='card' style='margin-bottom:16px;'>
    <div class='section-title'>
      <span>🚨 实时抓包异常诊断与修正意见列表</span>
      <button class='secondary' style='padding:4px 10px;font-size:12px;' onclick='clearAlerts()'>清空历史告警</button>
    </div>
    <div id='alertContainerFull' class='alert-list' style='margin-bottom:0;'></div>
  </div>

  <div class='card'>
    <div class='section-title'><span>🛠️ 局域网常见变慢/卡顿主动加固清单 (适用于维盟 WayOS & TP-LINK 企业路由)</span></div>
    <div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;font-size:13px;color:#cbd5e1;'>
      <div class='fix-box'>
        <div><b>1. 防止单机 P2P/迅雷打满连接表导致全网假死</b></div>
        <div>• <b>维盟 WayOS</b>：【防御配置】→【连接数设置】，限制单 IP 最大联机数为 1500~2000。</div>
        <div>• <b>TP-LINK</b>：【行为管控】→【连接数限制】，为内网地址组设置单机最大连接数 1500~2000。</div>
      </div>
      <div class='fix-box'>
        <div><b>2. 防止单机高速下载吃光整条宽带</b></div>
        <div>• <b>维盟 WayOS</b>：【智能流控】开启智能 QoS，限制单机最大上下行不超过总宽带的 60%。</div>
        <div>• <b>TP-LINK</b>：【行为管控】→【带宽控制】，设置总带宽达 80% 时启用单机限速。</div>
      </div>
      <div class='fix-box'>
        <div><b>3. 防止私接小路由器 DHCP 抢答与 ARP 欺骗</b></div>
        <div>• <b>维盟 WayOS</b>：【防御配置】→【ARP管理】开启静态绑定与免费 ARP；开启【防御二级路由】。</div>
        <div>• <b>TP-LINK</b>：【安全管理】→【ARP防护】开启 IP-MAC 绑定；排查拓扑图中标红的异网段节点。</div>
      </div>
    </div>
  </div>
</div>

  </div><!-- /nav-panel-frame -->
</div><!-- /nav-shell -->

<script>
let lastStatus = null;
let adapterInitialized = false;
let currentTab = 'overview';
let topoLayout = 'tree'; // 'tree' | 'radial'
let selectedNodeId = null;

// Table Sorting State
let sortCol = '';
let sortAsc = false;

// Topology Canvas Interaction & Logical Coordinate State
let topoZoom = 1.0;
let topoPanX = 0;
let topoPanY = 0;
let topoLogicW = 1000;
let topoLogicH = 560;
let topoDpr = 1;
let isDraggingCanvas = false;
let draggedNode = null;
let dragStartX = 0;
let dragStartY = 0;
let nodePositions = {}; // id -> {x, y, pinned}
let topoGraphNodes = [];
let topoGraphEdges = [];
let animTick = 0;

function ipToNum(ip) {
  if (!ip) return 0;
  const p = ip.split('.').map(x => parseInt(x, 10) || 0);
  if (p.length !== 4) return 0;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function hostStatusRank(h) {
  if (!h.isLocal) return 5;
  if (h.macCount > 1) return 4;
  if (h.bcastPps >= 80 || h.synRate >= 40) return 3;
  if (h.retransPct >= 4.5) return 2;
  if (h.isGw) return 1;
  return 0;
}

function sortHosts(col) {
  if (sortCol === col) {
    sortAsc = !sortAsc;
  } else {
    sortCol = col;
    // String columns default to ascending (A-Z / small IP first); numeric rate columns default to descending (highest first)
    sortAsc = ['ip', 'hostname', 'mac', 'vendor', 'role', 'activities'].includes(col);
  }
  if (lastStatus) renderStatus(lastStatus);
}

function updateSortHeaders() {
  const ths = document.querySelectorAll('#hostTableHead th.sortable');
  ths.forEach(th => {
    const col = th.getAttribute('data-col');
    const arrow = th.querySelector('.sort-arrow');
    if (col === sortCol) {
      th.classList.add('active-sort');
      if (arrow) arrow.textContent = sortAsc ? '▲' : '▼';
    } else {
      th.classList.remove('active-sort');
      if (arrow) arrow.textContent = '⇅';
    }
  });
}

const ROLE_META = {
  internet: { icon: '☁️', label: '互联网公网', color: '#38bdf8' },
  upstream: { icon: '🌐', label: '上级光猫/路由', color: '#a855f7' },
  gateway:  { icon: '🛡️', label: '主路由网关', color: '#10b981' },
  switch:   { icon: '🔀', label: '局域网交换汇聚层', color: '#0ea5e9' },
  probe:    { icon: '📡', label: '本机监控探针', color: '#38bdf8' },
  nas:      { icon: '🗄️', label: 'NAS / 存储服务器', color: '#f59e0b' },
  netdev:   { icon: '📶', label: '下级路由 / AP / 交换', color: '#8b5cf6' },
  camera:   { icon: '📷', label: '安防监控 / 智能IoT', color: '#14b8a6' },
  mobile:   { icon: '📱', label: '移动终端', color: '#ec4899' },
  pc:       { icon: '💻', label: '电脑 / 工作站', color: '#60a5fa' },
  rogue:    { icon: '⚠️', label: '异网段异常节点', color: '#ef4444' }
};

function switchTab(tab) {
  currentTab = tab;
  document.getElementById('tabBtnOverview').checked = (tab === 'overview');
  document.getElementById('tabBtnTopo').checked = (tab === 'topology');
  document.getElementById('tabBtnAlerts').checked = (tab === 'alerts');

  const views = {
    overview: document.getElementById('viewOverview'),
    topology: document.getElementById('viewTopology'),
    alerts: document.getElementById('viewAlerts')
  };
  Object.keys(views).forEach(k => {
    const el = views[k];
    el.classList.toggle('hidden', k !== tab);
    if (k === tab) {
      el.classList.remove('tab-pane-anim');
      void el.offsetWidth;
      el.classList.add('tab-pane-anim');
    }
  });

  if (tab === 'topology' && lastStatus) {
    requestAnimationFrame(() => {
      const sizeChanged = resizeTopoCanvas();
      if (sizeChanged) {
        Object.keys(nodePositions).forEach(k => {
          if (!nodePositions[k].pinned) delete nodePositions[k];
        });
      }
      rebuildTopologyGraph(lastStatus);
      fitTopologyToView();
    });
  }
}

function fitTopologyToView() {
  if (!topoGraphNodes || topoGraphNodes.length === 0) return;
  const W = topoLogicW, H = topoLogicH;
  if (W < 100 || H < 100) return;
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  topoGraphNodes.forEach(n => {
    const padX = Math.max(n.radius + 48, 66);
    const padTop = n.radius + 26;
    const padBot = n.radius + 46;
    if (n.x - padX < minX) minX = n.x - padX;
    if (n.x + padX > maxX) maxX = n.x + padX;
    if (n.y - padTop < minY) minY = n.y - padTop;
    if (n.y + padBot > maxY) maxY = n.y + padBot;
  });
  const bw = Math.max(100, maxX - minX);
  const bh = Math.max(100, maxY - minY);
  const scale = Math.min((W - 24) / bw, (H - 24) / bh);
  topoZoom = Math.max(0.45, Math.min(1.45, scale));
  const midX = (minX + maxX) / 2;
  const midY = (minY + maxY) / 2;
  topoPanX = (W / 2 - midX) * topoZoom;
  topoPanY = (H / 2 - midY) * topoZoom;
}

function syncTopoFsLayout() {
  const wrap = document.querySelector('#viewTopology .topo-wrapper');
  const btn = document.getElementById('btnTopoFs');
  const isFs = !!(document.fullscreenElement === wrap || (wrap && wrap.classList.contains('topo-fs-fallback')));
  if (btn) btn.textContent = isFs ? '✕ 退出全屏' : '⛶ 全屏模式';
  setTimeout(() => {
    resizeTopoCanvas();
    nodePositions = {};
    if (lastStatus) {
      rebuildTopologyGraph(lastStatus);
      fitTopologyToView();
    }
  }, 80);
}

function toggleTopoFullscreen() {
  const wrap = document.querySelector('#viewTopology .topo-wrapper');
  if (!wrap) return;
  const isNativeFs = document.fullscreenElement === wrap;
  const isFallbackFs = wrap.classList.contains('topo-fs-fallback');
  if (isNativeFs) {
    if (document.exitFullscreen) document.exitFullscreen().catch(() => {});
  } else if (isFallbackFs) {
    wrap.classList.remove('topo-fs-fallback');
    syncTopoFsLayout();
  } else {
    if (wrap.requestFullscreen) {
      wrap.requestFullscreen().catch(() => {
        wrap.classList.add('topo-fs-fallback');
        syncTopoFsLayout();
      });
    } else {
      wrap.classList.add('topo-fs-fallback');
      syncTopoFsLayout();
    }
  }
}

document.addEventListener('fullscreenchange', syncTopoFsLayout);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const wrap = document.querySelector('#viewTopology .topo-wrapper');
    if (wrap && wrap.classList.contains('topo-fs-fallback')) {
      wrap.classList.remove('topo-fs-fallback');
      syncTopoFsLayout();
    }
  }
});

function setTopoLayout(mode) {
  topoLayout = mode;
  document.getElementById('btnLayoutTree').classList.toggle('active', mode === 'tree');
  document.getElementById('btnLayoutRadial').classList.toggle('active', mode === 'radial');
  resetNodePositions();
}

function resetNodePositions() {
  nodePositions = {};
  if (lastStatus) {
    rebuildTopologyGraph(lastStatus);
    fitTopologyToView();
  }
}

function resetTopoView() {
  topoZoom = 1.0;
  topoPanX = 0;
  topoPanY = 0;
  resetNodePositions();
}

function zoomTopo(factor) {
  topoZoom = Math.min(2.4, Math.max(0.45, topoZoom * factor));
}

async function toggleCrossWire() {
  await fetch('/api/toggle-crosswire');
  fetchStatus();
}

async function quickSwitchNic(id) {
  await fetch('/api/switch?id=' + encodeURIComponent(id));
  fetchStatus();
}

function renderDualNic(d) {
  const bar = document.getElementById('dualNicBar');
  if (!bar) return;
  const dn = d.dualNic;
  if (!dn || !dn.nics || dn.nics.length < 2) {
    bar.classList.add('hidden');
    return;
  }
  bar.classList.remove('hidden');
  const leak = (!dn.sameSegment || dn.isolateCheck) && (dn.syncHits >= 3 || dn.sharedCount >= 1);
  let statusBadge = '';
  if (leak) {
    statusBadge = `<span class='tag critical'>🚨 检测到双网段串线 (同帧碰撞 ${dn.syncHits} / 跨接MAC ${dn.sharedCount})</span>`;
  } else if (dn.sameSegment && !dn.isolateCheck) {
    statusBadge = `<span class='tag ok'>🔗 同网段双线模式 (主口+镜像口)</span>`;
  } else {
    statusBadge = `<span class='tag ok'>🛡️ 双物理网段完全隔离 (无串线)</span>`;
  }
  const vtInfo = dn.ignoredVirtual > 0 ? `<span style='font-size:11.5px;color:#9aa0a6;'>已自动隔离 ${dn.ignoredVirtual} 个虚拟网卡(ZeroTier/VPN)</span>` : '';
  const cards = dn.nics.map(n => `
    <div onclick='quickSwitchNic(""${n.id}"")' style='cursor:pointer;padding:8px 12px;border-radius:8px;border:1px solid ${n.active ? ""#6c6cf5"" : ""#2a2f3a""};background:${n.active ? ""rgba(108,108,245,0.18)"" : ""#14161a""};min-width:250px;flex:1;'>
      <div style='display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:12.5px;'>
        <b style='color:#fff;'>${n.active ? '▶ ' : ''}${n.name}</b>
        <span style='font-size:11px;color:#a5a5ff;'>${n.subnet || '侦听中'}</span>
      </div>
      <div style='font-size:12px;color:#9aa0a6;margin-top:4px;'>
        速率: <b style='color:#e8eaed;'>${n.kbps} KB/s</b> (${n.pps} pps) | 发现MAC: <b style='color:#e8eaed;'>${n.macs}</b> | ${n.ip ? n.ip : '纯二层无IP'}
      </div>
    </div>
  `).join('');
  bar.innerHTML = `
    <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;'>
      <div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>
        <b style='font-size:13.5px;color:#fff;'>🔀 双物理网段并发监控 & 串线检测</b>
        ${statusBadge}
        ${vtInfo}
      </div>
      <button class='secondary' style='padding:4px 10px;font-size:12px;${dn.isolateCheck ? ""border-color:#6c6cf5;color:#a5a5ff;"" : """"}' onclick='toggleCrossWire()'>
        ${dn.isolateCheck ? '🔒 物理隔离串线检测: 强制开启' : '🔓 物理隔离串线检测: 自动识别'}
      </button>
    </div>
    <div style='display:flex;gap:10px;flex-wrap:wrap;'>${cards}</div>
  `;
}

async function fetchStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    lastStatus = d;
    renderStatus(d);
  } catch (e) {}
}

function renderStatus(d) {
  const verEl = document.getElementById('versionBadge');
  if (verEl && d.version) verEl.textContent = d.version;
  renderDualNic(d);
  const badgeEl = document.getElementById('engineBadge');
  badgeEl.textContent = d.captureEngine;
  badgeEl.style.background = d.paused ? 'rgba(245,158,11,0.2)' : 'rgba(108,108,245,0.16)';
  badgeEl.style.color = d.paused ? '#fcd34d' : '#a5a5ff';

  const pauseBtn = document.getElementById('btnPauseToggle');
  if (pauseBtn) {
    if (d.paused) {
      pauseBtn.innerHTML = '▶️ 恢复监控';
      pauseBtn.style.background = '#059669';
      pauseBtn.style.borderColor = '#10b981';
      pauseBtn.style.color = '#fff';
    } else {
      pauseBtn.innerHTML = '⏸️ 暂停监控';
      pauseBtn.style.background = '#1e293b';
      pauseBtn.style.borderColor = '#f59e0b';
      pauseBtn.style.color = '#fcd34d';
    }
  }

  document.getElementById('curAdapter').textContent = (d.activeAdapter.name || '') + ' (' + (d.activeAdapter.ip || '无IP镜像口') + ')';
  document.getElementById('curCidr').textContent = d.activeCidr;
  document.getElementById('curGw').textContent = d.activeAdapter.gw || '未检测到';

  document.getElementById('topoNodeBadge').textContent = d.hosts.length + ' 节点';
  const alertBadge = document.getElementById('alertTabBadge');
  alertBadge.textContent = d.alerts.length;
  alertBadge.classList.toggle('crit', d.alerts.length > 0);

  if (!adapterInitialized && d.adapters && d.adapters.length > 0) {
    const sel = document.getElementById('adapterSel');
    sel.innerHTML = '';
    d.adapters.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.id;
      const tag = a.isMirror ? '【镜像/副网卡】' : (a.gw ? '【主上网口】' : '');
      const state = a.isUp ? '' : ' (未插线)';
      opt.textContent = tag + a.name + state + ' [' + (a.ip || '纯抓包无IP') + '] - ' + a.desc;
      if (a.id === d.activeAdapter.id) opt.selected = true;
      sel.appendChild(opt);
    });
    document.getElementById('cidrInput').value = d.activeCidr;
    adapterInitialized = true;
  }

  renderChainBar(d);

  const sc = document.getElementById('healthScore');
  sc.textContent = d.healthScore + ' 分';
  sc.style.color = d.healthScore >= 85 ? 'var(--ok)' : (d.healthScore >= 60 ? 'var(--warn)' : 'var(--crit)');
  document.getElementById('healthSummary').textContent =
    d.alerts.length === 0 ? '当前局域网运行健康，未检出异常节点' : ('检出 ' + d.alerts.length + ' 项异常，请查看下方修正意见');

  const gwStr = d.gatewayLatencyMs >= 0 ? (d.gatewayLatencyMs.toFixed(1) + ' ms') : '超时';
  const wanStr = d.wanLatencyMs >= 0 ? (d.wanLatencyMs.toFixed(0) + ' ms') : '超时';
  document.getElementById('pingVal').textContent = '网关 ' + gwStr + ' / 外网 ' + wanStr;
  document.getElementById('pingSub').textContent =
    '网关丢包: ' + d.gatewayLossPct + '% | DNS延迟: ' + (d.dnsLatencyMs >= 0 ? d.dnsLatencyMs.toFixed(0) + 'ms' : '超时') + ' | 外网丢包: ' + d.wanLossPct + '%';

  document.getElementById('rateVal').textContent =
    d.currentKBps >= 1024 ? ((d.currentKBps / 1024).toFixed(2) + ' MB/s') : (d.currentKBps.toFixed(1) + ' KB/s');
  document.getElementById('rateSub').textContent =
    d.currentPps + ' Pkt/s | 广播速率: ' + d.currentBcastPps + ' Pkt/s';

  const foreignCount = d.hosts.filter(h => !h.isLocal).length;
  document.getElementById('hostVal').textContent = d.hosts.length + ' 台' + (foreignCount > 0 ? (' (含 ' + foreignCount + ' 台异网段!)') : '');
  document.getElementById('hostSub').textContent = '累计分析报文: ' + d.totalPackets.toLocaleString() + ' 个';

  // Alerts
  document.getElementById('alertCount').textContent = d.alerts.length;
  const alertsHtml = d.alerts.length === 0
    ? `<div class='card' style='color:var(--ok);font-size:13.5px;'>✓ 当前未发现私接 DHCP、跨网段异常设备、ARP 冲突、广播风暴或异常突发流量。</div>`
    : d.alerts.map(a => `
      <div class='alert-item ${a.severity}'>
        <div class='alert-head'>
          <div class='alert-title'>
            <span class='tag ${a.severity}'>${a.severity === 'critical' ? '严重异常' : '警告'}</span>
            <span>${a.title}</span>
          </div>
          <span style='font-size:12px;color:var(--muted)'>最近触发: ${a.lastTime} (累计 ${a.count} 次) | 节点: <a href='javascript:void(0)' onclick='focusNodeInTopo(""${a.ip}"")' style='color:var(--accent)'>${a.ip}</a> ${a.mac ? ('[' + a.mac + ' ' + a.vendor + ']') : ''}</span>
        </div>
        <div class='alert-body'>
          <div><b>【抓包证据】</b> ${a.evidence}</div>
          <div><b>【原因分析】</b> ${a.cause}</div>
          <div class='fix-box'>
            <div class='fix-row'><b>通用排查意见：</b>${a.fixGen}</div>
            <div class='fix-row'><b>维盟 (WayOS) 路由器修正操作：</b>${a.fixWayos}</div>
            <div class='fix-row'><b>TP-LINK 商用路由器修正操作：</b>${a.fixTplink}</div>
          </div>
        </div>
      </div>
    `).join('');
  document.getElementById('alertContainer').innerHTML = alertsHtml;
  document.getElementById('alertContainerFull').innerHTML = alertsHtml;

  // Hosts table (apply active user sort if selected)
  updateSortHeaders();
  const sortedHosts = (d.hosts || []).slice();
  if (sortCol) {
    sortedHosts.sort((a, b) => {
      let va, vb;
      if (sortCol === 'ip') { va = ipToNum(a.ip); vb = ipToNum(b.ip); }
      else if (sortCol === 'status') { va = hostStatusRank(a); vb = hostStatusRank(b); }
      else if (['rxKBps', 'txKBps', 'pps', 'bcastPps', 'synRate', 'retransPct', 'totalMB'].includes(sortCol)) {
        va = Number(a[sortCol] || 0); vb = Number(b[sortCol] || 0);
      } else {
        va = String(a[sortCol] || '').toLowerCase();
        vb = String(b[sortCol] || '').toLowerCase();
        return sortAsc ? va.localeCompare(vb, 'zh-CN') : vb.localeCompare(va, 'zh-CN');
      }
      return sortAsc ? (va - vb) : (vb - va);
    });
  }

  const tb = document.getElementById('hostTable');
  tb.innerHTML = sortedHosts.map(h => {
    let badge = `<span class='tag ok'>正常</span>`;
    if (!h.isLocal) badge = `<span class='tag critical'>异网段异常</span>`;
    else if (h.macCount > 1) badge = `<span class='tag critical'>IP冲突</span>`;
    else if (h.bcastPps >= 80 || h.synRate >= 40) badge = `<span class='tag warning'>发包异常</span>`;
    else if (h.retransPct >= 4.5) badge = `<span class='tag warning'>高重传丢包</span>`;
    else if (h.isGw) badge = `<span class='tag ok'>主网关</span>`;

    const rm = ROLE_META[h.role] || ROLE_META.pc;

    return `<tr class='${!h.isLocal ? 'foreign-row' : ''}' onclick='focusNodeInTopo(""${h.ip}"")' title='点击在网络拓扑图中定位并查看该节点详情'>
      <td>${badge}</td>
      <td>${rm.icon} <span style='font-size:12px;color:var(--muted)'>${rm.label}</span></td>
      <td class='mono'><b>${h.ip}</b></td>
      <td>${h.hostname || '-'}</td>
      <td class='mono'>${h.mac || '-'}</td>
      <td>${h.vendor}</td>
      <td class='mono' style='color:${h.rxKBps > 1024 ? 'var(--warn)' : 'inherit'}'>${h.rxKBps.toFixed(1)} KB/s</td>
      <td class='mono' style='color:${h.txKBps > 1024 ? 'var(--warn)' : 'inherit'}'>${h.txKBps.toFixed(1)} KB/s</td>
      <td class='mono'>${h.pps} /s</td>
      <td class='mono' style='color:${h.bcastPps > 50 ? 'var(--crit)' : 'inherit'}'>${h.bcastPps} /s</td>
      <td class='mono' style='color:${h.synRate > 30 ? 'var(--warn)' : 'inherit'}'>${h.synRate} /s</td>
      <td class='mono' style='color:${h.retransPct >= 4 ? 'var(--crit)' : 'inherit'}'>${h.retransPct}%</td>
      <td class='mono'>${h.totalMB.toFixed(2)} MB</td>
      <td style='max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted)' title='${h.activities}'>${h.activities || '-'}</td>
    </tr>`;
  }).join('');

  drawChart(d.history || []);
  rebuildTopologyGraph(d);
  if (selectedNodeId) renderInspector(selectedNodeId);
}

function renderChainBar(d) {
  const wanOk = d.wanLatencyMs >= 0 && d.wanLossPct < 50;
  const gwOk = d.gatewayLatencyMs >= 0 && d.gatewayLossPct < 25;
  const gwHost = d.hosts.find(h => h.isGw || h.ip === d.activeAdapter.gw);
  const gwVendor = gwHost ? gwHost.vendor : '主路由器';

  const roleCounts = {};
  d.hosts.forEach(h => {
    roleCounts[h.role] = (roleCounts[h.role] || 0) + 1;
  });

  let html = `
    <span style='color:var(--muted);font-weight:600;margin-right:4px;'>🗺️ 拓扑链路速览:</span>
    <div class='chain-node' onclick='focusNodeInTopo(""WAN_INTERNET"")'>
      <span class='dot ${wanOk ? ""ok"" : ""crit""}'></span>
      <span>☁️ 互联网公网 (223.5.5.5)</span>
    </div>
    <div class='chain-arrow'>
      <span>${d.wanLatencyMs >= 0 ? d.wanLatencyMs.toFixed(0) + 'ms' : '超时'}</span>
      <span>⇄</span>
    </div>
  `;

  if (d.upstreamGwIp) {
    html += `
      <div class='chain-node' onclick='focusNodeInTopo(""UPSTREAM_GW"")' title='自动探测到双层路由结构 (上级光猫/一级路由)'>
        <span class='dot ok'></span>
        <span>🌐 上级路由/光猫 (${d.upstreamGwIp})</span>
      </div>
      <div class='chain-arrow'>
        <span>${d.upstreamLatencyMs >= 0 ? d.upstreamLatencyMs.toFixed(1) + 'ms' : '<1ms'}</span>
        <span>⇄</span>
      </div>
    `;
  }

  html += `
    <div class='chain-node' onclick='focusNodeInTopo(""${d.activeAdapter.gw || ""GATEWAY""}"")'>
      <span class='dot ${gwOk ? ""ok"" : ""crit""}'></span>
      <span>🛡️ 主网关 (${d.activeAdapter.gw || '未检出'} · ${gwVendor})</span>
    </div>
    <div class='chain-arrow'>
      <span>${d.gatewayLatencyMs >= 0 ? d.gatewayLatencyMs.toFixed(1) + 'ms' : '-'}</span>
      <span>⇄</span>
    </div>
    <div class='chain-node' onclick='switchTab(""topology"")'>
      <span class='dot ok'></span>
      <span>🔀 ${d.activeCidr} 交换网络 (${d.hosts.length} 节点: 💻${(roleCounts.pc||0)+(roleCounts.probe||0)} 🗄️${roleCounts.nas||0} 📶${roleCounts.netdev||0} 📷${roleCounts.camera||0} 📱${roleCounts.mobile||0})</span>
    </div>
  `;

  if (roleCounts.rogue > 0) {
    html += `
      <div class='chain-node' style='border-color:var(--crit);background:rgba(239,68,68,0.15)' onclick='switchTab(""topology"")'>
        <span class='dot crit'></span>
        <span style='color:#fca5a5;font-weight:700;'>⚠️ 发现 ${roleCounts.rogue} 台跨网段异常节点!</span>
      </div>
    `;
  }

  html += `<button class='secondary' style='margin-left:auto;padding:4px 10px;font-size:12px;' onclick='switchTab(""topology"")'>打开全屏交互拓扑图 🕸️</button>`;
  document.getElementById('chainBar').innerHTML = html;
}

function focusNodeInTopo(nodeId) {
  selectedNodeId = nodeId;
  switchTab('topology');
  renderInspector(nodeId);
}

function rebuildTopologyGraph(d) {
  const c = document.getElementById('topoCanvas');
  if (!c) return;
  if (currentTab === 'topology') resizeTopoCanvas();
  const W = topoLogicW;
  const H = topoLogicH;

  const filter = document.getElementById('topoFilter') ? document.getElementById('topoFilter').value : 'all';
  const alertMap = {};
  (d.alerts || []).forEach(a => {
    if (a.ip) alertMap[a.ip] = a;
  });

  const nodes = [];
  const edges = [];

  // 1. Internet Node
  const wanNode = {
    id: 'WAN_INTERNET',
    label: '互联网公网',
    sub: '223.5.5.5 (' + (d.wanLatencyMs >= 0 ? d.wanLatencyMs.toFixed(0) + 'ms' : '超时') + ')',
    role: 'internet',
    status: (d.wanLatencyMs < 150 && d.wanLossPct < 30) ? 'ok' : 'warn',
    kbps: d.currentKBps,
    radius: 26,
    raw: { ip: '223.5.5.5', hostname: '互联网公网出口 (阿里DNS测试点)', vendor: '运营商公网', role: 'internet' }
  };
  nodes.push(wanNode);

  // 2. Optional Upstream Gateway (Double NAT)
  let upNode = null;
  if (d.upstreamGwIp) {
    upNode = {
      id: 'UPSTREAM_GW',
      label: '上级光猫/路由',
      sub: d.upstreamGwIp + (d.isDoubleNat ? ' (双层NAT)' : ''),
      role: 'upstream',
      status: 'ok',
      kbps: d.currentKBps,
      radius: 24,
      raw: { ip: d.upstreamGwIp, hostname: '上级光猫 / 一级路由器', vendor: d.isDoubleNat ? '双层路由上级网关' : 'ISP汇聚网关', role: 'upstream' }
    };
    nodes.push(upNode);
  }

  // 3. Main Gateway Node
  const gwIp = d.activeAdapter.gw || '10.0.0.1';
  const gwHost = d.hosts.find(h => h.ip === gwIp || h.isGw) || {
    ip: gwIp, mac: '', vendor: '主路由网关', hostname: '默认网关', role: 'gateway', txKBps: 0, rxKBps: 0, totalMB: 0, pps: 0, bcastPps: 0, synRate: 0, retransPct: 0
  };
  const gwNode = {
    id: gwIp,
    label: (gwHost.vendor && gwHost.vendor !== '未知设备') ? gwHost.vendor : '主路由网关',
    sub: gwIp,
    role: 'gateway',
    status: (d.gatewayLatencyMs < 30 && d.gatewayLossPct < 25) ? 'ok' : 'crit',
    kbps: d.currentKBps,
    radius: 28,
    raw: gwHost
  };
  nodes.push(gwNode);

  // 4. Core LAN Switch Hub Node (Logical L2 Switch fabric)
  const swNode = {
    id: 'LAN_SWITCH_CORE',
    label: '局域网千兆交换层',
    sub: d.activeCidr,
    role: 'switch',
    status: d.currentBcastPps > 200 ? 'crit' : 'ok',
    kbps: d.currentKBps,
    radius: 23,
    raw: { ip: d.activeCidr, hostname: '局域网二层交换汇聚核心', vendor: '二层以太网交换层 (广播速率 ' + d.currentBcastPps + ' Pkt/s)', role: 'switch' }
  };
  nodes.push(swNode);

  // Connect WAN -> Upstream -> Gateway -> Switch
  if (upNode) {
    edges.push({ from: wanNode.id, to: upNode.id, kbps: d.currentKBps, label: d.wanLatencyMs >= 0 ? d.wanLatencyMs.toFixed(0) + 'ms' : '', type: 'wan' });
    edges.push({ from: upNode.id, to: gwNode.id, kbps: d.currentKBps, label: d.upstreamLatencyMs >= 0 ? d.upstreamLatencyMs.toFixed(1) + 'ms' : 'WAN1', type: 'wan' });
  } else {
    edges.push({ from: wanNode.id, to: gwNode.id, kbps: d.currentKBps, label: d.wanLatencyMs >= 0 ? d.wanLatencyMs.toFixed(0) + 'ms' : '', type: 'wan' });
  }
  edges.push({ from: gwNode.id, to: swNode.id, kbps: d.currentKBps, label: d.gatewayLatencyMs >= 0 ? d.gatewayLatencyMs.toFixed(1) + 'ms' : 'LAN', type: 'backbone' });

  // 5. Filter & add LAN Endpoint Hosts
  const endpointHosts = d.hosts.filter(h => {
    if (h.ip === gwIp || h.isGw) return false;
    const isAnomaly = !h.isLocal || h.macCount > 1 || h.bcastPps >= 80 || h.retransPct >= 4.5 || alertMap[h.ip];
    const isActive = (h.txKBps + h.rxKBps) > 0.1 || h.pps > 0 || h.ip === d.activeAdapter.ip;
    if (filter === 'active') return isActive;
    if (filter === 'anomaly') return isAnomaly || h.ip === d.activeAdapter.ip;
    if (filter === 'pc_nas') return h.role === 'pc' || h.role === 'nas' || h.role === 'probe';
    if (filter === 'net_iot') return h.role === 'netdev' || h.role === 'camera' || h.role === 'rogue';
    return true;
  });

  // Sort endpoints deterministically by role + numeric IP so nodes never jump around on refresh
  const roleOrder = { rogue: 0, netdev: 1, nas: 2, probe: 3, pc: 4, camera: 5, mobile: 6 };
  endpointHosts.sort((a, b) => {
    const rd = (roleOrder[a.role] ?? 9) - (roleOrder[b.role] ?? 9);
    if (rd !== 0) return rd;
    return ipToNum(a.ip) - ipToNum(b.ip);
  });

  // Find if there is a subordinate router / AP node to visually group or attach to switch
  endpointHosts.forEach(h => {
    let st = 'ok';
    if (!h.isLocal || h.macCount > 1 || alertMap[h.ip]?.severity === 'critical') st = 'crit';
    else if (h.bcastPps >= 50 || h.retransPct >= 4.0 || (h.txKBps + h.rxKBps) > 2048 || alertMap[h.ip]) st = 'warn';

    let shortName = h.hostname ? h.hostname.replace(' (本机)', '') : '';
    if (!shortName || shortName === '-') {
      shortName = h.vendor.split(' ')[0];
    }
    if (shortName.length > 14) shortName = shortName.slice(0, 14) + '…';

    const nd = {
      id: h.ip,
      label: shortName,
      sub: h.ip,
      role: h.role || 'pc',
      status: st,
      kbps: (h.txKBps || 0) + (h.rxKBps || 0),
      radius: h.role === 'probe' || h.role === 'nas' || h.role === 'netdev' ? 21 : 18,
      raw: h
    };
    nodes.push(nd);

    edges.push({
      from: swNode.id,
      to: nd.id,
      kbps: nd.kbps,
      label: nd.kbps >= 1 ? (nd.kbps >= 1024 ? (nd.kbps / 1024).toFixed(1) + 'MB/s' : nd.kbps.toFixed(0) + 'KB/s') : '',
      type: st === 'crit' ? 'alert' : 'lan'
    });
  });

  // 6. Add Peer-to-Peer Internal Traffic Arcs (from d.links, filtering out tiny <1KB noise unless active)
  const nodeIdSet = new Set(nodes.map(n => n.id));
  (d.links || []).forEach(lk => {
    if (lk.src !== gwIp && lk.dst !== gwIp && nodeIdSet.has(lk.src) && nodeIdSet.has(lk.dst)) {
      if (lk.kbps >= 0.2 || lk.totalKB >= 1.5) {
        const showLbl = (lk.kbps >= 1.0 || lk.src === selectedNodeId || lk.dst === selectedNodeId)
          ? (lk.label + (lk.kbps >= 0.5 ? (' ' + lk.kbps.toFixed(0) + 'KB/s') : ''))
          : '';
        edges.push({
          from: lk.src,
          to: lk.dst,
          kbps: Math.max(0.5, lk.kbps),
          label: showLbl,
          type: 'p2p'
        });
      }
    }
  });

  // 7. Compute Node Coordinates (preserving any user-dragged positions)
  if (topoLayout === 'tree') {
    layoutHierarchical(nodes, endpointHosts.length, W, H, upNode != null);
  } else {
    layoutRadial(nodes, endpointHosts.length, W, H, upNode != null);
  }

  topoGraphNodes = nodes;
  topoGraphEdges = edges;

  if (!selectedNodeId && d.activeAdapter.ip) {
    selectedNodeId = d.activeAdapter.ip;
    renderInspector(selectedNodeId);
  }
}

function layoutHierarchical(nodes, epCount, W, H, hasUpstream) {
  const cx = W / 2;
  const setPos = (nd, x, y) => {
    // Keep existing node coordinates locked so nodes never jump on live updates
    if (nodePositions[nd.id]) {
      nd.x = nodePositions[nd.id].x;
      nd.y = nodePositions[nd.id].y;
    } else {
      nd.x = x;
      nd.y = y;
      nodePositions[nd.id] = { x, y, pinned: false };
    }
  };

  const wan = nodes.find(n => n.id === 'WAN_INTERNET');
  const up = nodes.find(n => n.id === 'UPSTREAM_GW');
  const gw = nodes.find(n => n.role === 'gateway');
  const sw = nodes.find(n => n.id === 'LAN_SWITCH_CORE');

  if (hasUpstream && up) {
    if (wan) setPos(wan, cx - 190, 52);
    setPos(up, cx + 10, 52);
    if (gw) setPos(gw, cx + 210, 52);
  } else {
    if (wan) setPos(wan, cx - 120, 52);
    if (gw) setPos(gw, cx + 120, 52);
  }

  if (sw) setPos(sw, cx, 145);

  const eps = nodes.filter(n => !['WAN_INTERNET', 'UPSTREAM_GW', 'LAN_SWITCH_CORE'].includes(n.id) && n.role !== 'gateway');
  if (eps.length === 0) return;

  // Arrange endpoints in 2 or 3 clean horizontal tiers below the switch
  const maxPerRow = Math.max(6, Math.min(9, Math.ceil(eps.length / 2)));
  const rows = [];
  for (let i = 0; i < eps.length; i += maxPerRow) {
    rows.push(eps.slice(i, i + maxPerRow));
  }

  const startY = 275;
  const rowGap = rows.length > 2 ? 115 : 145;

  rows.forEach((row, rIdx) => {
    const y = startY + rIdx * rowGap;
    const usableW = Math.min(W - 110, row.length * 135);
    const leftX = cx - usableW / 2;
    row.forEach((nd, cIdx) => {
      const x = row.length === 1 ? cx : (leftX + (cIdx / (row.length - 1)) * usableW);
      // Slight vertical stagger on dense rows so labels never collide
      const stagger = (row.length >= 7 && cIdx % 2 === 1) ? 22 : 0;
      setPos(nd, x, y + stagger);
    });
  });
}

function layoutRadial(nodes, epCount, W, H, hasUpstream) {
  const cx = W / 2;
  const cy = H / 2 + 25;
  const setPos = (nd, x, y) => {
    // Keep existing node coordinates locked so nodes never jump on live updates
    if (nodePositions[nd.id]) {
      nd.x = nodePositions[nd.id].x;
      nd.y = nodePositions[nd.id].y;
    } else {
      nd.x = x;
      nd.y = y;
      nodePositions[nd.id] = { x, y, pinned: false };
    }
  };

  const wan = nodes.find(n => n.id === 'WAN_INTERNET');
  const up = nodes.find(n => n.id === 'UPSTREAM_GW');
  const gw = nodes.find(n => n.role === 'gateway');
  const sw = nodes.find(n => n.id === 'LAN_SWITCH_CORE');

  if (sw) setPos(sw, cx, cy);
  if (gw) setPos(gw, cx, cy - 95);
  if (up) {
    setPos(up, cx - 125, cy - 175);
    if (wan) setPos(wan, cx + 125, cy - 175);
  } else if (wan) {
    setPos(wan, cx, cy - 185);
  }

  const eps = nodes.filter(n => !['WAN_INTERNET', 'UPSTREAM_GW', 'LAN_SWITCH_CORE'].includes(n.id) && n.role !== 'gateway');
  const count = eps.length;
  if (count === 0) return;

  const rx = Math.min(W * 0.41, 410);
  const ry = Math.min(H * 0.36, 205);
  eps.forEach((nd, idx) => {
    // Spread in an arc avoiding top-center where Gateway sits
    const angle = (Math.PI * -0.35) + (idx / Math.max(1, count - 1)) * (Math.PI * 1.7);
    const ringScale = (count > 12 && idx % 2 === 1) ? 0.72 : 1.0;
    const x = cx + Math.cos(angle) * rx * ringScale;
    const y = cy + Math.sin(angle) * ry * ringScale + 20;
    setPos(nd, x, y);
  });
}

function drawTopologyFrame() {
  animTick = (animTick + 1) % 100000;
  const c = document.getElementById('topoCanvas');
  if (c && currentTab === 'topology' && topoGraphNodes.length > 0) {
    const ctx = c.getContext('2d');
    const W = topoLogicW, H = topoLogicH;
    ctx.setTransform(topoDpr, 0, 0, topoDpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    ctx.save();
    ctx.translate(W / 2 + topoPanX, H / 2 + topoPanY);
    ctx.scale(topoZoom, topoZoom);
    ctx.translate(-W / 2, -H / 2);

    // Draw subtle background grid
    ctx.strokeStyle = 'rgba(35, 50, 82, 0.35)';
    ctx.lineWidth = 1;
    for (let x = 0; x < W; x += 60) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
    }
    for (let y = 0; y < H; y += 60) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }

    const nodeMap = {};
    topoGraphNodes.forEach(n => nodeMap[n.id] = n);

    // 1. Draw Edges & Animated Particles
    topoGraphEdges.forEach((e, eIdx) => {
      const n1 = nodeMap[e.from];
      const n2 = nodeMap[e.to];
      if (!n1 || !n2) return;

      ctx.beginPath();
      if (e.type === 'p2p') {
        // Curved dashed arc for internal peer-to-peer session
        const mx = (n1.x + n2.x) / 2;
        const my = (n1.y + n2.y) / 2 - 38;
        ctx.setLineDash([5, 4]);
        ctx.strokeStyle = 'rgba(168, 85, 247, 0.75)';
        ctx.lineWidth = 1.8;
        ctx.moveTo(n1.x, n1.y);
        ctx.quadraticCurveTo(mx, my, n2.x, n2.y);
        ctx.stroke();
        ctx.setLineDash([]);
      } else {
        ctx.moveTo(n1.x, n1.y);
        ctx.lineTo(n2.x, n2.y);
        if (e.type === 'alert') {
          ctx.setLineDash([6, 4]);
          ctx.strokeStyle = 'rgba(239, 68, 68, 0.85)';
          ctx.lineWidth = 2.2;
        } else if (e.type === 'wan' || e.type === 'backbone') {
          ctx.strokeStyle = 'rgba(56, 189, 248, 0.65)';
          ctx.lineWidth = 2.8;
        } else {
          ctx.strokeStyle = e.kbps > 0.5 ? 'rgba(56, 189, 248, 0.45)' : 'rgba(148, 163, 184, 0.22)';
          ctx.lineWidth = e.kbps > 50 ? 2.4 : 1.4;
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // Animated traffic particles along active links
        if (e.kbps > 0.1 || e.type === 'wan' || e.type === 'backbone') {
          const speed = Math.min(0.035, 0.006 + Math.log10(1 + (e.kbps || 1)) * 0.008);
          const numDots = e.kbps > 500 ? 3 : (e.kbps > 10 ? 2 : 1);
          for (let d = 0; d < numDots; d++) {
            const t = ((animTick * speed) + (d / numDots) + (eIdx * 0.17)) % 1.0;
            const px = n1.x + (n2.x - n1.x) * t;
            const py = n1.y + (n2.y - n1.y) * t;
            ctx.beginPath();
            ctx.arc(px, py, e.kbps > 200 ? 3.8 : 2.8, 0, Math.PI * 2);
            ctx.fillStyle = e.type === 'alert' ? '#ef4444' : (e.kbps > 500 ? '#f59e0b' : '#38bdf8');
            ctx.fill();
          }
        }
      }

      // Edge label
      if (e.label) {
        const lx = (n1.x + n2.x) / 2;
        const ly = (n1.y + n2.y) / 2 - (e.type === 'p2p' ? 22 : 6);
        ctx.font = '11px -apple-system, Microsoft YaHei, sans-serif';
        ctx.fillStyle = e.type === 'p2p' ? '#d8b4fe' : '#7dd3fc';
        ctx.textAlign = 'center';
        ctx.fillText(e.label, lx, ly);
      }
    });

    // 2. Draw Nodes
    topoGraphNodes.forEach(n => {
      const rm = ROLE_META[n.role] || ROLE_META.pc;
      const isSelected = n.id === selectedNodeId;

      // Radiating sonar / soundwave rings for anomalous (crit / warn) nodes
      if (n.status === 'crit' || n.status === 'warn') {
        const isCrit = n.status === 'crit';
        const waveCount = isCrit ? 3 : 2;
        const maxSpread = isCrit ? 36 : 24;
        const rgb = isCrit ? '239,68,68' : '245,158,11';
        for (let w = 0; w < waveCount; w++) {
          const prog = ((animTick * (isCrit ? 0.016 : 0.012)) + (w / waveCount)) % 1.0;
          const rWave = n.radius + prog * maxSpread;
          const alpha = Math.pow(1 - prog, 1.5) * (isCrit ? 0.85 : 0.55);
          ctx.beginPath();
          ctx.arc(n.x, n.y, rWave, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(${rgb},${alpha.toFixed(3)})`;
          ctx.lineWidth = (1 - prog) * 2.2 + 0.8;
          ctx.stroke();
        }
      } else if (n.role === 'probe' || isSelected) {
        const pulse = 4 + Math.sin(animTick * 0.08) * 2.5;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius + pulse, 0, Math.PI * 2);
        ctx.strokeStyle = isSelected ? 'rgba(108,108,245,0.8)' : 'rgba(56,189,248,0.35)';
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Node Circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      ctx.fillStyle = '#0f172a';
      ctx.fill();
      ctx.lineWidth = isSelected ? 3.2 : 2.2;
      ctx.strokeStyle = n.status === 'crit' ? '#ef4444' : (n.status === 'warn' ? '#f59e0b' : rm.color);
      ctx.stroke();

      // Icon inside node
      ctx.font = (n.radius >= 24 ? '18px' : '15px') + ' sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(rm.icon, n.x, n.y);

      // Node Title & IP Label Pill below node
      ctx.textBaseline = 'alphabetic';
      ctx.font = 'bold 12px -apple-system, Microsoft YaHei, sans-serif';
      ctx.fillStyle = isSelected ? '#38bdf8' : '#f8fafc';
      ctx.fillText(n.label, n.x, n.y + n.radius + 15);

      ctx.font = '11px Consolas, Monaco, monospace';
      ctx.fillStyle = n.status === 'crit' ? '#fca5a5' : '#94a3b8';
      ctx.fillText(n.sub, n.x, n.y + n.radius + 29);
    });

    ctx.restore();
  }
  requestAnimationFrame(drawTopologyFrame);
}

function renderInspector(nodeId) {
  if (!lastStatus) return;
  const nd = topoGraphNodes.find(n => n.id === nodeId);
  const h = (lastStatus.hosts || []).find(x => x.ip === nodeId) || (nd ? nd.raw : null);
  const body = document.getElementById('inspectorBody');
  const badge = document.getElementById('inspBadge');
  if (!h) {
    body.innerHTML = '未找到该节点详情，请点击拓扑图中的其他节点。';
    return;
  }

  const rm = ROLE_META[h.role] || ROLE_META.pc;
  const nodeAlerts = (lastStatus.alerts || []).filter(a => a.ip === h.ip);
  badge.textContent = rm.label;
  badge.className = 'tag ' + (nodeAlerts.length > 0 || h.isLocal === false ? 'critical' : 'ok');

  const peerLinks = (lastStatus.links || []).filter(l => l.src === h.ip || l.dst === h.ip);

  let html = `
    <div style='display:flex;align-items:center;gap:10px;background:rgba(15,23,42,0.7);padding:10px 12px;border-radius:8px;border:1px solid var(--border);'>
      <div style='font-size:26px;'>${rm.icon}</div>
      <div>
        <div style='font-size:15px;font-weight:700;color:#fff;'>${h.hostname || h.vendor || h.ip}</div>
        <div class='mono' style='color:var(--accent);font-size:12.5px;'>${h.ip}</div>
      </div>
    </div>

    <div class='kv-grid'>
      <div class='k'>MAC 地址</div><div class='v mono'>${h.mac || '系统虚拟/远端节点'}</div>
      <div class='k'>设备厂商</div><div class='v'>${h.vendor || '-'}</div>
      <div class='k'>网段归属</div><div class='v'>${h.isLocal === false ? '<span style=""color:var(--crit)"">⚠️ 跨网段异常节点</span>' : '当前监控网段正常节点'}</div>
      <div class='k'>实时下载/上传</div><div class='v mono'>↓ ${(h.rxKBps||0).toFixed(1)} KB/s | ↑ ${(h.txKBps||0).toFixed(1)} KB/s</div>
      <div class='k'>累计总流量</div><div class='v mono'>${(h.totalMB||0).toFixed(2)} MB (${(h.totalPkts||0).toLocaleString()} 包)</div>
      <div class='k'>实时包速率</div><div class='v mono'>${h.pps||0} Pkt/s (广播: ${h.bcastPps||0} /s)</div>
      <div class='k'>新建连接速率</div><div class='v mono'>${h.synRate||0} SYN/s (累计 ${h.synPkts||0})</div>
      <div class='k'>TCP 重传率</div><div class='v mono' style='color:${(h.retransPct||0)>=4 ? ""var(--crit)"" : ""var(--ok)""}'>${h.retransPct||0}%</div>
      <div class='k'>最后活跃</div><div class='v mono'>${h.lastSeen || '刚刚'}</div>
    </div>
  `;

  if (h.activities) {
    html += `
      <div class='fix-box'>
        <div style='color:var(--accent);font-weight:600;margin-bottom:2px;'>🌐 近期访问域名 / 协议活动</div>
        <div class='mono' style='font-size:12px;color:#e2e8f0;word-break:break-all;'>${h.activities.split(' | ').join('<br>')}</div>
      </div>
    `;
  }

  if (peerLinks.length > 0) {
    html += `
      <div class='fix-box'>
        <div style='color:#d8b4fe;font-weight:600;margin-bottom:2px;'>🔗 活跃拓扑通信链路 (${peerLinks.length})</div>
        ${peerLinks.slice(0, 6).map(l => {
          const peer = l.src === h.ip ? l.dst : l.src;
          return `<div class='mono' style='font-size:12px;'>⇄ <b>${peer}</b> (${l.label}, ${l.kbps} KB/s, 累计 ${l.totalKB} KB)</div>`;
        }).join('')}
      </div>
    `;
  }

  if (nodeAlerts.length > 0) {
    html += nodeAlerts.map(a => `
      <div class='fix-box' style='border-color:var(--crit);background:rgba(239,68,68,0.1)'>
        <div style='color:#fca5a5;font-weight:700;'>🚨 ${a.title}</div>
        <div style='font-size:12px;color:#cbd5e1;'>${a.evidence}</div>
        <div style='font-size:12px;color:#fcd34d;margin-top:4px;'><b>修正建议：</b>${a.fixGen}</div>
      </div>
    `).join('');
  } else {
    html += `<div style='font-size:12.5px;color:var(--ok);background:rgba(16,185,129,0.1);padding:8px 10px;border-radius:6px;'>✓ 该节点当前各项网络包指标正常，未发现冲突、风暴或丢包异常。</div>`;
  }

  body.innerHTML = html;
}

function initTopoEvents() {
  const c = document.getElementById('topoCanvas');
  if (!c) return;

  const toWorld = (clientX, clientY) => {
    const rect = c.getBoundingClientRect();
    const sx = (clientX - rect.left) * (topoLogicW / Math.max(1, rect.width));
    const sy = (clientY - rect.top) * (topoLogicH / Math.max(1, rect.height));
    const wx = (sx - topoLogicW / 2 - topoPanX) / topoZoom + topoLogicW / 2;
    const wy = (sy - topoLogicH / 2 - topoPanY) / topoZoom + topoLogicH / 2;
    return { wx, wy, sx, sy };
  };

  c.addEventListener('mousedown', e => {
    const { wx, wy } = toWorld(e.clientX, e.clientY);
    let hit = null;
    for (let i = topoGraphNodes.length - 1; i >= 0; i--) {
      const n = topoGraphNodes[i];
      const dx = wx - n.x, dy = wy - n.y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 8) {
        hit = n;
        break;
      }
    }
    if (hit) {
      draggedNode = hit;
      selectedNodeId = hit.id;
      renderInspector(hit.id);
    } else {
      isDraggingCanvas = true;
      dragStartX = e.clientX - topoPanX;
      dragStartY = e.clientY - topoPanY;
    }
  });

  window.addEventListener('mousemove', e => {
    if (draggedNode) {
      const { wx, wy } = toWorld(e.clientX, e.clientY);
      draggedNode.x = wx;
      draggedNode.y = wy;
      nodePositions[draggedNode.id] = { x: wx, y: wy, pinned: true };
    } else if (isDraggingCanvas) {
      topoPanX = e.clientX - dragStartX;
      topoPanY = e.clientY - dragStartY;
    }
  });

  window.addEventListener('mouseup', () => {
    draggedNode = null;
    isDraggingCanvas = false;
  });

  c.addEventListener('wheel', e => {
    e.preventDefault();
    zoomTopo(e.deltaY < 0 ? 1.12 : 0.89);
  }, { passive: false });
}

function resizeTopoCanvas() {
  const c = document.getElementById('topoCanvas');
  if (!c) return false;
  const rect = c.getBoundingClientRect();
  if (rect.width > 200 && rect.height > 200) {
    const dpr = window.devicePixelRatio || 1;
    const newW = Math.floor(rect.width);
    const newH = Math.floor(rect.height);
    const changed = (newW !== topoLogicW || newH !== topoLogicH || dpr !== topoDpr);
    if (changed) {
      topoLogicW = newW;
      topoLogicH = newH;
      topoDpr = dpr;
      c.width = Math.floor(newW * dpr);
      c.height = Math.floor(newH * dpr);
    }
    return changed;
  }
  return false;
}

function drawChart(hist) {
  const c = document.getElementById('trafficCanvas');
  if (!c) return;
  const ctx = c.getContext('2d');
  const w = c.width, h = c.height;
  ctx.clearRect(0, 0, w, h);
  if (hist.length < 2) return;

  const maxKbps = Math.max(100, ...hist.map(p => p.kbps));
  const maxBcast = Math.max(50, ...hist.map(p => p.bcast));

  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 1;
  for (let i = 1; i <= 3; i++) {
    let y = (h / 4) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2.2;
  ctx.beginPath();
  hist.forEach((p, idx) => {
    let x = (idx / (hist.length - 1)) * (w - 20) + 10;
    let y = h - 14 - (p.kbps / maxKbps) * (h - 28);
    if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.strokeStyle = '#f59e0b';
  ctx.lineWidth = 1.8;
  ctx.beginPath();
  hist.forEach((p, idx) => {
    let x = (idx / (hist.length - 1)) * (w - 20) + 10;
    let y = h - 14 - (p.bcast / maxBcast) * (h - 28);
    if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

async function applyAdapter() {
  const id = document.getElementById('adapterSel').value;
  const cidr = document.getElementById('cidrInput').value.trim();
  await fetch('/api/switch?id=' + encodeURIComponent(id) + '&cidr=' + encodeURIComponent(cidr));
  adapterInitialized = false;
  resetNodePositions();
  fetchStatus();
}

async function triggerScan() {
  await fetch('/api/scan');
  setTimeout(fetchStatus, 1500);
}

async function clearAlerts() {
  await fetch('/api/clear-alerts');
  fetchStatus();
}

async function togglePause() {
  await fetch('/api/toggle-pause');
  fetchStatus();
}

async function resetAllStats() {
  await fetch('/api/reset-all');
  adapterInitialized = false;
  resetNodePositions();
  fetchStatus();
}

function exportReport() {
  if (!lastStatus) return;
  const blob = new Blob([JSON.stringify(lastStatus, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'LanGuardian-诊断报告-' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.json';
  a.click();
}

window.addEventListener('resize', resizeTopoCanvas);
initTopoEvents();
requestAnimationFrame(drawTopologyFrame);
fetchStatus();
setInterval(fetchStatus, 1000);
</script>
</body>
</html>";
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            int port = 8088;
            string preferredIface = "";
            bool openBrowser = true;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--port" && i + 1 < args.Length) int.TryParse(args[++i], out port);
                else if (args[i] == "--iface" && i + 1 < args.Length) preferredIface = args[++i];
                else if (args[i] == "--no-browser") openBrowser = false;
            }

            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("================================================================");
            Console.WriteLine("  LanGuardian - 局域网实时状况检测、异常节点定位与修正诊断工具");
            Console.WriteLine("  开源免费 | 单文件免安装 | 自动识别任意网段 | 支持端口镜像");
            Console.WriteLine("================================================================");

            var engine = new MonitorEngine();
            engine.Start(preferredIface);

            Console.WriteLine("[+] 当前监控网卡 : {0} ({1})", engine.ActiveAdapter.Name, engine.ActiveAdapter.Description);
            Console.WriteLine("[+] 自动识别网段 : {0} (网关: {1}, DNS: {2})", engine.ActiveCidr, engine.ActiveAdapter.Gateway, engine.ActiveAdapter.Dns);
            Console.WriteLine("[+] 抓包分析引擎 : {0}", engine.CaptureEngineName);

            var server = new WebDashboardServer(engine, port);
            server.Start();

            string url = "http://127.0.0.1:" + port;
            string lanUrl = !string.IsNullOrEmpty(engine.ActiveAdapter.Ip) ? ("http://" + engine.ActiveAdapter.Ip + ":" + port) : url;
            Console.WriteLine("[+] 本地监控面板 : {0}", url);
            Console.WriteLine("[+] 局域网访问   : {0}", lanUrl);
            Console.WriteLine("================================================================");
            Console.WriteLine("正在持续抓包并分析局域网异常节点与突发流量 (按 Ctrl+C 退出)...");

            if (openBrowser && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    Process.Start(new ProcessStartInfo("cmd", "/c start " + url) { CreateNoWindow = true, UseShellExecute = false });
                }
                catch { }
            }

            Thread.Sleep(Timeout.Infinite);
        }
    }
}
