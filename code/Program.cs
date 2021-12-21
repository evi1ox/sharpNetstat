using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.Management;
using System.Threading;

namespace process
{
    class Program
    {
        public static int CurrentColumn = 0;
        public static int BeforeColumn = 0;

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                bool listen = false;
                StaticConn(listen);
            }

            if (args.Length == 1 && (args[0]=="-h"))
            {
                Console.WriteLine("");
                Console.WriteLine("Author: Evi1oX");
                Console.WriteLine("");
                Console.WriteLine("Usage: SharpNetStat -s listen");
                Console.WriteLine("       SharpNetStat -s monitor");
                Console.WriteLine("       SharpNetStat -s monitor listen");
                Console.WriteLine("");

            }
            if (args.Length == 2 && (args[0] =="-s") && (args[1] == "listen"))
            {
                bool listen = true;
                StaticConn(listen);
            }
            if (args.Length == 2 && (args[0] == "-s") && (args[1] == "monitor"))
            {
                bool listen = false;
                Console.Clear();
                MonitorConn(listen);
            }
            if (args.Length == 3 && (args[0] == "-s"))
            {
                if ((args[1] == "monitor") || (args[1] == "listen"))
                {
                    if ((args[2] == "monitor") || (args[1] == "listen"))
                    {
                        if (args[1] != args[2])
                        {
                            bool listen = true;
                            Console.Clear();
                            MonitorConn(listen);
                        }
                    }
                }

            }
        }

        static void StaticConn(bool Listen)
        {
            Process[] processes = Process.GetProcesses();
            var Ipv4Tcpconnections = IPHelper.GetTcpConnections(IPVersion.IPv4, processes);
            int TcpTableRowCount = Ipv4Tcpconnections.Count;

            Console.WriteLine("Proto  Local Address          Foreign Address        State           PID        USER                 Command");
            for (int i = 0; i < TcpTableRowCount; i++)
            {
                TcpConnection current = Ipv4Tcpconnections[i];
                if (Listen && current.State.ToString() != "Listening")
                {
                    continue;
                }
                string Commands = GetCommandLine(current.ProcessId);
                string UserName = GetProcessUserName(current.ProcessId);
                string SourceAddr = string.Format("{0}:{1}", current.LocalAddress, current.LocalPort);
                string DestAddr = string.Format("{0}:{1}", current.RemoteAddress, current.RemotePort);
                string outputRow = string.Format("{0, -7}{1, -23}{2, -23}{3, -16}{4, -10} {5, -20} {6}", current.Protocol, SourceAddr, DestAddr, current.State, current.ProcessId, UserName, Commands);
                Console.WriteLine(outputRow);

            }

            var Ipv4Udpconnections = IPHelper.GetUdpConnections(IPVersion.IPv4, processes);
            int UdpTableRowCount = Ipv4Udpconnections.Count;
            for (int i = 0; i < UdpTableRowCount; i++)
            {
                UdpConnection current = Ipv4Udpconnections[i];
                string Commands = GetCommandLine(current.ProcessId);
                string UserName = GetProcessUserName(current.ProcessId);
                string SourceAddr = string.Format("{0}:{1}", current.LocalAddress, current.LocalPort);
                string DestAddr = string.Format("{0}:{1}", current.RemoteAddress, current.RemotePort);
                string outputRow = string.Format("{0, -7}{1, -23}{2, -23}{3, -16}{4, -10} {5, -20} {6}", current.Protocol, SourceAddr, DestAddr, "", current.ProcessId, UserName, Commands);
                Console.WriteLine(outputRow);
            }
        }

        static void MonitorConn(bool Listen)
        {
            Console.WriteLine("Proto  Local Address          Foreign Address        State           PID        USER                 Command");
            List<String> rowsList = new List<string>();
            while (true)
            {
                Process[] processes = Process.GetProcesses();

                var Ipv4Tcpconnections = IPHelper.GetTcpConnections(IPVersion.IPv4, processes);
                int TcpTableRowCount = Ipv4Tcpconnections.Count;

                //WindowsTop属性用于获取或设置控制台窗口区域相对于屏幕缓冲区的顶部位置。
                Program.CurrentColumn = 0;
                int windowTop = Console.WindowTop;
                foreach (var current in Ipv4Tcpconnections)
                {
                    if (Listen && current.State.ToString() != "Listening")
                    {
                        continue;
                    }
                    string Commands = GetCommandLine(current.ProcessId);
                    string UserName = GetProcessUserName(current.ProcessId);
                    string SourceAddr = string.Format("{0}:{1}", current.LocalAddress, current.LocalPort);
                    string DestAddr = string.Format("{0}:{1}", current.RemoteAddress, current.RemotePort);
                    string outputRow = string.Format("{0, -7}{1, -23}{2, -23}{3, -16}{4, -10} {5, -20} {6}", current.Protocol, SourceAddr, DestAddr, current.State, current.ProcessId, UserName, Commands);
                    if (rowsList.Count < Program.CurrentColumn + 1)
                    {
                        Console.SetCursorPosition(0, Program.CurrentColumn + 1);
                        Console.WriteLine("{0, -200}", outputRow);
                        rowsList.Add(outputRow);
                    }
                    else if (rowsList[Program.CurrentColumn] != outputRow)
                    {
                        rowsList[Program.CurrentColumn] = outputRow;
                        Console.SetCursorPosition(0, Program.CurrentColumn + 1);
                        Console.WriteLine("{0, -200}", outputRow);
                    }
                    Program.CurrentColumn++;

                }

                var Ipv4Udpconnections = IPHelper.GetUdpConnections(IPVersion.IPv4, processes);
                foreach (var current in Ipv4Udpconnections)
                {
                    string Commands = GetCommandLine(current.ProcessId);
                    string UserName = GetProcessUserName(current.ProcessId);
                    string SourceAddr = string.Format("{0}:{1}", current.LocalAddress, current.LocalPort);
                    string DestAddr = string.Format("{0}:{1}", current.RemoteAddress, current.RemotePort);
                    string outputRow = string.Format("{0, -7}{1, -23}{2, -23}{3, -16}{4, -10} {5, -20} {6}", current.Protocol, SourceAddr, DestAddr, "", current.ProcessId, UserName, Commands);
                    if (rowsList.Count < Program.CurrentColumn + 1)
                    {
                        Console.SetCursorPosition(0, Program.CurrentColumn + 1);
                        Console.WriteLine("{0, -200}", outputRow);
                        rowsList.Add(outputRow);
                    }
                    else if (rowsList[Program.CurrentColumn] != outputRow)
                    {
                        rowsList[Program.CurrentColumn] = outputRow;
                        Console.SetCursorPosition(0, Program.CurrentColumn + 1);
                        Console.WriteLine("{0, -200}", outputRow);
                    }
                    Program.CurrentColumn++;
                }
                //Console.WriteLine("{0} - {1} - {2}", Program.BeforeColumn, Program.CurrentColumn, rowsList.Count);
                if (Program.BeforeColumn > Program.CurrentColumn)
                {
                    int linesToBeCleared = Program.BeforeColumn - Program.CurrentColumn;
                    rowsList.RemoveRange(Program.CurrentColumn, linesToBeCleared);
                    
                    for (int i = 1; i < linesToBeCleared + 2; i++)
                    {
                        Console.SetCursorPosition(0, Program.CurrentColumn + i);
                        Console.WriteLine("{0, -200}", " ");
                    }
                }

                Program.BeforeColumn = Program.CurrentColumn;
                Console.SetWindowPosition(0, windowTop);    //in order to keep console scroll bar stay
                Thread.Sleep(100);
            }
        }
        private static string GetCommandLine(int Pid)
        {
            ManagementObjectSearcher commandLineSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process WHERE ProcessId = " + Pid);
            String commandLine = "";
            int index = 0;
            foreach (ManagementObject commandLineObject in commandLineSearcher.Get())
            {
                string Temp = (String)commandLineObject["commandLine"];
                string TemPath = (String)commandLineObject["ExecutablePath"];
                if (index == 0 && Temp != null && Temp.Length > 200)
                {
                    return TemPath;
                }
                else if (index > 0 && Temp.Length > 50)
                {
                    return commandLine;
                }
                index++;
                commandLine += Temp;
            }
            return commandLine;


        }
        private static string GetProcessUserName(int Pid)
        {
            string UserName = null;

            SelectQuery queryOne = new SelectQuery("Select * from Win32_Process WHERE processID=" + Pid);
            ManagementObjectSearcher searcher1 = new ManagementObjectSearcher(queryOne);

            try
            {
                foreach (ManagementObject disk in searcher1.Get())
                {
                    ManagementBaseObject inPar = null;
                    ManagementBaseObject outPar = null;

                    inPar = disk.GetMethodParameters("GetOwner");

                    outPar = disk.InvokeMethod("GetOwner", inPar, null);

                    UserName = outPar["User"].ToString();
                    break;
                }
            }
            catch
            {
                UserName = "SYSTEM";
            }

            return UserName;
        }

    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public MibTcpState state;
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public uint remoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public int owningPid;
    }

    // Struct that should contain a table, containing IPv4 TCP entries.
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public MIB_TCPROW_OWNER_PID[] table;
    }

    // Struct that should contain an IPv6 TCP entry.
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public MibTcpState state;
        public int owningPid;
    }

    // Struct that should contain a table, containing IPv6 TCP entries.
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6TABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public MIB_TCP6ROW_OWNER_PID[] table;
    }

    // Struct that should contain a table, containing IPv4 UDP entries.
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public int owningPid;
    }

    // Struct that should contain a table, containing IPv4 UDP entries.
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public MIB_UDPROW_OWNER_PID[] table;
    }

    // Struct that should contain a table, containing IPv6 UDP entries.
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public int owningPid;
    }

    // Struct that should contain a table, containing IPv6 UDP entries.
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDP6TABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public MIB_UDP6ROW_OWNER_PID[] table;
    }

    [StructLayout(LayoutKind.Sequential)]
    public abstract class NetworkConnection
    {
        public virtual Protocol Protocol { get; set; }
        public virtual IPAddress LocalAddress { get; set; }
        public virtual ushort LocalPort { get; set; }
        public virtual IPAddress RemoteAddress { get; set; }
        public virtual ushort RemotePort { get; set; }
        public virtual MibTcpState State { get; set; }
        public virtual int ProcessId { get; set; }
        public virtual string ProcessName { get; set; }
    }

    public enum Protocol
    {
        TCP,
        UDP
    }

    // enum for IPVersion.
    public enum IPVersion
    {
        IPv4,
        IPv6
    }

    // enum for TPC_TABLE_CLASS.
    public enum TcpTableClass
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWMER_MODULE_ALL
    }

    // enum for UDP_TABLE_CLASS.
    public enum UdpTableClass
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_TABLE_OWNER_MODULE
    }

    // enum for the different states of a connection.
    public enum MibTcpState
    {
        Closed = 1,
        Listening = 2,
        Syn_Sent = 3,
        Established = 5,
        Fin_Wait1 = 6,
        Fin_Wait2 = 7,
        Close_Wait = 8,
        Closing = 9,
        Last_Ack = 10,
        Time_Wait = 11,
        Delete_TCP = 12,
        None = 0
    }

    public class Host
    {
        private string hostName;
        private IPAddress ipAddress;

        public string HostName
        {
            get { return hostName; }
            set { hostName = value; }
        }

        public IPAddress IPAddress
        {
            get { return ipAddress; }
            set { ipAddress = value; }
        }

        public Host() { }

        public Host(string hostName, IPAddress ipAddress)
        {
            HostName = hostName;
            IPAddress = ipAddress;
        }

        public Host(string hostName, string ipAddress)
        {
            HostName = hostName;
            IPAddress = IPAddress.Parse(ipAddress);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class TcpConnection : NetworkConnection
    {
        public override Protocol Protocol { get; set; }
        public override IPAddress LocalAddress { get; set; }
        public override ushort LocalPort { get; set; }
        public override IPAddress RemoteAddress { get; set; }
        public override ushort RemotePort { get; set; }
        public override MibTcpState State { get; set; }
        public override int ProcessId { get; set; }
        public override string ProcessName { get; set; }

        public TcpConnection(Protocol protocol, IPAddress localIp, IPAddress remoteIp, ushort localPort,
            ushort remotePort, int pId, MibTcpState state)
        {
            Protocol = protocol;
            LocalAddress = localIp;
            RemoteAddress = remoteIp;
            LocalPort = localPort;
            RemotePort = remotePort;
            State = state;
            ProcessId = pId;
        }

        public TcpConnection(Protocol protocol, IPAddress localIp, IPAddress remoteIp, ushort localPort,
            ushort remotePort, int pId, MibTcpState state, Process[] processes)
        {
            Protocol = protocol;
            LocalAddress = localIp;
            RemoteAddress = remoteIp;
            LocalPort = localPort;
            RemotePort = remotePort;
            State = state;
            ProcessId = pId;
            ProcessName = processes.Where(process => process.Id == pId).FirstOrDefault().ProcessName;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class UdpConnection : NetworkConnection
    {
        public override Protocol Protocol { get; set; }
        public override IPAddress LocalAddress { get; set; }
        public override ushort LocalPort { get; set; }
        public override int ProcessId { get; set; }
        public override string ProcessName { get; set; }

        public UdpConnection(Protocol protocol, IPAddress localAddress, ushort localPort, int pId)
        {
            Protocol = protocol;
            LocalAddress = localAddress;
            LocalPort = localPort;
            ProcessId = pId;
        }

        public UdpConnection(Protocol protocol, IPAddress localAddress, ushort localPort, int pId, Process[] processes)
        {
            Protocol = protocol;
            LocalAddress = localAddress;
            LocalPort = localPort;
            ProcessId = pId;

            ProcessName = processes.Where(process => process.Id == pId).FirstOrDefault().ProcessName;
        }
    }
    public class IPHelper
    {
        // Version of IP used. 
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        // Import external helper DLLs and methods.
        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize,
            bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

        /// <summary>
        /// This function reads and parses the active TCP socket connections available.
        /// </summary>
        /// <returns>
        /// It returns the current set of TCP socket connections which are active.
        /// </returns>
        /// <exception cref="OutOfMemoryException">
        /// This exception may be thrown by the function Marshal.AllocHGlobal when
        /// there is insufficient memory to satisfy the request.
        /// </exception>
        public static List<TcpConnection> GetTcpConnections(IPVersion ipVersion, Process[] processes = null)
        {
            int bufferSize = 0;
            List<TcpConnection> tcpTableRecords = new List<TcpConnection>();

            int ulAf = AF_INET;

            if (ipVersion == IPVersion.IPv6)
            {
                ulAf = AF_INET6;
            }

            // Getting the initial size of TCP table.
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, ulAf,
                TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

            // Allocating memory as an IntPtr with the bufferSize.
            IntPtr tcpTableRecordsPtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                // The IntPtr from last call, tcpTableRecoresPtr must be used in the subsequent
                // call and passed as the first parameter.
                result = GetExtendedTcpTable(tcpTableRecordsPtr, ref bufferSize, true,
                    ulAf, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

                // If not zero, the call failed.
                if (result != 0)
                    return new List<TcpConnection>();

                // Marshals data fron an unmanaged block of memory to the
                // newly allocated managed object 'tcpRecordsTable' of type
                // 'MIB_TCPTABLE_OWNER_PID' to get number of entries of TCP
                // table structure.

                // Determine if IPv4 or IPv6.
                if (ipVersion == IPVersion.IPv4)
                {
                    MIB_TCPTABLE_OWNER_PID tcpRecordsTable = (MIB_TCPTABLE_OWNER_PID)
                        Marshal.PtrToStructure(tcpTableRecordsPtr, typeof(MIB_TCPTABLE_OWNER_PID));

                    IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr +
                                            Marshal.SizeOf(tcpRecordsTable.dwNumEntries));

                    // Read and parse the TCP records from the table and store them in list 
                    // 'TcpConnection' structure type objects.
                    for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++)
                    {
                        MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.
                            PtrToStructure(tableRowPtr, typeof(MIB_TCPROW_OWNER_PID));
                        // Add row to list of TcpConnetions.
                        tcpTableRecords.Add(new TcpConnection(
                                                Protocol.TCP,
                                                new IPAddress(tcpRow.localAddr),
                                                new IPAddress(tcpRow.remoteAddr),
                                                BitConverter.ToUInt16(new byte[2] {
                                                tcpRow.localPort[1],
                                                tcpRow.localPort[0] }, 0),
                                                BitConverter.ToUInt16(new byte[2] {
                                                tcpRow.remotePort[1],
                                                tcpRow.remotePort[0] }, 0),
                                                tcpRow.owningPid,
                                                tcpRow.state,
                                                processes));
                        tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                    }
                }
                else if (ipVersion == IPVersion.IPv6)
                {
                    MIB_TCP6TABLE_OWNER_PID tcpRecordsTable = (MIB_TCP6TABLE_OWNER_PID)
                        Marshal.PtrToStructure(tcpTableRecordsPtr, typeof(MIB_TCP6TABLE_OWNER_PID));

                    IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr +
                                            Marshal.SizeOf(tcpRecordsTable.dwNumEntries));

                    // Read and parse the TCP records from the table and store them in list 
                    // 'TcpConnection' structure type objects.
                    for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++)
                    {
                        MIB_TCP6ROW_OWNER_PID tcpRow = (MIB_TCP6ROW_OWNER_PID)Marshal.
                            PtrToStructure(tableRowPtr, typeof(MIB_TCP6ROW_OWNER_PID));

                        tcpTableRecords.Add(new TcpConnection(
                                                Protocol.TCP,
                                                new IPAddress(tcpRow.localAddr, tcpRow.localScopeId),
                                                new IPAddress(tcpRow.remoteAddr, tcpRow.remoteScopeId),
                                                BitConverter.ToUInt16(new byte[2] {
                                                tcpRow.localPort[1],
                                                tcpRow.localPort[0] }, 0),
                                                BitConverter.ToUInt16(new byte[2] {
                                                tcpRow.remotePort[1],
                                                tcpRow.remotePort[0] }, 0),
                                                tcpRow.owningPid,
                                                tcpRow.state,
                                                processes));
                        tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                    }
                }
            }
            catch (OutOfMemoryException outOfMemoryException)
            {
                throw outOfMemoryException;
            }
            catch (Exception exception)
            {
                //throw exception;
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTableRecordsPtr);
            }

            return tcpTableRecords != null ? tcpTableRecords.Distinct()
                .ToList() : new List<TcpConnection>();
        }

        /// <summary>
        /// This function reads and parses the active UDP socket connections available.
        /// </summary>
        /// <returns>
        /// It returns the current set of TCP socket connections which are active.
        /// </returns>
        /// <exception cref="OutOfMemoryException">
        /// This exception may be thrown by the function Marshal.AllocHGlobal when
        /// there is insufficient memory to satisfy the request.
        /// </exception>
        public static List<UdpConnection> GetUdpConnections(IPVersion ipVersion, Process[] processes = null)
        {
            int bufferSize = 0;
            List<UdpConnection> udpTableRecords = new List<UdpConnection>();

            int ulAf = AF_INET;

            if (ipVersion == IPVersion.IPv6)
            {
                ulAf = AF_INET6;
            }

            // Getting the initial size of UDP table.
            uint result = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true,
                ulAf, UdpTableClass.UDP_TABLE_OWNER_PID);

            // Allocating memory as an IntPtr with the bufferSize.
            IntPtr udpTableRecordsPtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                // The IntPtr from last call, udpTableRecoresPtr must be used in the subsequent
                // call and passed as the first parameter.
                result = GetExtendedUdpTable(udpTableRecordsPtr, ref bufferSize, true,
                    ulAf, UdpTableClass.UDP_TABLE_OWNER_PID);

                // If not zero, call failed.
                if (result != 0)
                    return new List<UdpConnection>();

                // Marshals data fron an unmanaged block of memory to the
                // newly allocated managed object 'udpRecordsTable' of type
                // 'MIB_UDPTABLE_OWNER_PID' to get number of entries of TCP
                // table structure.

                // Determine if IPv4 or IPv6.
                if (ipVersion == IPVersion.IPv4)
                {
                    MIB_UDPTABLE_OWNER_PID udpRecordsTable = (MIB_UDPTABLE_OWNER_PID)
                        Marshal.PtrToStructure(udpTableRecordsPtr, typeof(MIB_UDPTABLE_OWNER_PID));
                    IntPtr tableRowPtr = (IntPtr)((long)udpTableRecordsPtr +
                        Marshal.SizeOf(udpRecordsTable.dwNumEntries));

                    // Read and parse the UDP records from the table and store them in list 
                    // 'UdpConnection' structure type objects.
                    for (int i = 0; i < udpRecordsTable.dwNumEntries; i++)
                    {
                        MIB_UDPROW_OWNER_PID udpRow = (MIB_UDPROW_OWNER_PID)
                            Marshal.PtrToStructure(tableRowPtr, typeof(MIB_UDPROW_OWNER_PID));
                        udpTableRecords.Add(new UdpConnection(
                                                Protocol.UDP,
                                                new IPAddress(udpRow.localAddr),
                                                BitConverter.ToUInt16(new byte[2] { udpRow.localPort[1],
                                                udpRow.localPort[0] }, 0),
                                                udpRow.owningPid,
                                                processes));
                        tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(udpRow));
                    }
                }
                else if (ipVersion == IPVersion.IPv6)
                {
                    MIB_UDP6TABLE_OWNER_PID udpRecordsTable = (MIB_UDP6TABLE_OWNER_PID)
                        Marshal.PtrToStructure(udpTableRecordsPtr, typeof(MIB_UDP6TABLE_OWNER_PID));
                    IntPtr tableRowPtr = (IntPtr)((long)udpTableRecordsPtr +
                        Marshal.SizeOf(udpRecordsTable.dwNumEntries));

                    // Read and parse the UDP records from the table and store them in list 
                    // 'UdpConnection' structure type objects.
                    for (int i = 0; i < udpRecordsTable.dwNumEntries; i++)
                    {
                        MIB_UDP6ROW_OWNER_PID udpRow = (MIB_UDP6ROW_OWNER_PID)
                            Marshal.PtrToStructure(tableRowPtr, typeof(MIB_UDP6ROW_OWNER_PID));
                        udpTableRecords.Add(new UdpConnection(
                                                Protocol.UDP,
                                                new IPAddress(udpRow.localAddr, udpRow.localScopeId),
                                                BitConverter.ToUInt16(new byte[2] {
                                                udpRow.localPort[1],
                                                udpRow.localPort[0] }, 0),
                                                udpRow.owningPid,
                                                processes));
                        tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(udpRow));
                    }
                }
            }
            catch (OutOfMemoryException outOfMemoryException)
            {
                throw outOfMemoryException;
            }
            catch (Exception exception)
            {
                //throw exception;
            }
            finally
            {
                Marshal.FreeHGlobal(udpTableRecordsPtr);
            }

            return udpTableRecords != null ? udpTableRecords.Distinct()
                .ToList() : new List<UdpConnection>();
        }
    }
}


