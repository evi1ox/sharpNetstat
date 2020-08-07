using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ConnectionMonitor
{
    public class TcpConnectionTableHelper
    {
        [DllImport("Ws2_32.dll")]
        static extern ushort ntohs(ushort netshort);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_TYPE tblClass, int reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UDP_TABLE_TYPE tblClass, int reserved);


        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;

            public ushort LocalPort
            {
                get
                {
                    return BitConverter.ToUInt16(new byte[2] { localPort2, localPort1 }, 0);
                }
            }

            public ushort RemotePort
            {
                get
                {
                    return BitConverter.ToUInt16(new byte[2] { remotePort2, remotePort1 }, 0);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            MIB_TCPROW_OWNER_PID table;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            MIB_UDPROW_OWNER_PID table;
        }

        public static string GetIpAddress(long ipAddrs)
        {
            try
            {
                System.Net.IPAddress ipAddress = new System.Net.IPAddress(ipAddrs);
                return ipAddress.ToString();
            }
            catch { return ipAddrs.ToString(); }

        }

        public static ushort GetTcpPort(int tcpPort)
        {
            return ntohs((ushort)tcpPort);
        }

        public static MIB_TCPROW_OWNER_PID[] GetAllTcpConnections()
        {
            MIB_TCPROW_OWNER_PID[] tcpConnectionRows;
            int AF_INET = 2;    // IPv4
            int buffSize = 0;

            // use WinAPI GetExtendedTcpTable to query all active tcp connection information
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET, TCP_TABLE_TYPE.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0 && ret != 122) // 122 means insufficient buffer size
            {
                throw new Exception("Error occurred when trying to query tcp table, return code: " + ret);
            }
            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                ret = GetExtendedTcpTable(buffTable, ref buffSize, true, AF_INET, TCP_TABLE_TYPE.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0)
                {
                    throw new Exception("Error occurred when trying to query tcp table, return code: " + ret);
                }

                // get the number of entries in the table
                MIB_TCPTABLE_OWNER_PID table = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(buffTable, typeof(MIB_TCPTABLE_OWNER_PID));
                IntPtr rowPtr = (IntPtr)((long)buffTable + Marshal.SizeOf(table.dwNumEntries));
                tcpConnectionRows = new MIB_TCPROW_OWNER_PID[table.dwNumEntries];

                for (int i = 0; i < table.dwNumEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    tcpConnectionRows[i] = tcpRow;
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(tcpRow));
                }
            }
            finally
            {
                // free memory
                Marshal.FreeHGlobal(buffTable);
            }
            return tcpConnectionRows;
        }
        public static MIB_UDPROW_OWNER_PID[] GetAllUdpConnections()
        {
            MIB_UDPROW_OWNER_PID[] udpConnectionRows;
            int AF_INET = 2; // IP_v4
            int buffSize = 0;
            uint ret = GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, AF_INET, UDP_TABLE_TYPE.UDP_TABLE_OWNER_PID, 0);
            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);
            try
            {
                ret = GetExtendedUdpTable(buffTable, ref buffSize, true, AF_INET, UDP_TABLE_TYPE.UDP_TABLE_OWNER_PID, 0);
                if (ret != 0)
                {//none found
                    MIB_UDPROW_OWNER_PID[] con = new MIB_UDPROW_OWNER_PID[0];
                    return con;
                }
                MIB_UDPTABLE_OWNER_PID tab = (MIB_UDPTABLE_OWNER_PID)Marshal.PtrToStructure(buffTable, typeof(MIB_UDPTABLE_OWNER_PID));
                IntPtr rowPtr = (IntPtr)((long)buffTable + Marshal.SizeOf(tab.dwNumEntries));
                udpConnectionRows = new MIB_UDPROW_OWNER_PID[tab.dwNumEntries];

                for (int i = 0; i < tab.dwNumEntries; i++)
                {
                    MIB_UDPROW_OWNER_PID udprow = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_PID));
                    udpConnectionRows[i] = udprow;
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(udprow));
                }
            }
            finally
            { 
                Marshal.FreeHGlobal(buffTable); 
            }
            return udpConnectionRows;
        }
    }
}

public enum TCP_TABLE_TYPE : int
{
    TCP_TABLE_BASIC_LISTENER,
    TCP_TABLE_BASIC_CONNECTIONS,
    TCP_TABLE_BASIC_ALL,
    TCP_TABLE_OWNER_PID_LISTENER,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
    TCP_TABLE_OWNER_PID_ALL,
    TCP_TABLE_OWNER_MODULE_LISTENER,
    TCP_TABLE_OWNER_MODULE_CONNECTIONS,
    TCP_TABLE_OWNER_MODULE_ALL
}

enum UDP_TABLE_TYPE
{
    UDP_TABLE_BASIC,
    UDP_TABLE_OWNER_PID,
    UDP_OWNER_MODULE
}

public enum TCP_CONNECTION_STATE : int
{
    CLOSED = 1,
    LISTENING,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    DELETE_TCP
};