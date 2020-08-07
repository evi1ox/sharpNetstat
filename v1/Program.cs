using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;

namespace ConnectionMonitor
{
    class Program
    {
        public static int MaxColumn = 0;
        static void Main(string[] args)
        {

            if ((args.Length == 2) && (args[0] == "listen" || args[1] == "listen") && (args[0] == "monitor" || args[1] == "monitor"))
            {
                Console.Clear();
                MonitorTcpConnections(true, true);
            }
            else if ((args.Length == 1) && (args[0] == "listen"))
            {
                TcpConnections(true);
            }
            else if ((args.Length == 1) && (args[0] == "monitor"))
            {
                Console.Clear();
                MonitorTcpConnections(false, true);
            }
            else
            {
                TcpConnections(false);
            }
        }

        static void TcpConnections(bool listen)
        {
            Console.WriteLine("Proto  Local Address          Foreign Address        State           PID        USER                 Command");
            List<String> rows = new List<string>();
            int windowTop = Console.WindowTop;  //in order to keep console scroll bar stay
            TcpConnectionTableHelper.MIB_TCPROW_OWNER_PID[] tcpProgressInfoTable = TcpConnectionTableHelper.GetAllTcpConnections();
            int tableRowCount = tcpProgressInfoTable.Length;
            for (int i = 0; i < tableRowCount; i++)
            {
                TcpConnectionTableHelper.MIB_TCPROW_OWNER_PID row = tcpProgressInfoTable[i];
                if (listen)
                {
                    if (TcpConnectionTableHelper.GetIpAddress(row.localAddr) != "0.0.0.0")
                    {
                        continue;
                    }
                }
                string Command = GetCommandLine(row.owningPid);
                string UserName = GetProcessUserName(row.owningPid);
                string source = string.Format("{0}:{1}", TcpConnectionTableHelper.GetIpAddress(row.localAddr), row.LocalPort);
                string dest = string.Format("{0}:{1}", TcpConnectionTableHelper.GetIpAddress(row.remoteAddr), row.RemotePort);
                string outputRow = string.Format("{0, -7}{1, -23}{2, -23}{3, -16}{4, -10} {5, -20} {6}", "TCP", source, dest, (TCP_CONNECTION_STATE)row.state, row.owningPid, UserName, Command);

                Console.WriteLine(outputRow);
            }
            //获取udp信息
            // TcpConnectionTableHelper.MIB_UDPROW_OWNER_PID[] udpProgressInfoTable = TcpConnectionTableHelper.GetAllUdpConnections();
            // int udptableRowCount = udpProgressInfoTable.Length;
            // for (int i = 0; i < udptableRowCount; i++)
            // {
            //     TcpConnectionTableHelper.MIB_UDPROW_OWNER_PID row = udpProgressInfoTable[i];
            //     if (listen)
            //     {
            //         if (TcpConnectionTableHelper.GetIpAddress(row.dwLocalAddr) != "0.0.0.0")
            //         {
            //             continue;
            //         }
            //     }
            //     string Command = GetCommandLine(int.Parse(row.dwOwningPid + ""));
            //     string UserName = GetProcessUserName(int.Parse(row.dwOwningPid + ""));
            //     string source = string.Format("{0}:{1}", TcpConnectionTableHelper.GetIpAddress(row.dwLocalAddr), row.dwLocalPort);
            //     string dest = string.Format("{0}:{1}", "*", "*");
            //     string outputRow = string.Format("{0, -7}{1, -23}{2, -23}{3, -16}{4, -10} {5, -20} {6}", "UDP", source, dest, "", row.dwOwningPid, UserName, Command);

            //     Console.WriteLine(outputRow);
            // }

        }


        static void MonitorTcpConnections(bool listen,bool Monitors)
        {
            Console.WriteLine("Proto  Local Address          Foreign Address        State           PID        USER                 Command");
            List<String> rows = new List<string>();
            while (true)
            {
                int windowTop = Console.WindowTop;  //in order to keep console scroll bar stay
                TcpConnectionTableHelper.MIB_TCPROW_OWNER_PID[] tcpProgressInfoTable = TcpConnectionTableHelper.GetAllTcpConnections();
                int tableRowCount = tcpProgressInfoTable.Length;
                if (tableRowCount > Program.MaxColumn)
                {
                    Program.MaxColumn = tableRowCount;
                }

                for (int i = 0; i < tableRowCount; i++)
                {
                    TcpConnectionTableHelper.MIB_TCPROW_OWNER_PID row = tcpProgressInfoTable[i];

                    if (listen) {
                        if (TcpConnectionTableHelper.GetIpAddress(row.localAddr) != "0.0.0.0" )
                        {
                            continue;
                        }
                    }
                    string Command = GetCommandLine(row.owningPid);
                    string UserName = GetProcessUserName(row.owningPid);
                    string source = string.Format("{0}:{1}", TcpConnectionTableHelper.GetIpAddress(row.localAddr), row.LocalPort);
                    string dest = string.Format("{0}:{1}", TcpConnectionTableHelper.GetIpAddress(row.remoteAddr), row.RemotePort);
                    string outputRow = string.Format("{0, -7}{1, -23}{2, -23}{3, -16}{4, -10} {5, -20} {6}", "TCP", source, dest, (TCP_CONNECTION_STATE)row.state, row.owningPid, UserName, Command);
                    if (rows.Count < i + 1)
                    {
                        Console.SetCursorPosition(0, i + 1);
                        Console.WriteLine("{0, -200}", outputRow);
                        rows.Add(outputRow);
                    }
                    else if (rows[i] != outputRow)
                    {
                        rows[i] = outputRow;
                        Console.SetCursorPosition(0, i + 1);
                        Console.WriteLine("{0, -200}", outputRow);
                    }
                }
                if (rows.Count > tableRowCount)
                {
                    int linesToBeCleared = rows.Count - tableRowCount;
                    rows.RemoveRange(tableRowCount, linesToBeCleared);
                    for (int i = 0; i < linesToBeCleared + 1; i++)
                    {
                        Console.WriteLine("{0, -200}", " ");
                    }
                }
                Console.SetWindowPosition(0, windowTop);    //in order to keep console scroll bar stay
                Thread.Sleep(100);
                if (!Monitors)
                {
                    System.Environment.Exit(0);
                }
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
}
