﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

using DInvoke.DynamicInvoke;

using MonkeyWorks.Unmanaged.Libraries.DInvoke;

namespace MonkeyWorks.Resources
{
    static class Misc
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Finds an exe in command
        ////////////////////////////////////////////////////////////////////////////////
        public static void FindExe(ref string command, out string arguments)
        {
            arguments = "";
            if (command.Contains(" "))
            {
                string[] commandAndArguments = command.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                command = commandAndArguments.First();
                arguments = string.Join(" ", commandAndArguments.Skip(1).Take(commandAndArguments.Length - 1).ToArray());
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal static string GenerateUuid(int length)
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        #region Error Reporting
        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetLsaNtError(string location, uint ntError)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // uint win32Error = advapi32.LsaNtStatusToWinError(ntError);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            IntPtr hLsaNtStatusToWinError = Generic.GetExportAddress(hadvapi32, "LsaNtStatusToWinError");
            advapi32.LsaNtStatusToWinError fLsaNtStatusToWinError = (advapi32.LsaNtStatusToWinError)Marshal.GetDelegateForFunctionPointer(hLsaNtStatusToWinError, typeof(advapi32.LsaNtStatusToWinError));

            uint win32Error = 0;
            try
            {
                win32Error = fLsaNtStatusToWinError(ntError);
            }
            catch (Exception ex)
            {
                GetExceptionMessage(ex, "LsaNtStatusToWinError");
                return;
            }

            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception((int)win32Error).Message);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetNetApiError(string location, uint netError)
        {
            if (1722 == netError)
            {
                Console.WriteLine("[*] Unable to contact Domain Controller");
            }
            else
            {
                Console.WriteLine(" [-] Function {0} failed: ", location);
                Console.WriteLine(" [-] {0}", (netapi32.NET_API_STATUS)netError);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetNtError(string location, uint ntError)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // uint win32Error = advapi32.LsaNtStatusToWinError(ntError);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hntdll = Generic.GetPebLdrModuleEntry("ntdll.dll");
            IntPtr hRtlNtStatusToDosError = Generic.GetExportAddress(hntdll, "RtlNtStatusToDosError");
            ntdll.RtlNtStatusToDosError fRtlNtStatusToDosError = (ntdll.RtlNtStatusToDosError)Marshal.GetDelegateForFunctionPointer(hRtlNtStatusToDosError, typeof(ntdll.RtlNtStatusToDosError));


            uint win32Error;
            try
            {
                win32Error = fRtlNtStatusToDosError(ntError);
            }
            catch (Exception ex)
            {
                GetExceptionMessage(ex, "RtlNtStatusToDosError");
                return;
            }

            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0} (0x{1})", new System.ComponentModel.Win32Exception((int)win32Error).Message, ntError.ToString("X4"));
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetWin32Error(string location)
        {
            Console.WriteLine(" [-] Function {0} failed: ", location);
            int error = Marshal.GetLastWin32Error();
            Console.WriteLine(" [-] {0} (0x{1})", new System.ComponentModel.Win32Exception(error).Message, error.ToString("X4"));
        }

        public static void GetExceptionMessage(Exception ex, string location)
        {
            Console.WriteLine("[-] {0} Generated an Exception", location);
            Console.WriteLine("[-] {0}", ex.Message);
        }

        #endregion

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static uint GetProcessId(string processName)
        {
            uint ProcessId = 0;

            List<ManagementObject> systemProcesses = new List<ManagementObject>();
            ManagementScope scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            if (!scope.IsConnected)
            {
                Console.WriteLine("[-] Failed to connect to WMI");
            }

            Console.WriteLine(" [*] Querying for service: " + processName);
            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Service WHERE Name = \'" + processName + "\'");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();
            if (objectCollection == null)
            {
                Console.WriteLine("ManagementObjectCollection");
            }
            foreach (ManagementObject managementObject in objectCollection)
            {
                ProcessId = (uint)managementObject["ProcessId"];
            }
            Console.WriteLine(" [+] Returned PID: " + ProcessId);
            return ProcessId;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Pops an item from the input and returns the item - only used in inital menu
        // Taken from FowlPlay
        ////////////////////////////////////////////////////////////////////////////////
        public static string NextItem(ref string input)
        {
            string option = string.Empty;
            string[] options = input.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
            if (options.Length > 1)
            {
                option = options[0];
                input = string.Join(" ", options, 1, options.Length - 1);
            }
            else
            {
                option = input;
            }
            return option.ToLower();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Pops an item from the input and returns the item - only used in inital menu
        // Taken from FowlPlay
        ////////////////////////////////////////////////////////////////////////////////
        public static string NextItemPreserveCase(ref string input)
        {
            string option = string.Empty;
            string[] options = input.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
            if (options.Length > 1)
            {
                option = options[0];
                input = string.Join(" ", options, 1, options.Length - 1);
            }
            else
            {
                option = input;
            }
            return option;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // https://stackoverflow.com/questions/16100/convert-a-string-to-an-enum-in-c-sharp
        ////////////////////////////////////////////////////////////////////////////////
        public static T ParseEnum<T>(string value)
        {
            return (T)Enum.Parse(typeof(T), value, true);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Print a struct
        ////////////////////////////////////////////////////////////////////////////////
        public static void PrintStruct<T>(T printMe)
        {
            System.Reflection.FieldInfo[] fields = printMe.GetType().GetFields();
            Console.WriteLine("==========");
            foreach (var xInfo in fields)
            {
                try
                {
                    Console.WriteLine("Field    {0,-30}    {1,-20}", xInfo.Name, xInfo.GetValue(printMe).ToString());
                }
                catch (NullReferenceException)
                {
                    Console.WriteLine("Field    {0,-30}    {1,-20}", xInfo.Name, string.Empty);
                }
            }
            Console.WriteLine("==========");
        }

        public static int GetFieldOffset<T>(T input, string fieldName)
        {
            int sum = 0;

            System.Reflection.FieldInfo[] fields = input.GetType().GetFields();

            foreach (var xInfo in fields)
            {
                Console.WriteLine("Field    {0,-30}    {1, -10}    {,-20}", xInfo.Name, Marshal.SizeOf(xInfo.FieldType), xInfo.GetValue(input).ToString());
                if (xInfo.Name == fieldName)
                {
                    return sum;
                }
                sum += Marshal.SizeOf(xInfo.FieldType);
            }
            return sum;
        }

        //https://stackoverflow.com/questions/1343704/casting-c-sharp-out-parameters
        static bool TryGetTypedValue<TKey, TValue, TActual>(this System.Collections.Generic.IDictionary<TKey, TValue> data, TKey key, out TActual value) where TActual : TValue
        {
            TValue tmp;
            if (data.TryGetValue(key, out tmp))
            {
                value = (TActual)tmp;
                return true;
            }
            value = default(TActual);
            return false;
        }
    }
}