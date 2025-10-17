using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Components
{
    public static class ProcessWatcher
    {
        private static TraceEventSession _session;
        private static Thread _thread;
        private static bool _running;

        public static event Action<string, string, string, int, int> OnProcess;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public static void Start()
        {
            if (TraceEventSession.IsElevated() == false)
            {
                Console.WriteLine("Run as Administrator");
                return;
            }

            if (_running) return;
            _running = true;

            _session = new TraceEventSession("SimpleProcWatch") { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

            var src = _session.Source;

            src.Kernel.ProcessStart += data =>
            {
                try
                {
                    string image = GetPath(data.ProcessID);
                    string parentImage = GetPath(data.ParentID);
                    string cmd = data.CommandLine ?? "";

                    if (OnProcess != null)
                        OnProcess(image, cmd, parentImage, data.ProcessID, data.ParentID);
                }
                catch { }
            };

            _thread = new Thread(() => src.Process())
            {
                IsBackground = true,
                Name = "ETW_ProcessWatcher"
            };
            _thread.Start();
        }

        public static void Stop()
        {
            if (!_running) return;
            _running = false;
            try
            {
                _session.Dispose();
                _thread.Join(500);
            }
            catch { }
        }

        private static string GetPath(int pid)
        {
            if (pid <= 0) return "";
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return "";
                var sb = new StringBuilder(512);
                int size = sb.Capacity;
                if (QueryFullProcessImageName(h, 0, sb, ref size))
                    return sb.ToString();
            }
            catch
            {
                try
                {
                    using (var p = Process.GetProcessById(pid))
                        return p.MainModule?.FileName ?? "";
                }
                catch { }
            }
            finally
            {
                if (h != IntPtr.Zero) CloseHandle(h);
            }
            return "";
        }
    }
}
