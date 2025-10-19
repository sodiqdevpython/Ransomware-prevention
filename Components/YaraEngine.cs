using Components;
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.Threading;
using YaraClient;

namespace ransomware.Components
{
    public class YaraEngine
    {
        public static void Run()
        {

            string rulesPath = @"C:\yara_rules\ransomware.yar";
            string yaraDllDir = @"C:\yara_rules";
            string[] wantedExts = { ".exe", ".dll", ".bat", ".cmd" };
            string[] excludes = { @"\Windows\WinSxS", @"\node_modules" };
            int cpuCount = 0;

            var checker = new YaraChecker(rulesPath, wantedExts, excludes, dllDir: yaraDllDir, cpuCount: cpuCount);
            var cts = new CancellationTokenSource();

            ProcessWatcher.OnProcess += async (image, cmd, parentImage, pid, ppid) =>
            {
                if (parentImage != null && parentImage.Contains("explorer.exe"))
                {
                    try
                    {
                        var result = await checker.CheckFileAsync(image, cts.Token);

                        if (result.Length > 0)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[YARA rule ga tushdi] {image}");
                            Console.WriteLine(JsonConvert.SerializeObject(result, Formatting.Indented));
                            Console.ResetColor();

                            // Yara ga tushdi endi shu pid ni kill qildim
                            Process process = Process.GetProcessById(pid);
                            if(process != null)
                            {
                                process.Kill();
                                Console.WriteLine($"Bu procces yopildi pid={pid}");
                                Console.WriteLine($"Endi {pid} ochgan proccesslar qidirayabdi");
                            }
                            else
                            {
                                Console.WriteLine($"Bunday pid topilmadi={pid}");
                            }
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[OK] {image} - toza");
                            Console.ResetColor();
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"YARA tekshiruvda xatolik: {ex.Message}");
                        Console.ResetColor();
                    }
                }
            };


            ProcessWatcher.Start();
            Console.WriteLine("ProcessWatcher ishlamoqda...\n");

            Console.ReadLine();

            ProcessWatcher.Stop();
            Console.WriteLine("ProcessWatcher to‘xtatildi.");

            YaraScanManager.FinalizeYara();

        }
    }
}
