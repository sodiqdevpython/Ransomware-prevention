using System;

class Program
{
    static void Main(string[] args)
    {
        Components.ProcessWatcher.OnProcess += (image, cmd, parentImage, pid, ppid) =>
        {
            Console.WriteLine(
                $"Image: {image}\nCommandLine: {cmd}\nParentImage: {parentImage}\npid={pid}, ppid={ppid}\n"
            );
        };

        Components.ProcessWatcher.Start();

        Console.WriteLine("ProcessWatcher ishlamoqda... Enter bosilsa to‘xtaydi.");
        Console.ReadLine();

        Components.ProcessWatcher.Stop();
    }
}
