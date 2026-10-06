// W4.12 (#135) spike: a throwaway Windows service that runs ONE command line as the
// service's own account (LocalSystem or a virtual account), so the Worker's restore
// credential export can be tried from a real service process. It takes the command from
// <outDir>\command.txt (one line: the exe; then one argument per line; no secret in it),
// the secrets as NAME=VALUE lines from a named pipe the elevated shell serves (never
// from disk, the registry or the command line), writes the child's stdout, stderr and
// exit code to <outDir>, and stops itself. Deleted at the end of the spike.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public class RpSpikeHost : ServiceBase
{
    static string[] g_args;

    public static void Main(string[] args)
    {
        g_args = args;
        ServiceBase.Run(new RpSpikeHost());
    }

    public RpSpikeHost()
    {
        ServiceName = "RpSpikeProbe";
        CanStop = true;
    }

    protected override void OnStart(string[] startArgs)
    {
        var t = new Thread(Work);
        t.IsBackground = true;
        t.Start();
    }

    protected override void OnStop() { }

    static string Quote(string a)
    {
        if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
        return "\"" + a.Replace("\\\"", "\\\\\"").Replace("\"", "\\\"") + "\"";
    }

    void Work()
    {
        string outDir = g_args[0];
        string pipe = g_args[1];
        string log = Path.Combine(outDir, "host.log");
        var enc = new UTF8Encoding(false);
        int exit = -1;
        try
        {
            File.WriteAllText(log, "host identity: " + WindowsIdentity.GetCurrent().Name +
                " session " + Process.GetCurrentProcess().SessionId + "\r\n", enc);
            var lines = File.ReadAllLines(Path.Combine(outDir, "command.txt"));
            var psi = new ProcessStartInfo(lines[0]);
            var rest = new List<string>();
            for (int i = 1; i < lines.Length; i++) if (lines[i].Length > 0) rest.Add(Quote(lines[i]));
            psi.Arguments = string.Join(" ", rest);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = enc;
            psi.StandardErrorEncoding = enc;
            psi.WorkingDirectory = outDir;
            psi.EnvironmentVariables["TEMP"] = outDir;
            psi.EnvironmentVariables["TMP"] = outDir;
            int n = 0;
            using (var client = new NamedPipeClientStream(".", pipe, PipeDirection.In, PipeOptions.None,
                                                          TokenImpersonationLevel.Identification))
            {
                client.Connect(120000);
                using (var r = new StreamReader(client, enc))
                {
                    string line;
                    while ((line = r.ReadLine()) != null)
                    {
                        int eq = line.IndexOf('=');
                        if (eq <= 0) continue;
                        psi.EnvironmentVariables[line.Substring(0, eq)] = line.Substring(eq + 1);
                        n++;
                    }
                }
            }
            File.AppendAllText(log, "secrets: " + n + " variable(s) taken from the pipe\r\n", enc);
            File.AppendAllText(log, "command: " + lines[0] + " " + psi.Arguments + "\r\n", enc);
            using (var p = Process.Start(psi))
            {
                Task<string> so = p.StandardOutput.ReadToEndAsync();
                Task<string> se = p.StandardError.ReadToEndAsync();
                p.WaitForExit();
                File.WriteAllText(Path.Combine(outDir, "stdout.txt"), so.Result, enc);
                File.WriteAllText(Path.Combine(outDir, "stderr.txt"), se.Result, enc);
                exit = p.ExitCode;
            }
            File.AppendAllText(log, "child exit code: " + exit + "\r\n", enc);
        }
        catch (Exception e)
        {
            File.AppendAllText(log, "host error: " + e + "\r\n", enc);
        }
        File.WriteAllText(Path.Combine(outDir, "exit.txt"), exit.ToString(), enc);
        Stop();
    }
}
