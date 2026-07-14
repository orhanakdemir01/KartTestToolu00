// KartTest launcher — starts the bundled Node server in standalone mode.
// Compiled to a native Windows .exe with the built-in .NET C# compiler (csc).
// The Node server serves the frontend and opens the browser itself.
using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

class KartTest {
    [STAThread]
    static void Main() {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string node    = Path.Combine(baseDir, "runtime", "node.exe");
        string server  = Path.Combine(baseDir, "app", "backend", "server.js");
        string workdir = Path.Combine(baseDir, "app", "backend");

        if (!File.Exists(node) || !File.Exists(server)) {
            MessageBox.Show("Gerekli dosyalar bulunamadı:\n" + node + "\n" + server,
                            "KartTest", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        try {
            var psi = new ProcessStartInfo {
                FileName         = node,
                Arguments        = "\"" + server + "\"",
                WorkingDirectory = workdir,
                UseShellExecute  = false,   // inherit env, give the console app its own new window
                CreateNoWindow   = false
            };
            psi.EnvironmentVariables["KARTTEST_STANDALONE"] = "1";
            Process.Start(psi);
        } catch (Exception ex) {
            MessageBox.Show("KartTest başlatılamadı:\n" + ex.Message,
                            "KartTest", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
