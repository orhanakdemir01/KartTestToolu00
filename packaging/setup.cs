// KartTest self-installing Setup.exe. A small C# stub with the whole app folder
// embedded as a zip resource ("payload.zip"). On run it extracts to
// %LOCALAPPDATA%\KartTest, creates Desktop + Start Menu shortcuts, and offers to
// launch. Compiled with the built-in .NET csc — no internet / toolchain needed.
using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Diagnostics;
using System.Windows.Forms;

class Setup {
    const string APP = "KartTest";

    [STAThread]
    static void Main() {
        try {
            string target = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), APP);

            // Fresh extract (best effort — remove old install first).
            if (Directory.Exists(target)) {
                try { Directory.Delete(target, true); }
                catch { throw new Exception(APP + " çalışıyor olabilir. Lütfen kapatıp tekrar deneyin."); }
            }
            Directory.CreateDirectory(target);

            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
            using (ZipArchive zip = new ZipArchive(s, ZipArchiveMode.Read)) {
                zip.ExtractToDirectory(target);
            }

            string exe = Path.Combine(target, APP + ".exe");
            if (!File.Exists(exe)) throw new Exception("Kurulum bozuk: " + exe + " bulunamadı.");

            // Desktop + Start Menu shortcuts.
            CreateShortcut(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop), APP + ".lnk"), exe);
            string sm = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), APP);
            Directory.CreateDirectory(sm);
            CreateShortcut(Path.Combine(sm, APP + ".lnk"), exe);

            var r = MessageBox.Show(
                APP + " kuruldu:\n" + target + "\n\nMasaüstü ve Başlat Menüsü kısayolları oluşturuldu.\nŞimdi başlatılsın mı?",
                APP + " Kurulum", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (r == DialogResult.Yes) Process.Start(new ProcessStartInfo { FileName = exe, UseShellExecute = true });
        } catch (Exception ex) {
            MessageBox.Show("Kurulum hatası:\n" + ex.Message, APP, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    // Create a .lnk via WScript.Shell (late-bound, no COM reference needed).
    static void CreateShortcut(string lnk, string targetExe) {
        Type t = Type.GetTypeFromProgID("WScript.Shell");
        object shell = Activator.CreateInstance(t);
        object sc = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnk });
        Type st = sc.GetType();
        st.InvokeMember("TargetPath", BindingFlags.SetProperty, null, sc, new object[] { targetExe });
        st.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, sc, new object[] { Path.GetDirectoryName(targetExe) });
        st.InvokeMember("Description", BindingFlags.SetProperty, null, sc, new object[] { "KartTest — Smart Card / EMV Test Tool" });
        st.InvokeMember("Save", BindingFlags.InvokeMethod, null, sc, null);
    }
}
