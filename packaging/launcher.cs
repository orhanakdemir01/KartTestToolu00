// KartTest launcher — bundle'lanan Node sunucusunu GİZLİ (konsol penceresi yok)
// başlatır ve bir sistem-tepsisi (tray) simgesi gösterir. Kullanıcı tarayıcıdan
// çalışır; tepsi simgesinden "Aç" veya "Çıkış" yapar. -target:winexe ile derlenir,
// yani launcher'ın kendisi de konsol açmaz.
using System;
using System.Diagnostics;
using System.IO;
using System.Drawing;
using System.Windows.Forms;

class KartTest {
    static Process server;
    const string url = "http://localhost:3001/";

    [STAThread]
    static void Main() {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string node    = Path.Combine(baseDir, "runtime", "node.exe");
        string srv     = Path.Combine(baseDir, "app", "backend", "server.js");
        string workdir = Path.Combine(baseDir, "app", "backend");

        if (!File.Exists(node) || !File.Exists(srv)) {
            MessageBox.Show("Gerekli dosyalar bulunamadı:\n" + node + "\n" + srv,
                            "KartTest", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        try {
            var psi = new ProcessStartInfo {
                FileName         = node,
                Arguments        = "\"" + srv + "\"",
                WorkingDirectory = workdir,
                UseShellExecute  = false,
                CreateNoWindow   = true,                      // konsol penceresi gösterme
                WindowStyle      = ProcessWindowStyle.Hidden
            };
            psi.EnvironmentVariables["KARTTEST_STANDALONE"] = "1";
            server = Process.Start(psi);
            // Sunucu (node) beklenmedik şekilde kapanırsa tepsi simgesi de kapansın.
            server.EnableRaisingEvents = true;
            server.Exited += delegate { try { Application.Exit(); } catch { } };
        } catch (Exception ex) {
            MessageBox.Show("KartTest başlatılamadı:\n" + ex.Message,
                            "KartTest", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Sistem tepsisi menüsü: Aç / Çıkış
        var menu = new ContextMenu();
        menu.MenuItems.Add("KartTest'i Aç", delegate { OpenBrowser(); });
        menu.MenuItems.Add("-");
        menu.MenuItems.Add("Çıkış", delegate { Quit(); });

        Icon ico;
        try { ico = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
        catch { ico = SystemIcons.Application; }

        var tray = new NotifyIcon {
            Icon = ico,
            Text = "KartTest — çalışıyor (çift tık: aç)",
            Visible = true,
            ContextMenu = menu
        };
        tray.DoubleClick += delegate { OpenBrowser(); };

        // Çıkışta tepsi simgesini kaldır ve sunucuyu durdur.
        Application.ApplicationExit += delegate {
            tray.Visible = false;
            try { if (server != null && !server.HasExited) server.Kill(); } catch { }
        };

        Application.Run();   // mesaj döngüsü — tepsi simgesi bu sayede yaşar
    }

    static void OpenBrowser() {
        try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); } catch { }
    }

    static void Quit() {
        try { if (server != null && !server.HasExited) server.Kill(); } catch { }
        Application.Exit();
    }
}
