import { useEffect, useState } from 'react';
import { API } from '../lib/api.js';
import { getRemoteToken, setRemoteToken, AUTH_REQUIRED_EVENT } from '../lib/remoteAuth.js';

// Header widget for the remote-control feature. On the host machine (the PC
// with the reader attached) it reveals the LAN URL + pairing token to share.
// On a remote client it prompts for that token and stores it for future
// requests — auto-opening whenever the backend rejects a call as unauthorized.
export function RemoteAccessPanel() {
  const [open, setOpen] = useState(false);
  const [hostInfo, setHostInfo] = useState(null);
  const [tokenInput, setTokenInput] = useState(getRemoteToken());
  const [needsToken, setNeedsToken] = useState(false);

  useEffect(() => {
    fetch(`${API}/remote/info`).then((r) => (r.ok ? r.json() : null)).then((d) => d && setHostInfo(d)).catch(() => {});
  }, []);

  useEffect(() => {
    const onAuthRequired = () => { setNeedsToken(true); setOpen(true); };
    window.addEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
  }, []);

  const save = () => {
    setRemoteToken(tokenInput.trim());
    setNeedsToken(false);
    window.location.reload();
  };

  return (
    <>
      <button className="chip chip-remote" onClick={() => setOpen((v) => !v)} title="Uzaktan erişim ayarları">
        🌐 Uzaktan Erişim
      </button>
      {open && (
        <div className="remote-panel-backdrop" onClick={() => setOpen(false)}>
          <div className="remote-panel" onClick={(e) => e.stopPropagation()}>
            <h3>Uzaktan Erişim</h3>
            {hostInfo ? (
              <>
                <p>Bu makine kart okuyucuyu barındırıyor. Aynı ağdaki başka bir cihazdan tarayıcıyla aşağıdaki adrese bağlanıp token'ı girerek kontrol edebilirsiniz:</p>
                {hostInfo.lanUrls.length
                  ? <ul className="remote-url-list">{hostInfo.lanUrls.map((u) => <li key={u}><code>{u}</code></li>)}</ul>
                  : <p className="remote-warn">Ağ arayüzü bulunamadı (yalnızca bu bilgisayardan erişilebilir).</p>}
                <p>Erişim token'ı:</p>
                <code className="remote-token">{hostInfo.token}</code>
              </>
            ) : (
              <>
                {needsToken && <p className="remote-warn">Bu sunucuya uzaktan erişim için geçerli bir token gerekiyor.</p>}
                <p>Kart okuyucuyu barındıran bilgisayarda gösterilen erişim token'ını girin:</p>
                <input
                  className="remote-token-input"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  placeholder="Erişim token'ı"
                  onKeyDown={(e) => e.key === 'Enter' && save()}
                />
                <button className="remote-save" onClick={save} disabled={!tokenInput.trim()}>Kaydet ve bağlan</button>
              </>
            )}
            <button className="remote-close" onClick={() => setOpen(false)}>Kapat</button>
          </div>
        </div>
      )}
    </>
  );
}
