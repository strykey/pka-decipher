import sys, os, threading, zlib, struct, re, json, shutil

_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _DIR)

try:
    from Decipher.pt_crypto import decrypt_pkt
    from Decipher.eax import EAX
    from Decipher.twofish import Twofish
    _CRYPTO_OK = True
except ImportError as e:
    _CRYPTO_OK = False
    _CRYPTO_ERR = str(e)

import webview


def _compress_qt(data):
    return struct.pack(">I", len(data)) + zlib.compress(data)

def _obf_stage2(data):
    L = len(data)
    return bytes(b ^ (L - i & 0xFF) for i, b in enumerate(data))

def _obf_stage1(data):
    L = len(data); o = bytearray(L)
    for i in range(L):
        o[L-1-i] = data[i] ^ ((L - i*L) & 0xFF)
    return bytes(o)

def pka_to_xml(path):
    with open(path, "rb") as f: raw = f.read()
    return decrypt_pkt(raw).decode("latin-1")

def xml_to_pka(xml_str):
    key = bytes([137])*16; iv = bytes([16])*16
    tf = Twofish(key); eax = EAX(tf.encrypt)
    data = xml_str.encode("latin-1")
    qt = _compress_qt(data)
    s2 = _obf_stage2(qt)
    ct, tag = eax.encrypt(nonce=iv, plaintext=s2)
    return _obf_stage1(ct + tag)

def patch_xml(xml_str):
    m = re.search(r'<COMPARISONS>(.*?)</COMPARISONS>', xml_str, re.DOTALL)
    if not m: raise ValueError("COMPARISONS block not found.")
    nb = len(re.findall(r'<NODE>', m.group(1)))
    new = (
        '<COMPARISONS>\n  <NODE>\n'
        '   <NAME nodeValue="" checkType="1" variableName="" headNode="true" '
        'eclass="8" variableEnabled="false" incorrectFeedback="">Network</n>\n'
        '   <ID>Network</ID>\n   <COMPONENTS/>\n   <POINTS>100</POINTS>\n'
        '  </NODE>\n </COMPARISONS>'
    )
    return xml_str[:m.start()] + new + xml_str[m.end():], nb


class API:
    def __init__(self): self._w = None
    def set_window(self, w): self._w = w

    def check_crypto(self):
        return {"ok": _CRYPTO_OK, "err": "" if _CRYPTO_OK else _CRYPTO_ERR}

    def pick_file(self):

        try:
            r = self._w.create_file_dialog(
                webview.OPEN_DIALOG, allow_multiple=False,
                file_types=("Packet Tracer (*.pka;*.pkt)", "All files (*.*)")
            )
            if r:
                return r[0]
        except Exception:
            pass
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            path = filedialog.askopenfilename(
                title="Select Packet Tracer file",
                filetypes=[("Packet Tracer", "*.pka *.pkt"), ("All files", "*.*")]
            )
            root.destroy()
            return path if path else None
        except Exception:
            return None

    def inject(self, src):
        def run():
            try:
                self._w.evaluate_js('setProgress(5, "Reading file...")')
                size = os.path.getsize(src)
                self._w.evaluate_js(f'setProgress(20, "{size:,} bytes loaded")')
                self._w.evaluate_js('setProgress(35, "Decrypting Twofish / EAX...")')
                xml_str = pka_to_xml(src)
                self._w.evaluate_js(f'setProgress(55, "Payload: {len(xml_str):,} chars")')
                self._w.evaluate_js('setProgress(70, "Patching nodes...")')
                patched, nb = patch_xml(xml_str)
                self._w.evaluate_js(f'setProgress(82, "{nb} nodes stripped")')
                self._w.evaluate_js('setProgress(92, "Re-encrypting...")')
                raw = xml_to_pka(patched)
                self._w.evaluate_js('setProgress(98, "Writing to disk...")')
                tmp = src + ".tmp"
                with open(tmp, "wb") as f: f.write(raw)
                shutil.move(tmp, src)
                self._w.evaluate_js('setProgress(100, "Done")')
                self._w.evaluate_js(f'onDone({json.dumps(os.path.basename(src))})')
            except Exception as e:
                self._w.evaluate_js(f'onError({json.dumps(str(e))})')
        threading.Thread(target=run, daemon=True).start()


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PKA Injector</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&family=Inter:wght@300;400;500&display=swap');

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:   #1a1c2a;
  --card: rgba(255,255,255,0.04);
  --brd:  rgba(255,255,255,0.08);
  --brd2: rgba(255,255,255,0.14);
  --a:    #e8dcc8;
  --a2:   #fff8ec;
  --fg:   #c8cdd8;
  --fg2:  #5e6478;
  --ok:   #7ec8a0;
  --err:  #e07878;
  --px:   'Press Start 2P',monospace;
  --ui:   'Inter',sans-serif;
}

html,body{height:100%;overflow:hidden;font-family:var(--px);color:var(--fg)}

/* Parallax orbs */
.orb{position:fixed;border-radius:50%;filter:blur(90px);pointer-events:none;z-index:1;animation:drift linear infinite}
.orb1{width:280px;height:280px;background:rgba(110,120,210,.07);top:-80px;left:-80px;animation-duration:20s}
.orb2{width:200px;height:200px;background:rgba(170,150,240,.05);bottom:-50px;right:-50px;animation-duration:26s;animation-delay:-10s}
.orb3{width:120px;height:120px;background:rgba(200,215,180,.04);top:42%;left:62%;animation-duration:32s;animation-delay:-16s}
@keyframes drift{
  0%{transform:translate(0,0) scale(1)}
  33%{transform:translate(16px,-12px) scale(1.04)}
  66%{transform:translate(-10px,18px) scale(.97)}
  100%{transform:translate(0,0) scale(1)}
}

/* Rain bg */
.rain-bg{
  position:fixed;inset:0;z-index:0;
  background:url('https://mir-s3-cdn-cf.behance.net/project_modules/disp/cca1e136569841.5720ffd3c7679.gif') center/cover no-repeat;
  opacity:.28;
}
.rain-overlay{
  position:fixed;inset:0;z-index:1;
  background:radial-gradient(ellipse at 50% 35%, #1f2138 0%, #0c0e1c 75%);
  opacity:.78;
}

/* Splash */
#splash{
  position:fixed;inset:0;z-index:100;
  background:#0e1020;
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:20px;
  transition:opacity .6s ease, visibility .6s;
}
#splash.hide{opacity:0;visibility:hidden}
.splash-title{
  font-family:var(--px);font-size:11px;color:var(--a);
  letter-spacing:2px;image-rendering:pixelated;
}
.splash-sub{
  font-family:var(--px);font-size:7px;color:var(--fg2);
  letter-spacing:1px;
}
.splash-bar-track{
  width:180px;height:6px;
  background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.1);
  image-rendering:pixelated;
  overflow:hidden;
}
.splash-bar-fill{
  height:100%;width:0%;
  background:var(--a);
  transition:width .08s steps(4);
}
.splash-made{
  font-family:var(--px);font-size:6px;color:var(--fg2);
  letter-spacing:1px;margin-top:8px;
}

/* Main */
#app{
  position:relative;z-index:2;
  height:100%;display:flex;align-items:center;justify-content:center;
  opacity:0;transition:opacity .6s ease;
}
#app.show{opacity:1}

.card{
  width:420px;
  background:var(--card);
  border:1px solid var(--brd);
  backdrop-filter:blur(24px);
  -webkit-backdrop-filter:blur(24px);
  padding:32px;
  display:flex;flex-direction:column;gap:22px;
  text-align:center;
  transition:transform .12s ease-out;
  animation:cardIn .7s .2s cubic-bezier(.2,.8,.3,1) forwards;
  opacity:0;
}
@keyframes cardIn{
  from{opacity:0;transform:translateY(16px)}
  to{opacity:1;transform:translateY(0)}
}

/* Header */
.card-head{display:flex;flex-direction:column;align-items:center;gap:10px;padding-bottom:20px;border-bottom:1px solid var(--brd)}
.card-title{
  font-family:var(--px);font-size:12px;color:var(--a2);
  letter-spacing:2px;line-height:2;
}
.card-sub{font-family:var(--px);font-size:6px;color:var(--fg2);letter-spacing:.08em;line-height:2}

/* File picker */
.field-label{font-family:var(--px);font-size:7px;color:var(--fg2);letter-spacing:.1em;margin-bottom:8px}

.pick{
  border:1px solid var(--brd);
  background:rgba(255,255,255,.02);
  padding:14px 16px;cursor:pointer;
  display:flex;align-items:center;gap:12px;
  transition:border-color .2s,background .2s,transform .15s;
}
.pick:hover{border-color:var(--brd2);background:rgba(255,255,255,.05);transform:translateY(-1px)}
.pick:active{transform:translateY(0)}
.pick.loaded{border-color:rgba(232,220,200,.3)}

.pick-badge{
  font-family:var(--px);font-size:7px;color:var(--fg2);
  border:1px solid var(--brd2);padding:5px 7px;
  flex-shrink:0;letter-spacing:.05em;
  transition:color .2s,border-color .2s;
}
.pick.loaded .pick-badge{color:var(--a);border-color:rgba(232,220,200,.4)}

.pick-text{flex:1;min-width:0;text-align:left}
.pick-hint{font-family:var(--px);font-size:7px;color:var(--fg2);letter-spacing:.06em;line-height:2}
.pick.loaded .pick-hint{color:rgba(200,205,216,.3)}
.pick-name{
  font-family:var(--px);font-size:8px;color:var(--a);
  margin-top:5px;display:none;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  letter-spacing:.03em;
}
.pick.loaded .pick-name{display:block}

/* Progress */
.prog-section{display:flex;flex-direction:column;gap:8px}
.prog-head{display:flex;justify-content:space-between;align-items:center}
.prog-head span{font-family:var(--px);font-size:7px;color:var(--fg2);letter-spacing:.08em}
#prog-pct{font-family:var(--px);font-size:7px;color:var(--fg);transition:color .3s}
#prog-pct.done{color:var(--ok)}

.prog-track{
  height:4px;background:rgba(255,255,255,.05);
  border:1px solid var(--brd);overflow:hidden;
  image-rendering:pixelated;
}
#prog-fill{
  height:100%;width:0%;
  background:var(--a);
  transition:width .4s cubic-bezier(.4,0,.2,1);
  image-rendering:pixelated;
}
#prog-fill.done{background:var(--ok)}

#prog-msg{
  font-family:var(--px);font-size:7px;color:var(--fg2);letter-spacing:.06em;
  min-height:18px;transition:opacity .3s;line-height:2;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}

/* Button */
#btn{
  font-family:var(--px);font-size:9px;letter-spacing:2px;
  background:transparent;color:var(--a);
  border:1px solid rgba(232,220,200,.3);
  padding:14px;width:100%;cursor:pointer;
  transition:background .2s,color .2s,border-color .2s,transform .15s,opacity .2s;
  image-rendering:pixelated;
  position:relative;overflow:hidden;
}
#btn::after{
  content:'';position:absolute;inset:0;
  background:var(--a);opacity:0;
  transition:opacity .2s;
}
#btn:hover:not(:disabled){
  color:#1a1c2a;border-color:var(--a);
  transform:translateY(-1px);
}
#btn:hover:not(:disabled)::after{opacity:1}
#btn span{position:relative;z-index:1}
#btn:active:not(:disabled){transform:translateY(0)}
#btn:disabled{opacity:.25;cursor:default}

/* Success */
#success{
  display:none;padding:13px 15px;
  border:1px solid rgba(126,200,160,.25);
  background:rgba(126,200,160,.04);
  animation:fadeUp .4s ease forwards;
}
#success.show{display:block}
.success-lbl{font-family:var(--px);font-size:7px;color:var(--fg2);letter-spacing:.1em;margin-bottom:6px}
.success-val{font-family:var(--px);font-size:8px;color:var(--ok);letter-spacing:.04em;line-height:1.8}

/* Error */
#errbox{
  display:none;padding:12px 15px;
  border:1px solid rgba(224,120,120,.2);
  background:rgba(224,120,120,.04);
}
#errbox.show{display:block}
.err-txt{font-family:var(--px);font-size:7px;color:var(--err);line-height:2;letter-spacing:.06em}

@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}
.sp{display:inline-block;width:8px;height:8px;border:1.5px solid transparent;border-top-color:currentColor;border-radius:50%;animation:spin .5s linear infinite;vertical-align:middle;margin-right:6px}
</style>
</head>
<body>

<div class="rain-bg"></div>
<div class="rain-overlay"></div>
<div class="orb orb1"></div>
<div class="orb orb2"></div>
<div class="orb orb3"></div>

<!-- Splash -->
<div id="splash">
  <div class="splash-title">PKA INJECTOR</div>
  <div class="splash-bar-track"><div class="splash-bar-fill" id="sbar"></div></div>
  <div class="splash-sub" id="sload">LOADING INJECTOR...</div>
  <div class="splash-made">MADE BY STRYKEY</div>
</div>

<!-- App -->
<div id="app">
<div class="card">

  <div class="card-head">
    <div class="card-title">PKA INJECTOR</div>
    <div class="card-sub">Packet Tracer · strip verification nodes · 100% score</div>
  </div>

  <div>
    <div class="field-label">TARGET FILE</div>
    <div class="pick" id="pick" onclick="pickFile()">
      <div class="pick-badge">PKA</div>
      <div class="pick-text">
        <div class="pick-hint">Select a .pka or .pkt file</div>
        <div class="pick-name" id="pname"></div>
      </div>
    </div>
  </div>

  <div class="prog-section">
    <div class="prog-head">
      <span>PROGRESS</span>
      <span id="prog-pct">0%</span>
    </div>
    <div class="prog-track"><div id="prog-fill"></div></div>
    <div id="prog-msg"></div>
  </div>

  <button id="btn" disabled onclick="runInject()"><span id="btntxt">INJECT</span></button>

  <div id="success">
    <div class="success-lbl">RESULT</div>
    <div class="success-val" id="sval"></div>
  </div>
  <div id="errbox">
    <div class="err-txt" id="errtxt"></div>
  </div>

</div>
</div>

<script>
// Splash animation
(function(){
  const bar = document.getElementById('sbar');
  const lbl = document.getElementById('sload');
  const steps = [
    [0,  'LOADING INJECTOR...'],
    [30, 'LOADING CRYPTO...'],
    [60, 'INITIALIZING...'],
    [85, 'READY'],
    [100,'']
  ];
  let i = 0;
  const t = setInterval(()=>{
    if(i>=steps.length){ clearInterval(t); return; }
    bar.style.width = steps[i][0]+'%';
    if(steps[i][1]) lbl.textContent = steps[i][1];
    i++;
    if(i===steps.length){
      setTimeout(()=>{
        document.getElementById('splash').classList.add('hide');
        document.getElementById('app').classList.add('show');
      }, 300);
    }
  }, 340);
})();

let src = null;

function pickFile(){
  pywebview.api.pick_file().then(p=>{
    if(!p) return;
    src = p;
    const name = p.split(/[\\/]/).pop();
    document.getElementById('pick').classList.add('loaded');
    document.getElementById('pname').textContent = name;
    document.getElementById('btn').disabled = false;
    hide('success'); hide('errbox');
    setProgress(0,'');
  });
}

function runInject(){
  if(!src) return;
  document.getElementById('btn').disabled = true;
  document.getElementById('btntxt').innerHTML = '<span class="sp"></span>INJECTING';
  hide('success'); hide('errbox');
  setProgress(0,'');
  pywebview.api.inject(src);
}

function setProgress(pct, msg){
  const fill = document.getElementById('prog-fill');
  const pctEl = document.getElementById('prog-pct');
  fill.style.width = pct+'%';
  pctEl.textContent = pct+'%';
  if(pct===100){ fill.classList.add('done'); pctEl.classList.add('done'); }
  else { fill.classList.remove('done'); pctEl.classList.remove('done'); }
  if(msg) document.getElementById('prog-msg').textContent = msg;
}

function onDone(name){
  document.getElementById('btn').disabled = false;
  document.getElementById('btntxt').textContent = 'INJECT';
  document.getElementById('sval').textContent = name + 'INJECTION SUCCESSFUL';
  show('success');
}

function onError(msg){
  document.getElementById('btn').disabled = false;
  document.getElementById('btntxt').textContent = 'INJECT';
  document.getElementById('errtxt').textContent = msg;
  show('errbox');
}

function show(id){ document.getElementById(id).classList.add('show') }
function hide(id){ document.getElementById(id).classList.remove('show') }

window.addEventListener('pywebviewready', ()=>{
  pywebview.api.check_crypto().then(r=>{
    if(!r.ok) onError('Decipher missing: ' + r.err);
  });
});

// Parallax mouse
document.addEventListener('mousemove', e=>{
  const cx = window.innerWidth/2, cy = window.innerHeight/2;
  const dx = (e.clientX-cx)/cx, dy = (e.clientY-cy)/cy;
  const card = document.querySelector('.card');
  card.style.transform = `perspective(900px) rotateY(${dx*2.5}deg) rotateX(${-dy*2.5}deg) translateY(0)`;
  document.querySelector('.orb1').style.transform=`translate(${dx*12}px,${dy*10}px)`;
  document.querySelector('.orb2').style.transform=`translate(${dx*-10}px,${dy*-8}px)`;
  document.querySelector('.orb3').style.transform=`translate(${dx*6}px,${dy*-12}px)`;
});
document.addEventListener('mouseleave', ()=>{
  document.querySelector('.card').style.transform='perspective(900px) rotateY(0) rotateX(0) translateY(0)';
});
</script>
</body>
</html>"""


def _set_icon(window):
    icon_path = None
    for ext in ("icon.ico", "icon.png", "icon.jpg"):
        p = os.path.join(_DIR, ext)
        if os.path.isfile(p):
            icon_path = p
            break
    if not icon_path:
        return
    try:
        import ctypes
        import ctypes.wintypes as wt
        ico_path = icon_path
        try:
            from PIL import Image
            import tempfile
            img = Image.open(icon_path)
            tmp = tempfile.NamedTemporaryFile(suffix=".ico", delete=False)
            tmp.close()
            img.save(tmp.name, format="ICO", sizes=[(256,256),(64,64),(32,32),(16,16)])
            ico_path = tmp.name
        except Exception:
            pass
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        LR_LOADFROMFILE = 0x00000010
        IMAGE_ICON      = 1
        WM_SETICON      = 0x0080
        ICON_SMALL, ICON_BIG = 0, 1
        hwnd       = wt.HWND(window.native.Handle.ToInt32())
        hicon_big  = user32.LoadImageW(None, ico_path, IMAGE_ICON, 256, 256, LR_LOADFROMFILE)
        hicon_small= user32.LoadImageW(None, ico_path, IMAGE_ICON,  16,  16, LR_LOADFROMFILE)
        if hicon_big:   user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG,   hicon_big)
        if hicon_small: user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon_small)
    except Exception as e:
        print(f"[icon] {e}")


if __name__ == "__main__":
    api = API()
    window = webview.create_window(
        "PKA Injector",
        html=HTML,
        js_api=api,
        width=500, height=560,
        resizable=False,
        background_color="#0e1020",
    )
    api.set_window(window)
    window.events.before_show += lambda: _set_icon(window)
    webview.start(debug=False)