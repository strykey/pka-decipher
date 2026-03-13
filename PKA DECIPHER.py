#!/usr/bin/env python3
import sys, os, threading, zlib, struct, re, json, shutil, copy

_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _DIR)

_CRYPTO_OK  = False
_CRYPTO_ERR = ""

try:
    from Decipher.pt_crypto import decrypt_pkt
    from Decipher.eax import EAX
    from Decipher.twofish import Twofish
    _CRYPTO_OK = True
except ImportError as _e1:
    _CRYPTO_ERR = str(_e1)
    _decipher_dir = os.path.join(_DIR, "Decipher")
    if os.path.isdir(_decipher_dir):
        sys.path.insert(0, _decipher_dir)
        try:
            import pt_crypto as _pt
            import eax as _eax_mod
            import twofish as _tf_mod
            decrypt_pkt = _pt.decrypt_pkt
            EAX         = _eax_mod.EAX
            Twofish     = _tf_mod.Twofish
            _CRYPTO_OK  = True
            _CRYPTO_ERR = ""
        except ImportError as _e2:
            _CRYPTO_ERR = str(_e2)

import webview


def _compress_qt(data):
    return struct.pack(">I", len(data)) + zlib.compress(data)

def _obf_stage2(data):
    L = len(data)
    return bytes(b ^ (L - i & 0xFF) for i, b in enumerate(data))

def _obf_stage1(data):
    L = len(data)
    o = bytearray(L)
    for i in range(L):
        o[L - 1 - i] = data[i] ^ ((L - i * L) & 0xFF)
    return bytes(o)

def pka_to_xml(path):
    with open(path, "rb") as f:
        raw = f.read()
    return decrypt_pkt(raw).decode("latin-1")

def xml_to_pka(xml_str):
    key = bytes([137]) * 16
    iv  = bytes([16])  * 16
    tf  = Twofish(key)
    eax = EAX(tf.encrypt)
    data = xml_str.encode("latin-1")
    qt   = _compress_qt(data)
    s2   = _obf_stage2(qt)
    ct, tag = eax.encrypt(nonce=iv, plaintext=s2)
    return _obf_stage1(ct + tag)



# ── SCORE PRESETS ──────────────────────────────────────────────────────

def preset_100_completion(xml):
    m = re.search(r'<COMPARISONS>(.*?)</COMPARISONS>', xml, re.DOTALL)
    if not m:
        raise ValueError("COMPARISONS block not found in this file.")
    nb = len(re.findall(r'<NODE>', m.group(1)))
    block = (
        '<COMPARISONS>\n  <NODE>\n'
        '   <NAME nodeValue="" checkType="1" variableName="" headNode="true" '
        'eclass="8" variableEnabled="false" incorrectFeedback="">Network</n>\n'
        '   <ID>Network</ID>\n   <COMPONENTS/>\n   <POINTS>100</POINTS>\n'
        '  </NODE>\n </COMPARISONS>'
    )
    return xml[:m.start()] + block + xml[m.end():], f"{nb} verification node(s) stripped"

def preset_god_score(xml):
    original = xml
    xml = re.sub(r'<POINTS>\d+(?:\.\d+)?</POINTS>', '<POINTS>100</POINTS>', xml)
    n = len(re.findall(r'<POINTS>\d+(?:\.\d+)?</POINTS>', original))
    return xml, f"{n} POINTS node(s) set to 100"

def preset_zero_score_threshold(xml):
    original = xml
    xml = re.sub(r'<PASS_SCORE>\d+(?:\.\d+)?</PASS_SCORE>', '<PASS_SCORE>0</PASS_SCORE>', xml)
    xml = re.sub(r'passScore="\d+(?:\.\d+)?"', 'passScore="0"', xml)
    xml = re.sub(r'<MIN_SCORE>\d+(?:\.\d+)?</MIN_SCORE>', '<MIN_SCORE>0</MIN_SCORE>', xml)
    n = (len(re.findall(r'<PASS_SCORE>', original)) +
         len(re.findall(r'passScore="', original)) +
         len(re.findall(r'<MIN_SCORE>', original)))
    return xml, f"Pass threshold zeroed ({n} field(s))"

def preset_unlock_all(xml):
    original = xml
    xml = re.sub(r'locked="true"',       'locked="false"',       xml)
    xml = re.sub(r'<LOCKED>true</LOCKED>','<LOCKED>false</LOCKED>', xml)
    xml = re.sub(r'lock="1"',             'lock="0"',             xml)
    xml = re.sub(r'<LOCK>1</LOCK>',       '<LOCK>0</LOCK>',       xml)
    n = (len(re.findall(r'locked="true"', original)) +
         len(re.findall(r'<LOCKED>true</LOCKED>', original)) +
         len(re.findall(r'lock="1"', original)) +
         len(re.findall(r'<LOCK>1</LOCK>', original)))
    return xml, f"{n} lock(s) removed"

def preset_bypass_timer(xml):
    original = xml
    xml = re.sub(r'<TIME_LIMIT>\d+</TIME_LIMIT>', '<TIME_LIMIT>0</TIME_LIMIT>', xml)
    xml = re.sub(r'<TIMER_ENABLED>true</TIMER_ENABLED>', '<TIMER_ENABLED>false</TIMER_ENABLED>', xml)
    xml = re.sub(r'timerEnabled="true"', 'timerEnabled="false"', xml)
    xml = re.sub(r'<TIME>\d+</TIME>', '<TIME>0</TIME>', xml)
    n = (len(re.findall(r'<TIME_LIMIT>\d+</TIME_LIMIT>', original)) +
         len(re.findall(r'timerEnabled="true"', original)))
    return xml, f"Timer disabled ({n} instance(s))"

def preset_show_answers(xml):
    original = xml
    xml = re.sub(r'showAnswers="false"',    'showAnswers="true"',    xml)
    xml = re.sub(r'<SHOW_ANSWERS>false</SHOW_ANSWERS>', '<SHOW_ANSWERS>true</SHOW_ANSWERS>', xml)
    xml = re.sub(r'answersVisible="false"', 'answersVisible="true"', xml)
    n = (len(re.findall(r'showAnswers="false"', original)) +
         len(re.findall(r'answersVisible="false"', original)))
    return xml, f"showAnswers enabled ({n} instance(s))"

def preset_max_attempts(xml):
    original = xml
    xml = re.sub(r'maxAttempts="\d+"', 'maxAttempts="999"', xml)
    xml = re.sub(r'<MAX_ATTEMPTS>\d+</MAX_ATTEMPTS>', '<MAX_ATTEMPTS>999</MAX_ATTEMPTS>', xml)
    xml = re.sub(r'<ATTEMPTS_LIMIT>\d+</ATTEMPTS_LIMIT>', '<ATTEMPTS_LIMIT>999</ATTEMPTS_LIMIT>', xml)
    n = (len(re.findall(r'maxAttempts="\d+"', original)) +
         len(re.findall(r'<MAX_ATTEMPTS>\d+</MAX_ATTEMPTS>', original)))
    return xml, f"Max attempts set to 999 ({n} field(s))"

def preset_enable_hints(xml):
    original = xml
    xml = re.sub(r'hintsEnabled="false"', 'hintsEnabled="true"', xml)
    xml = re.sub(r'<HINTS_ENABLED>false</HINTS_ENABLED>', '<HINTS_ENABLED>true</HINTS_ENABLED>', xml)
    xml = re.sub(r'hintEnabled="false"',  'hintEnabled="true"',  xml)
    n = (len(re.findall(r'hintsEnabled="false"', original)) +
         len(re.findall(r'hintEnabled="false"', original)))
    return xml, f"Hints enabled ({n} instance(s))"

def preset_remove_feedback(xml):
    original = xml
    xml = re.sub(r'incorrectFeedback="[^"]*"', 'incorrectFeedback=""', xml)
    xml = re.sub(r'<INCORRECT_FEEDBACK>[^<]*</INCORRECT_FEEDBACK>', '<INCORRECT_FEEDBACK></INCORRECT_FEEDBACK>', xml)
    n = (len(re.findall(r'incorrectFeedback="[^"]+"', original)) +
         len(re.findall(r'<INCORRECT_FEEDBACK>[^<]+</INCORRECT_FEEDBACK>', original)))
    return xml, f"{n} feedback message(s) cleared"

def preset_unlock_activity_wizard(xml):
    original = xml
    xml = re.sub(r'<PASSWORD>[^<]+</PASSWORD>', '<PASSWORD></PASSWORD>', xml)
    xml = re.sub(r'activityPassword="[^"]*"', 'activityPassword=""', xml)
    xml = re.sub(r'wizardPassword="[^"]*"',   'wizardPassword=""',   xml)
    n = (len(re.findall(r'<PASSWORD>[^<]+</PASSWORD>', original)) +
         len(re.findall(r'activityPassword="[^"]+"', original)) +
         len(re.findall(r'wizardPassword="[^"]+"', original)))
    return xml, f"Activity Wizard password(s) cleared ({n})"

# ── NETWORK PRESETS ────────────────────────────────────────────────────

def preset_strip_device_passwords(xml):
    original = xml
    xml = re.sub(r'<SECRET>[^<]+</SECRET>',                   '<SECRET></SECRET>',                   xml)
    xml = re.sub(r'<ENABLE_SECRET>[^<]+</ENABLE_SECRET>',     '<ENABLE_SECRET></ENABLE_SECRET>',     xml)
    xml = re.sub(r'<ENABLE_PASSWORD>[^<]+</ENABLE_PASSWORD>', '<ENABLE_PASSWORD></ENABLE_PASSWORD>', xml)
    xml = re.sub(r'<VTY_PASSWORD>[^<]+</VTY_PASSWORD>',       '<VTY_PASSWORD></VTY_PASSWORD>',       xml)
    xml = re.sub(r'<CON_PASSWORD>[^<]+</CON_PASSWORD>',       '<CON_PASSWORD></CON_PASSWORD>',       xml)
    xml = re.sub(r'password="[^"]*"', 'password=""', xml)
    n = sum(len(re.findall(p, original)) for p in [
        r'<SECRET>[^<]+</SECRET>', r'<ENABLE_SECRET>[^<]+</ENABLE_SECRET>',
        r'<ENABLE_PASSWORD>[^<]+</ENABLE_PASSWORD>', r'<VTY_PASSWORD>[^<]+</VTY_PASSWORD>',
        r'<CON_PASSWORD>[^<]+</CON_PASSWORD>',
    ])
    return xml, f"{n} device password field(s) cleared"

def preset_enable_all_ports(xml):
    original = xml
    xml = re.sub(r'portEnabled="false"',   'portEnabled="true"',   xml)
    xml = re.sub(r'<PORT_ENABLED>false</PORT_ENABLED>', '<PORT_ENABLED>true</PORT_ENABLED>', xml)
    xml = re.sub(r'<SHUTDOWN>true</SHUTDOWN>', '<SHUTDOWN>false</SHUTDOWN>', xml)
    xml = re.sub(r'shutdown="true"', 'shutdown="false"', xml)
    n = (len(re.findall(r'portEnabled="false"', original)) +
         len(re.findall(r'<SHUTDOWN>true</SHUTDOWN>', original)) +
         len(re.findall(r'shutdown="true"', original)))
    return xml, f"{n} port(s) / interface(s) enabled"

def preset_enable_all_interfaces(xml):
    original = xml
    xml = re.sub(r'<ADMIN_STATUS>down</ADMIN_STATUS>', '<ADMIN_STATUS>up</ADMIN_STATUS>', xml)
    xml = re.sub(r'adminStatus="down"', 'adminStatus="up"', xml)
    xml = re.sub(r'<INTERFACE_ENABLED>false</INTERFACE_ENABLED>', '<INTERFACE_ENABLED>true</INTERFACE_ENABLED>', xml)
    n = (len(re.findall(r'<ADMIN_STATUS>down</ADMIN_STATUS>', original)) +
         len(re.findall(r'adminStatus="down"', original)))
    return xml, f"{n} interface(s) set to up"

def preset_show_device_labels(xml):
    original = xml
    xml = re.sub(r'showDeviceLabels="false"', 'showDeviceLabels="true"', xml)
    xml = re.sub(r'<SHOW_LABELS>false</SHOW_LABELS>', '<SHOW_LABELS>true</SHOW_LABELS>', xml)
    xml = re.sub(r'labelVisible="false"', 'labelVisible="true"', xml)
    n = (len(re.findall(r'showDeviceLabels="false"', original)) +
         len(re.findall(r'labelVisible="false"', original)))
    return xml, f"Device labels shown ({n} instance(s))"

def preset_clear_activity_password(xml):
    original = xml
    xml = re.sub(r'activityPass="[^"]*"', 'activityPass=""', xml)
    xml = re.sub(r'<ACTIVITY_PASSWORD>[^<]*</ACTIVITY_PASSWORD>', '<ACTIVITY_PASSWORD></ACTIVITY_PASSWORD>', xml)
    xml = re.sub(r'wizardPassword="[^"]*"', 'wizardPassword=""', xml)
    n = (len(re.findall(r'activityPass="[^"]+"', original)) +
         len(re.findall(r'wizardPassword="[^"]+"', original)))
    return xml, f"Activity password cleared ({n} field(s))"

def preset_remove_completion_criteria(xml):
    original = xml
    xml = re.sub(r'<COMPLETION_CRITERIA>.*?</COMPLETION_CRITERIA>', '<COMPLETION_CRITERIA/>', xml, flags=re.DOTALL)
    xml = re.sub(r'<GRADING_CRITERIA>.*?</GRADING_CRITERIA>', '<GRADING_CRITERIA/>', xml, flags=re.DOTALL)
    n = len(re.findall(r'<COMPLETION_CRITERIA>', original))
    return xml, f"Completion criteria cleared ({n} block(s))"

def preset_expose_device_configs(xml):
    original = xml
    xml = re.sub(r'configHidden="true"', 'configHidden="false"', xml)
    xml = re.sub(r'showConfig="false"', 'showConfig="true"', xml)
    xml = re.sub(r'<CONFIG_HIDDEN>true</CONFIG_HIDDEN>', '<CONFIG_HIDDEN>false</CONFIG_HIDDEN>', xml)
    n = (len(re.findall(r'configHidden="true"', original)) +
         len(re.findall(r'showConfig="false"', original)))
    return xml, f"{n} config visibility flag(s) cleared"


PRESETS = {
    "inject_100_completion": {
        "label": "Inject 100% Completion",
        "description": "Strip verification nodes, force 100% score",
        "category": "score", "fn": preset_100_completion,
    },
    "god_score": {
        "label": "Set All Points to 100",
        "description": "Set every POINTS value to 100",
        "category": "score", "fn": preset_god_score,
    },
    "zero_pass_threshold": {
        "label": "Zero Pass Threshold",
        "description": "Set PASS_SCORE / MIN_SCORE to 0",
        "category": "score", "fn": preset_zero_score_threshold,
    },
    "unlock_all": {
        "label": "Unlock All Elements",
        "description": "Remove locked flags on devices and topology",
        "category": "access", "fn": preset_unlock_all,
    },
    "bypass_timer": {
        "label": "Bypass Timer",
        "description": "Disable all timers and time limits",
        "category": "access", "fn": preset_bypass_timer,
    },
    "show_answers": {
        "label": "Show Answers",
        "description": "Enable showAnswers / answersVisible flags",
        "category": "access", "fn": preset_show_answers,
    },
    "max_attempts": {
        "label": "Unlimited Attempts",
        "description": "Set maxAttempts / ATTEMPTS_LIMIT to 999",
        "category": "access", "fn": preset_max_attempts,
    },
    "enable_hints": {
        "label": "Enable Hints",
        "description": "Force hintsEnabled true everywhere",
        "category": "access", "fn": preset_enable_hints,
    },
    "remove_feedback": {
        "label": "Clear Incorrect Feedback",
        "description": "Remove all incorrectFeedback messages",
        "category": "access", "fn": preset_remove_feedback,
    },
    "unlock_wizard": {
        "label": "Unlock Activity Wizard",
        "description": "Clear Activity Wizard password fields",
        "category": "access", "fn": preset_unlock_activity_wizard,
    },
    "clear_activity_password": {
        "label": "Clear Activity Password",
        "description": "Wipe activityPass / wizardPassword hash fields",
        "category": "access", "fn": preset_clear_activity_password,
    },
    "remove_completion_criteria": {
        "label": "Remove Completion Criteria",
        "description": "Erase all grading/completion criteria blocks",
        "category": "score", "fn": preset_remove_completion_criteria,
    },
    "expose_device_configs": {
        "label": "Expose Device Configs",
        "description": "Make all hidden device running-configs visible",
        "category": "network", "fn": preset_expose_device_configs,
    },
    "strip_passwords": {
        "label": "Strip Device Passwords",
        "description": "Clear enable/vty/con passwords on all devices",
        "category": "network", "fn": preset_strip_device_passwords,
    },
    "enable_all_ports": {
        "label": "Enable All Ports",
        "description": "Enable ports and remove shutdown state",
        "category": "network", "fn": preset_enable_all_ports,
    },
    "enable_all_interfaces": {
        "label": "Bring Interfaces Up",
        "description": "Set adminStatus=up on all interfaces",
        "category": "network", "fn": preset_enable_all_interfaces,
    },
    "show_device_labels": {
        "label": "Show Device Labels",
        "description": "Make all device labels visible",
        "category": "network", "fn": preset_show_device_labels,
    },
}

class API:
    def __init__(self):
        self._w       = None
        self._src     = None
        self._xml     = None
        self._history = []

    def set_window(self, w):
        self._w = w

    def check_crypto(self):
        return {"ok": _CRYPTO_OK, "err": _CRYPTO_ERR}

    def pick_file(self):
        try:
            r = self._w.create_file_dialog(
                webview.OPEN_DIALOG,
                allow_multiple=False,
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

    def load_file(self, path):
        def run():
            try:
                self._js('ui.setStatus("loading", "Decrypting...")')
                size = os.path.getsize(path)
                xml = pka_to_xml(path)
                self._src  = path
                self._xml  = xml
                self._history = [xml]
                payload = json.dumps({
                    "name": os.path.basename(path),
                    "size": size,
                    "xml":  xml
                })
                self._js(f'ui.onFileLoaded({payload})')
            except Exception as e:
                self._js(f'ui.onError({json.dumps(str(e))})')
        threading.Thread(target=run, daemon=True).start()

    def save_xml_to_file(self, xml_content):
        def run():
            try:
                if not self._src:
                    self._js('ui.onError("No source file loaded.")')
                    return
                self._xml = xml_content
                self._js('ui.setStatus("saving", "Re-encrypting...")')
                raw = xml_to_pka(xml_content)
                tmp = self._src + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(raw)
                shutil.move(tmp, self._src)
                self._js(f'ui.onSaved({json.dumps(os.path.basename(self._src))})')
            except Exception as e:
                self._js(f'ui.onError({json.dumps(str(e))})')
        threading.Thread(target=run, daemon=True).start()

    def apply_preset(self, preset_id, xml_content):
        def run():
            try:
                if preset_id not in PRESETS:
                    self._js(f'ui.onError("Unknown preset: {preset_id}")')
                    return
                fn = PRESETS[preset_id]["fn"]
                new_xml, msg = fn(xml_content)
                if xml_content != new_xml:
                    self._history.append(new_xml)
                self._xml = new_xml
                payload = json.dumps({"xml": new_xml, "msg": msg, "preset": preset_id})
                self._js(f'ui.onPresetApplied({payload})')
            except Exception as e:
                self._js(f'ui.onError({json.dumps(str(e))})')
        threading.Thread(target=run, daemon=True).start()

    def apply_all_presets(self, xml_content, preset_ids):
        def run():
            try:
                xml = xml_content
                messages = []
                for pid in preset_ids:
                    if pid in PRESETS:
                        xml, msg = PRESETS[pid]["fn"](xml)
                        messages.append(f"{PRESETS[pid]['label']}: {msg}")
                self._xml = xml
                self._history.append(xml)
                payload = json.dumps({"xml": xml, "messages": messages})
                self._js(f'ui.onAllPresetsApplied({payload})')
            except Exception as e:
                self._js(f'ui.onError({json.dumps(str(e))})')
        threading.Thread(target=run, daemon=True).start()

    def get_presets(self):
        return [
            {
                "id":          k,
                "label":       v["label"],
                "description": v["description"],
                "category":    v["category"],
            }
            for k, v in PRESETS.items()
        ]

    def undo(self, xml_content):
        if len(self._history) > 1:
            self._history.pop()
            xml = self._history[-1]
            self._xml = xml
            return {"ok": True, "xml": xml}
        return {"ok": False, "xml": xml_content}

    def _js(self, code):
        if self._w:
            self._w.evaluate_js(code)



HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PKA Decipher : Packet Tracer Editor</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@300;400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg-base:    #1e1e1e;
  --bg-sidebar: #252526;
  --bg-panel:   #2d2d30;
  --bg-editor:  #1e1e1e;
  --bg-input:   #3c3c3c;
  --bg-hover:   #2a2d2e;
  --bg-active:  #094771;
  --bg-select:  #264f78;

  --border:     #3e3e42;
  --border2:    #555;

  --fg:         #cccccc;
  --fg-dim:     #858585;
  --fg-muted:   #6a6a6a;
  --fg-title:   #ffffff;

  --accent:     #0078d4;
  --accent2:    #1a9fff;

  --green:      #4ec9b0;
  --green2:     #6fcf97;
  --yellow:     #dcdcaa;
  --orange:     #ce9178;
  --blue:       #569cd6;
  --purple:     #c586c0;
  --red:        #f44747;
  --red2:       #f97583;

  --tag:        #4ec9b0;
  --attr:       #9cdcfe;
  --val:        #ce9178;
  --comment:    #6a9955;

  --font-ui:    'Inter', system-ui, sans-serif;
  --font-mono:  'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
}

html, body {
  height: 100%;
  overflow: hidden;
  font-family: var(--font-ui);
  background: var(--bg-base);
  color: var(--fg);
  font-size: 12px;
  -webkit-font-smoothing: antialiased;
  user-select: none;
}

/* ── SPLASH ─────────────────────────────────────────────────────────── */
#splash {
  position: fixed; inset: 0; z-index: 999;
  background: #1e1e1e;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  gap: 14px;
}
#splash.out {
  opacity: 0;
  pointer-events: none;
  transition: opacity .35s ease;
}

.splash-wordmark {
  font-family: var(--font-ui);
  font-size: 13px;
  font-weight: 400;
  color: #858585;
  letter-spacing: .12em;
  text-transform: uppercase;
}
.splash-wordmark strong {
  color: #cccccc;
  font-weight: 600;
}

.splash-track {
  width: 160px;
  height: 1px;
  background: #3e3e42;
  position: relative;
  overflow: hidden;
}
.splash-fill {
  position: absolute;
  left: 0; top: 0;
  height: 100%;
  width: 0%;
  background: #0078d4;
  transition: width .18s ease;
}
.splash-msg {
  font-family: var(--font-mono);
  font-size: 10px;
  color: #6a6a6a;
  letter-spacing: .02em;
}

/* ── APP SHELL ──────────────────────────────────────────────────────── */
#app {
  display: flex;
  flex-direction: column;
  height: 100%;
  opacity: 0;
  transition: opacity .3s ease;
}
#app.visible { opacity: 1; }
#main-row {
  flex: 1;
  display: flex;
  flex-direction: row;
  overflow: hidden;
  min-height: 0;
}
.resizer {
  width: 4px;
  background: #3c3c3c;
  cursor: col-resize;
  flex-shrink: 0;
  transition: background .12s;
  z-index: 20;
}
.resizer:hover, .resizer.active { background: #0078d4; }

/* ── TITLE BAR ──────────────────────────────────────────────────────── */
#titlebar {
  flex-shrink: 0;
  background: #323233;
  border-bottom: 1px solid #1e1e1e;
  display: flex;
  align-items: center;
  padding: 0 12px;
  gap: 12px;
  -webkit-app-region: drag;
}
.tb-app-name {
  font-size: 12px;
  font-weight: 500;
  color: #cccccc;
  letter-spacing: .01em;
  flex-shrink: 0;
}
.tb-app-name span { color: #858585; font-weight: 300; }
.tb-sep { width: 1px; height: 14px; background: #555; flex-shrink: 0; }
.tb-file {
  font-family: var(--font-mono);
  font-size: 11px;
  color: #858585;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  flex: 1;
}
.tb-file.active { color: #cccccc; }
.tb-actions {
  display: flex; gap: 6px; align-items: center; flex-shrink: 0;
  -webkit-app-region: no-drag;
}

.btn {
  font-family: var(--font-ui);
  font-size: 11px;
  font-weight: 400;
  border: 1px solid transparent;
  border-radius: 2px;
  padding: 3px 10px;
  cursor: pointer;
  transition: background .1s, border-color .1s;
  outline: none;
  display: inline-flex; align-items: center; gap: 5px;
  white-space: nowrap;
  -webkit-app-region: no-drag;
}
.btn:disabled { opacity: .35; pointer-events: none; }

.btn-default {
  background: #3a3d41;
  border-color: #555;
  color: #cccccc;
}
.btn-default:hover { background: #45494e; border-color: #6a6a6a; }

.btn-primary {
  background: #0078d4;
  border-color: #0078d4;
  color: #fff;
}
.btn-primary:hover { background: #1a8fdf; border-color: #1a8fdf; }

.btn-danger {
  background: transparent;
  border-color: #555;
  color: #f97583;
}
.btn-danger:hover { background: #3a1c1c; border-color: #f44747; }

.btn-success {
  background: transparent;
  border-color: #555;
  color: #4ec9b0;
}
.btn-success:hover { background: #1a3330; border-color: #4ec9b0; }

/* ── MENUBAR ────────────────────────────────────────────────────────── */
#menubar {
  flex-shrink: 0;
  background: #2d2d30;
  border-bottom: 1px solid #3e3e42;
  display: flex;
  align-items: center;
  padding: 0 8px;
  gap: 2px;
}
.menu-item {
  font-size: 11px;
  color: #cccccc;
  padding: 2px 8px;
  border-radius: 2px;
  cursor: pointer;
  transition: background .1s;
}
.menu-item:hover { background: #3e3e42; }

/* ── LEFT SIDEBAR ───────────────────────────────────────────────────── */
#sidebar-left {
  width: 260px;
  min-width: 140px;
  max-width: 500px;
  flex-shrink: 0;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.sidebar-section-header {
  padding: 8px 12px 5px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--fg-dim);
  flex-shrink: 0;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.file-zone {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.file-zone-inner {
  border: 1px dashed #555;
  padding: 12px;
  text-align: center;
  cursor: pointer;
  transition: border-color .15s, background .15s;
  border-radius: 2px;
}
.file-zone-inner:hover {
  border-color: #0078d4;
  background: #1a2a3a;
}
.file-zone-inner.loaded {
  border-style: solid;
  border-color: #4ec9b0;
  background: #0d2420;
}
.file-zone-label {
  font-size: 11px;
  color: var(--fg-dim);
  display: block;
}
.file-zone-inner.loaded .file-zone-label { color: #4ec9b0; }
.file-zone-name {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--fg-muted);
  margin-top: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  display: none;
}
.file-zone-inner.loaded .file-zone-name { display: block; color: #6fcf97; }

.preset-list {
  flex: 1;
  overflow-y: auto;
  padding: 4px 0;
}
.preset-list::-webkit-scrollbar { width: 4px; }
.preset-list::-webkit-scrollbar-thumb { background: #555; }

.preset-group-label {
  padding: 8px 12px 3px;
  font-size: 9px;
  font-weight: 600;
  letter-spacing: .12em;
  text-transform: uppercase;
  color: #6a6a6a;
}
.preset-row {
  display: flex;
  align-items: center;
  padding: 4px 12px;
  gap: 7px;
  cursor: pointer;
  transition: background .1s;
  border-left: 2px solid transparent;
}
.preset-row:hover { background: #2a2d2e; }
.preset-row.selected {
  background: #094771;
  border-left-color: #0078d4;
}
.preset-row.applied {
  border-left-color: #4ec9b0;
}
.preset-check {
  width: 13px; height: 13px;
  border: 1px solid #555;
  border-radius: 2px;
  flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  transition: background .1s, border-color .1s;
}
.preset-row.selected .preset-check {
  background: #0078d4;
  border-color: #0078d4;
}
.preset-row.selected .preset-check::after {
  content: '';
  display: block;
  width: 7px; height: 5px;
  border-left: 1.5px solid #fff;
  border-bottom: 1.5px solid #fff;
  transform: rotate(-45deg) translateY(-1px);
}
.preset-row.applied .preset-check {
  background: #1a3330;
  border-color: #4ec9b0;
}
.preset-row.applied .preset-check::after {
  content: '';
  display: block;
  width: 7px; height: 5px;
  border-left: 1.5px solid #4ec9b0;
  border-bottom: 1.5px solid #4ec9b0;
  transform: rotate(-45deg) translateY(-1px);
}
.preset-info { flex: 1; min-width: 0; }
.preset-label {
  font-size: 11px;
  color: #cccccc;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.preset-desc {
  font-family: var(--font-mono);
  font-size: 9px;
  color: #6a6a6a;
  margin-top: 1px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.preset-btn-apply {
  flex-shrink: 0;
  display: none;
  font-family: var(--font-ui);
  font-size: 9px;
  border: 1px solid #555;
  background: #3a3d41;
  color: #cccccc;
  border-radius: 2px;
  padding: 2px 7px;
  cursor: pointer;
  transition: background .1s;
}
.preset-row:hover .preset-btn-apply { display: block; }
.preset-btn-apply:hover { background: #0078d4; border-color: #0078d4; color: #fff; }

.sidebar-footer {
  padding: 8px 12px;
  border-top: 1px solid var(--border);
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 5px;
}

/* ── EDITOR ─────────────────────────────────────────────────────────── */
#panel-editor {
  flex: 1;
  min-width: 180px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--bg-editor);
}

.editor-tabs {
  background: #2d2d30;
  border-bottom: 1px solid #3e3e42;
  display: flex;
  align-items: stretch;
  flex-shrink: 0;
  height: 34px;
}
.editor-tab {
  display: flex; align-items: center;
  padding: 0 14px;
  gap: 8px;
  font-size: 11px;
  color: #858585;
  border-right: 1px solid #3e3e42;
  cursor: pointer;
  position: relative;
  flex-shrink: 0;
  transition: color .1s;
}
.editor-tab.active {
  background: #1e1e1e;
  color: #cccccc;
}
.editor-tab.active::after {
  content: '';
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 1px;
  background: #0078d4;
}
.tab-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: #569cd6;
  flex-shrink: 0;
}
.editor-toolbar {
  background: #252526;
  border-bottom: 1px solid #3e3e42;
  display: flex; align-items: center;
  padding: 4px 10px;
  gap: 8px;
  flex-shrink: 0;
}
.toolbar-group {
  display: flex; align-items: center; gap: 4px;
}
.toolbar-sep { width: 1px; height: 16px; background: #3e3e42; margin: 0 4px; }

.search-wrap {
  display: flex; align-items: center;
  background: #3c3c3c;
  border: 1px solid #555;
  border-radius: 2px;
  padding: 3px 7px;
  gap: 5px;
}
.search-wrap:focus-within { border-color: #0078d4; }
.search-wrap input {
  background: none; border: none; outline: none;
  font-family: var(--font-mono);
  font-size: 11px;
  color: #cccccc;
  width: 150px;
}
.search-wrap input::placeholder { color: #6a6a6a; }
.search-count { font-family: var(--font-mono); font-size: 10px; color: #858585; white-space: nowrap; }

.toggle-group {
  display: flex;
  border: 1px solid #555;
  border-radius: 2px;
  overflow: hidden;
}
.toggle-btn {
  font-family: var(--font-ui);
  font-size: 10px;
  padding: 3px 9px;
  border: none;
  background: #3a3d41;
  color: #858585;
  cursor: pointer;
  transition: background .1s, color .1s;
}
.toggle-btn + .toggle-btn { border-left: 1px solid #555; }
.toggle-btn.active { background: #0078d4; color: #fff; }
.toggle-btn:hover:not(.active) { background: #45494e; color: #cccccc; }

#editor-wrap {
  flex: 1;
  overflow: hidden;
  position: relative;
  display: flex;
  flex-direction: column;
}
.xml-empty-state {
  position: absolute; inset: 0;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  gap: 8px;
  pointer-events: none;
}
.empty-icon {
  width: 40px; height: 40px;
  border: 1px solid #3e3e42;
  border-radius: 2px;
  display: flex; align-items: center; justify-content: center;
  margin-bottom: 4px;
}
.empty-icon svg { opacity: .3; }
.empty-title { font-size: 12px; color: #858585; font-weight: 500; }
.empty-hint  { font-size: 11px; color: #6a6a6a; }

#xml-view {
  flex: 1;
  width: 100%;
  overflow: auto;
  position: relative;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 20px;
  color: #d4d4d4;
  tab-size: 2;
  padding: 0;
  box-sizing: border-box;
}
#virt-sizer { pointer-events: none; }
#xml-view::-webkit-scrollbar { width: 10px; height: 10px; }
#xml-view::-webkit-scrollbar-track { background: #1e1e1e; }
#xml-view::-webkit-scrollbar-thumb { background: #424242; border: 2px solid #1e1e1e; border-radius: 4px; }

#xml-edit {
  display: none;
  width: 100%; height: 100%;
  background: #1e1e1e;
  color: #d4d4d4;
  border: none; outline: none; resize: none;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.65;
  padding: 12px 16px;
  tab-size: 2;
}
#xml-edit::-webkit-scrollbar { width: 10px; }
#xml-edit::-webkit-scrollbar-track { background: #1e1e1e; }
#xml-edit::-webkit-scrollbar-thumb { background: #424242; border: 2px solid #1e1e1e; border-radius: 4px; }

/* XML syntax */
.xt  { color: #4ec9b0; }
.xa  { color: #9cdcfe; }
.xv  { color: #ce9178; }
.xc  { color: #6a9955; font-style: italic; }
.xh  { background: rgba(255,213,0,.15); border-radius: 2px; outline: 1px solid rgba(255,213,0,.3); }

/* ── RIGHT PANEL ────────────────────────────────────────────────────── */
#sidebar-right {
  width: 260px;
  min-width: 140px;
  max-width: 500px;
  flex-shrink: 0;
  background: var(--bg-sidebar);
  border-left: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.right-section {
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.right-section-head {
  padding: 6px 12px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: #6a6a6a;
  cursor: pointer;
  display: flex; align-items: center; justify-content: space-between;
  user-select: none;
}
.right-section-head:hover { color: #858585; }
.right-section-body { padding: 6px 12px 10px; }

.stat-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1px;
  background: var(--border);
}
.stat-cell {
  background: var(--bg-sidebar);
  padding: 7px 10px;
}
.stat-cell-key {
  font-size: 9px;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: #6a6a6a;
  margin-bottom: 3px;
}
.stat-cell-val {
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 500;
  color: #cccccc;
}

.kv-row {
  display: flex; justify-content: space-between; align-items: center;
  padding: 3px 0;
  font-size: 11px;
  border-bottom: 1px solid #2d2d30;
}
.kv-row:last-child { border-bottom: none; }
.kv-key { color: #858585; }
.kv-val { font-family: var(--font-mono); color: #cccccc; }
.kv-val.warn { color: #dcdcaa; }
.kv-val.alert { color: #f97583; }

.history-list {
  display: flex; flex-direction: column; gap: 3px;
  max-height: 100px; overflow-y: auto;
}
.history-list::-webkit-scrollbar { width: 3px; }
.history-list::-webkit-scrollbar-thumb { background: #555; }
.history-entry {
  font-family: var(--font-mono);
  font-size: 10px;
  color: #4ec9b0;
  padding: 3px 7px;
  background: #0d2420;
  border-left: 2px solid #4ec9b0;
}

.log-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-height: 0;
}
.log-area-head {
  padding: 6px 12px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: #6a6a6a;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  display: flex; align-items: center; justify-content: space-between;
}
.log-clear { font-size: 9px; color: #6a6a6a; cursor: pointer; letter-spacing: 0; text-transform: none; font-weight: 400; }
.log-clear:hover { color: #cccccc; }
.log-scroll {
  flex: 1;
  overflow-y: auto;
  padding: 4px 0;
}
.log-scroll::-webkit-scrollbar { width: 4px; }
.log-scroll::-webkit-scrollbar-thumb { background: #555; }
.log-line {
  display: flex; align-items: flex-start; gap: 8px;
  padding: 2px 12px;
  font-family: var(--font-mono);
  font-size: 10px;
  line-height: 1.5;
  transition: background .1s;
}
.log-line:hover { background: #2a2d2e; }
.log-time { color: #6a6a6a; flex-shrink: 0; }
.log-msg  { color: #cccccc; word-break: break-all; flex: 1; }
.log-line.info .log-msg  { color: #569cd6; }
.log-line.ok   .log-msg  { color: #4ec9b0; }
.log-line.err  .log-msg  { color: #f44747; }
.log-line.warn .log-msg  { color: #dcdcaa; }

/* ── STATUSBAR ──────────────────────────────────────────────────────── */
#statusbar {
  flex-shrink: 0;
  background: #007acc;
  display: flex; align-items: center;
  padding: 0 10px;
  gap: 10px;
  height: 22px;
}
#statusbar.err { background: #5a1d1d; }
#statusbar.ready { background: #007acc; }
.sb-item {
  font-size: 11px;
  color: rgba(255,255,255,.85);
  display: flex; align-items: center; gap: 5px;
  cursor: default;
}
.sb-item:hover { color: #fff; }
.sb-sep { flex: 1; }
#sb-crypto { font-family: var(--font-mono); }
#sb-pos    { font-family: var(--font-mono); margin-left: auto; }

/* ── TOAST ──────────────────────────────────────────────────────────── */
#toasts {
  position: fixed; bottom: 30px; right: 14px;
  display: flex; flex-direction: column; gap: 5px;
  z-index: 9999; pointer-events: none;
}
.toast {
  font-family: var(--font-mono);
  font-size: 11px;
  padding: 7px 14px;
  background: #252526;
  border: 1px solid #555;
  border-left: 3px solid #0078d4;
  color: #cccccc;
  box-shadow: 0 4px 12px rgba(0,0,0,.4);
  max-width: 340px;
  animation: toastIn .2s ease forwards;
}
.toast.ok   { border-left-color: #4ec9b0; }
.toast.err  { border-left-color: #f44747; }
.toast.warn { border-left-color: #dcdcaa; }
.toast.out  { animation: toastOut .2s ease forwards; }
@keyframes toastIn  { from { opacity:0; transform:translateX(10px); } to { opacity:1; transform:translateX(0); } }
@keyframes toastOut { from { opacity:1; } to { opacity:0; transform:translateX(10px); } }

.spin {
  display: inline-block;
  width: 9px; height: 9px;
  border: 1.5px solid rgba(255,255,255,.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin .6s linear infinite;
  vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #424242; border-radius: 2px; }
</style>
</head>
<body>

<!-- SPLASH -->
<div id="splash">
  <div class="splash-wordmark"><strong>PKA Decipher</strong> &nbsp;/&nbsp; Packet Tracer Editor</div>
  <div class="splash-track"><div class="splash-fill" id="s-fill"></div></div>
  <div class="splash-msg" id="s-msg">Loading modules</div>
</div>

<!-- APP -->
<div id="app">

  <!-- TITLE BAR -->
  <div id="titlebar">
    <div class="tb-app-name" style="display:flex;align-items:baseline;gap:10px">PKA Decipher<span style="font-size:10px;font-weight:300;color:#6a6a6a;letter-spacing:.02em">Cisco Packet Tracer File Editor</span> <span>by Strykey</span></div>
    <div class="tb-sep"></div>
    <div class="tb-file" id="tb-file">No file : Packet Tracer Editor</div>
    <div class="tb-actions">
      <button class="btn btn-default" id="btn-undo" onclick="doUndo()" disabled>Undo</button>
      <button class="btn btn-success" id="btn-save" onclick="doSave()" disabled>Save to PKA</button>
      <button class="btn btn-primary" onclick="pickAndLoad()">Open File</button>
    </div>
  </div>

  <!-- MENUBAR -->
  <div id="menubar">
    <div class="menu-item" onclick="pickAndLoad()">File</div>
    <div class="menu-item" onclick="doSave()">Save</div>
    <div class="menu-item" onclick="doUndo()">Edit</div>
    <div class="menu-item" onclick="applyAll()">Patch</div>
  </div>

  <!-- MAIN ROW -->
  <div id="main-row">

  <!-- SIDEBAR LEFT -->
  <div id="sidebar-left">

    <div class="sidebar-section-header">
      Explorer
      <span style="font-size:9px;font-weight:400;text-transform:none;letter-spacing:0;color:#6a6a6a">Packet Tracer .pka / .pkt</span>
    </div>

    <div class="file-zone">
      <div class="file-zone-inner" id="file-zone" onclick="pickAndLoad()">
        <span class="file-zone-label">Click to open .pka / .pkt file</span>
        <span class="file-zone-name" id="file-zone-name"></span>
      </div>
    </div>

    <div class="sidebar-section-header" style="margin-top:0">
      Patches
    </div>

    <div class="preset-list" id="preset-list"></div>

    <div class="sidebar-footer">
      <div style="font-size:9px;color:#6a6a6a;font-family:var(--font-mono)">Select presets then apply</div>
      <div style="display:flex;gap:5px">
        <button class="btn btn-primary" id="btn-apply-all" style="flex:1" onclick="applyAll()" disabled>Apply Selected</button>
        <button class="btn btn-default" onclick="clearSelection()">Clear</button>
      </div>
    </div>

  </div><!-- /sidebar-left -->

  <div class="resizer" id="resizer-left" title="Drag to resize"></div>

  <!-- EDITOR CENTER -->
  <div id="panel-editor">
    <div class="editor-tabs">
      <div class="editor-tab active" id="tab-label">
        <div class="tab-dot"></div>
        <span id="tab-filename">untitled.xml</span>
      </div>
    </div>
    <div class="editor-toolbar">
      <div class="toolbar-group">
        <div class="toggle-group">
          <button class="toggle-btn active" id="toggle-view" onclick="setMode('view')">Preview</button>
          <button class="toggle-btn"        id="toggle-edit" onclick="setMode('edit')">Edit</button>
        </div>
      </div>
      <div class="toolbar-sep"></div>
      <div class="search-wrap">
        <svg width="10" height="10" viewBox="0 0 16 16" fill="none">
          <circle cx="6.5" cy="6.5" r="5" stroke="#858585" stroke-width="1.5"/>
          <line x1="10.5" y1="10.5" x2="14" y2="14" stroke="#858585" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
        <input id="search-in" type="text" placeholder="Find in XML..." oninput="doSearch(this.value)" onkeydown="if(event.key==='Enter'){event.preventDefault();searchNav(event.shiftKey?-1:1)}">
        <button class="search-nav-btn" onclick="searchNav(-1)" title="Previous (Shift+Enter)">&#8593;</button>
        <button class="search-nav-btn" onclick="searchNav(1)"  title="Next (Enter)">&#8595;</button>
        <span class="search-count" id="search-ct"></span>
      </div>
      <div style="flex:1"></div>
      <div style="font-family:var(--font-mono);font-size:10px;color:#6a6a6a" id="char-count"></div>
    </div>
    <div id="editor-wrap">
      <div class="xml-empty-state" id="empty-state">
        <div class="empty-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke="#858585" stroke-width="1.5"/>
            <polyline points="14 2 14 8 20 8" stroke="#858585" stroke-width="1.5"/>
          </svg>
        </div>
        <div class="empty-title">No file loaded</div>
        <div class="empty-hint">Open a Packet Tracer .pka or .pkt file</div>
      </div>
      <div id="xml-view"></div>
      <textarea id="xml-edit" spellcheck="false"></textarea>
    </div>
  </div><!-- /panel-editor -->

  <div class="resizer" id="resizer-right" title="Drag to resize"></div>

  <!-- SIDEBAR RIGHT -->
  <div id="sidebar-right">

    <div class="stat-grid">
      <div class="stat-cell">
        <div class="stat-cell-key">Nodes</div>
        <div class="stat-cell-val" id="s-nodes"></div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-key">Avg Points</div>
        <div class="stat-cell-val" id="s-pts"></div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-key">Devices</div>
        <div class="stat-cell-val" id="s-dev"></div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-key">XML size</div>
        <div class="stat-cell-val" id="s-size"></div>
      </div>
    </div>

    <div class="right-section">
      <div class="right-section-head">Analysis</div>
      <div class="right-section-body">
        <div class="kv-row"><span class="kv-key">Timer</span><span class="kv-val" id="a-timer"></span></div>
        <div class="kv-row"><span class="kv-key">Locks</span><span class="kv-val" id="a-locks"></span></div>
        <div class="kv-row"><span class="kv-key">Passwords</span><span class="kv-val" id="a-pwds"></span></div>
        <div class="kv-row"><span class="kv-key">Verif. nodes</span><span class="kv-val" id="a-vnodes"></span></div>
        <div class="kv-row"><span class="kv-key">Hints</span><span class="kv-val" id="a-hints"></span></div>
      </div>
    </div>

    <div class="right-section">
      <div class="right-section-head">Patch history</div>
      <div class="right-section-body" style="padding-bottom:8px">
        <div class="history-list" id="history-list">
          <div style="font-family:var(--font-mono);font-size:10px;color:#6a6a6a">No patches applied</div>
        </div>
      </div>
    </div>

    <div class="log-area">
      <div class="log-area-head">
        Output
        <span class="log-clear" onclick="clearLog()">Clear</span>
      </div>
      <div class="log-scroll" id="log-scroll">
        <div class="log-line"><span class="log-time">--:--:--</span><span class="log-msg">PKA Decipher ready</span></div>
      </div>
    </div>

  </div><!-- /sidebar-right -->
  </div><!-- /main-row -->

  <!-- STATUSBAR -->
  <div id="statusbar">
    <div class="sb-item" id="sb-status">Ready</div>
    <div class="sb-sep"></div>
    <div class="sb-item" id="sb-crypto" style="font-size:10px">Checking crypto</div>
    <div class="sb-item" id="sb-pos"></div>
  </div>

</div>

<div id="toasts"></div>

<script>
// ── SPLASH ────────────────────────────────────────────────────────────
(function() {
  const fill = document.getElementById('s-fill');
  const msg  = document.getElementById('s-msg');
  const steps = [[0,'Loading modules'],[25,'Twofish / EAX'],[50,'Preset engine'],[75,'Initializing UI'],[100,'Ready']];
  let i = 0;
  const t = setInterval(() => {
    if (i >= steps.length) { clearInterval(t); return; }
    fill.style.width = steps[i][0] + '%';
    msg.textContent  = steps[i][1];
    i++;
    if (i === steps.length) setTimeout(() => {
      document.getElementById('splash').classList.add('out');
      document.getElementById('app').classList.add('visible');
    }, 280);
  }, 220);
})();

// ── STATE ─────────────────────────────────────────────────────────────
const S = {
  xml:      null,
  mode:     'view',
  search:   '',
  selected: new Set(),
  applied:  new Set(),
};

// ── INIT ──────────────────────────────────────────────────────────────
window.addEventListener('pywebviewready', () => {
  pywebview.api.check_crypto().then(r => {
    const el = document.getElementById('sb-crypto');
    if (r.ok) {
      el.textContent = 'Twofish/EAX OK';
      el.style.color = 'rgba(78,201,176,.9)';
      log('Crypto modules loaded : Twofish / EAX ready', 'ok');
    } else {
      el.textContent = 'Crypto missing: ' + r.err;
      el.style.color = 'rgba(244,71,71,.9)';
      log('Crypto error: ' + r.err, 'err');
      document.getElementById('statusbar').classList.add('err');
    }
  });
  pywebview.api.get_presets().then(buildPresets);
});

// ── PRESETS UI ────────────────────────────────────────────────────────
function buildPresets(presets) {
  const container = document.getElementById('preset-list');
  container.innerHTML = '';
  const cats = { score: 'Score', access: 'Access & Settings', network: 'Network' };
  const groups = {};
  presets.forEach(p => { (groups[p.category] = groups[p.category] || []).push(p); });
  Object.entries(cats).forEach(([cat, label]) => {
    if (!groups[cat]) return;
    const g = document.createElement('div');
    g.className = 'preset-group-label';
    g.textContent = label;
    container.appendChild(g);
    groups[cat].forEach(p => {
      const row = document.createElement('div');
      row.className = 'preset-row';
      row.id = 'pr-' + p.id;
      row.innerHTML =
        '<div class="preset-check"></div>' +
        '<div class="preset-info">' +
          '<div class="preset-label">' + p.label + '</div>' +
          '<div class="preset-desc">' + p.description + '</div>' +
        '</div>' +
        '<button class="preset-btn-apply" onclick="applySingle(\'' + p.id + '\',event)">Apply</button>';
      row.addEventListener('click', e => {
        if (e.target.classList.contains('preset-btn-apply')) return;
        toggleSelect(p.id, row);
      });
      container.appendChild(row);
    });
  });
}

function toggleSelect(id, row) {
  if (S.selected.has(id)) { S.selected.delete(id); row.classList.remove('selected'); }
  else { S.selected.add(id); row.classList.add('selected'); }
  document.getElementById('btn-apply-all').disabled = (S.selected.size === 0 || !S.xml);
}

function clearSelection() {
  S.selected.clear();
  document.querySelectorAll('.preset-row.selected').forEach(r => r.classList.remove('selected'));
  document.getElementById('btn-apply-all').disabled = true;
}

function applySingle(id, e) {
  if (e) e.stopPropagation();
  if (!S.xml) { toast('Open a file first', 'warn'); return; }
  setStatus('Applying patch...');
  pywebview.api.apply_preset(id, S.xml);
}

function applyAll() {
  if (!S.xml || S.selected.size === 0) return;
  setStatus('Applying ' + S.selected.size + ' patch(es)...');
  pywebview.api.apply_all_presets(S.xml, Array.from(S.selected));
}

// ── FILE ──────────────────────────────────────────────────────────────
function pickAndLoad() {
  pywebview.api.pick_file().then(p => {
    if (!p) return;
    setStatus('Decrypting...');
    log('Opening: ' + p.split(/[\\/]/).pop(), 'info');
    pywebview.api.load_file(p);
  });
}

// ── UI CALLBACKS ──────────────────────────────────────────────────────
const ui = {
  onFileLoaded(d) {
    S.xml = d.xml;
    S.applied.clear();
    clearSelection();

    document.getElementById('tb-file').textContent = d.name + '  ' + fmtBytes(d.size);
    document.getElementById('tb-file').classList.add('active');
    document.getElementById('tab-filename').textContent = d.name;
    const fz = document.getElementById('file-zone');
    fz.classList.add('loaded');
    fz.querySelector('.file-zone-label').textContent = 'Loaded';
    document.getElementById('file-zone-name').textContent = d.name;

    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('btn-save').disabled  = false;
    document.getElementById('btn-undo').disabled  = true;

    document.getElementById('history-list').innerHTML =
      '<div style="font-family:var(--font-mono);font-size:10px;color:#6a6a6a">No patches applied</div>';

    renderXml(d.xml);
    updateStats(d.xml);
    updateCharCount(d.xml);
    setStatus('Loaded : ' + d.name);
    log('Decrypted ' + d.name + ' (' + fmtBytes(d.size) + ', ' + d.xml.length.toLocaleString() + ' chars)', 'ok');
  },

  onPresetApplied(d) {
    S.xml = d.xml;
    S.applied.add(d.preset);
    const row = document.getElementById('pr-' + d.preset);
    if (row) { row.classList.remove('selected'); row.classList.add('applied'); }
    S.selected.delete(d.preset);
    renderXml(d.xml);
    updateStats(d.xml);
    updateCharCount(d.xml);
    addHistory(d.msg);
    setStatus(d.msg);
    log(d.msg, 'ok');
    toast(d.msg, 'ok');
    document.getElementById('btn-undo').disabled = false;
    document.getElementById('btn-apply-all').disabled = (S.selected.size === 0);
  },

  onAllPresetsApplied(d) {
    S.xml = d.xml;
    d.messages.forEach(m => { addHistory(m); log(m, 'ok'); });
    S.selected.clear();
    document.querySelectorAll('.preset-row.selected').forEach(r => { r.classList.remove('selected'); r.classList.add('applied'); });
    renderXml(d.xml);
    updateStats(d.xml);
    updateCharCount(d.xml);
    setStatus(d.messages.length + ' patch(es) applied');
    toast(d.messages.length + ' patch(es) applied', 'ok');
    document.getElementById('btn-undo').disabled = false;
    document.getElementById('btn-apply-all').disabled = true;
  },

  onSaved(name) {
    setStatus('Written: ' + name);
    log('Saved to disk: ' + name, 'ok');
    toast('Saved: ' + name, 'ok');
  },

  onError(msg) {
    setStatus('Error: ' + msg);
    log('Error: ' + msg, 'err');
    toast(msg, 'err');
    document.getElementById('statusbar').classList.add('err');
    setTimeout(() => document.getElementById('statusbar').classList.remove('err'), 3000);
  },

  setStatus(type, msg) { setStatus(msg); },
};

// ── ACTIONS ───────────────────────────────────────────────────────────
function doSave() {
  if (!S.xml) return;
  const content = S.mode === 'edit' ? document.getElementById('xml-edit').value : S.xml;
  if (S.mode === 'edit') S.xml = content;
  setStatus('Re-encrypting...');
  log('Writing to .pka...', 'info');
  pywebview.api.save_xml_to_file(content);
}

function doUndo() {
  const cur = S.mode === 'edit' ? document.getElementById('xml-edit').value : S.xml;
  pywebview.api.undo(cur).then(r => {
    if (r.ok) {
      S.xml = r.xml;
      renderXml(r.xml);
      updateStats(r.xml);
      updateCharCount(r.xml);
      log('Undo', 'info');
      toast('Undo applied', 'info');
      setStatus('Undo applied');
    } else {
      toast('Nothing to undo', 'warn');
    }
  });
}

// ── EDITOR ────────────────────────────────────────────────────────────
function setMode(mode) {
  S.mode = mode;
  const view = document.getElementById('xml-view');
  const edit = document.getElementById('xml-edit');
  const wrap = document.getElementById('editor-wrap');
  const btnV = document.getElementById('toggle-view');
  const btnE = document.getElementById('toggle-edit');
  if (mode === 'edit') {
    edit.value = S.xml || '';
    edit.style.cssText = 'display:block;position:absolute;inset:0;z-index:2;';
    btnV.classList.remove('active');
    btnE.classList.add('active');
    edit.focus();
  } else {
    const v = edit.value;
    edit.style.cssText = 'display:none;';
    if (v !== S.xml && v) { S.xml = v; renderXml(v); updateStats(v); updateCharCount(v); }
    btnV.classList.add('active');
    btnE.classList.remove('active');
    if (S.xml) { VIRT.startIdx = -1; requestAnimationFrame(virtPaint); }
  }
}

// ── VIRTUAL XML RENDERER ─────────────────────────────────────────────
// Correct implementation: one sizer div sets scroll height,
// one absolute content div is repositioned via transform on scroll.

const VIRT = {
  lines:      [],
  lh:         20,
  pad:        8,
  startIdx:   -1,
  endIdx:     -1,
  scroller:   null,
  sizer:      null,
  content:    null,
  ready:      false,
};

function virtSetup() {
  if (VIRT.ready) return;
  const scroller = document.getElementById('xml-view');
  VIRT.scroller = scroller;

  // sizer: invisible div that gives the scroller its full scroll height
  const sizer = document.createElement('div');
  sizer.id = 'virt-sizer';
  sizer.style.cssText = 'position:absolute;top:0;left:0;width:1px;';
  scroller.appendChild(sizer);
  VIRT.sizer = sizer;

  // content: absolutely positioned, moved by JS on scroll
  const content = document.createElement('div');
  content.id = 'virt-content';
  content.style.cssText = 'position:absolute;top:0;left:0;right:0;will-change:transform;';
  scroller.appendChild(content);
  VIRT.content = content;

  scroller.addEventListener('scroll', function() {
    VIRT.startIdx = -1; // force repaint on next frame
    requestAnimationFrame(virtPaint);
  }, { passive: true });

  VIRT.ready = true;
}

function virtLoad(xml) {
  virtSetup();
  VIRT.lines    = xml.split('\n');
  VIRT.startIdx = -1;
  VIRT.endIdx   = -1;
  VIRT.sizer.style.height = (VIRT.lines.length * VIRT.lh) + 'px';
  VIRT.scroller.scrollTop = 0;
  requestAnimationFrame(virtPaint);
}

function virtPaint() {
  if (!VIRT.ready || !VIRT.lines.length) return;
  const scrollTop = VIRT.scroller.scrollTop;
  const viewH     = VIRT.scroller.clientHeight || 600;
  const lh        = VIRT.lh;
  const total     = VIRT.lines.length;

  const start = Math.max(0,       Math.floor(scrollTop / lh) - VIRT.pad);
  const end   = Math.min(total-1, Math.ceil((scrollTop + viewH) / lh) + VIRT.pad);

  if (start === VIRT.startIdx && end === VIRT.endIdx) return;
  VIRT.startIdx = start;
  VIRT.endIdx   = end;

  VIRT.content.style.transform = 'translateY(' + (start * lh) + 'px)';

  const frag = document.createDocumentFragment();
  for (let i = start; i <= end; i++) {
    const row = document.createElement('div');
    row.style.cssText = 'height:' + lh + 'px;line-height:' + lh + 'px;white-space:pre;padding:0 16px;font-family:var(--font-mono);font-size:12px;';
    row.innerHTML = virtHighlight(VIRT.lines[i] || '');
    frag.appendChild(row);
  }
  VIRT.content.innerHTML = '';
  VIRT.content.appendChild(frag);
}

// Single-line XML highlighter : no catastrophic backtracking
function virtHighlight(raw) {
  if (!raw) return '\u200b';
  // Escape HTML, using sentinel chars to avoid double-processing
  let s = raw
    .replace(/&/g, '\x00amp;')
    .replace(/</g, '\x01')
    .replace(/>/g, '\x02');

  // Comments
  s = s.replace(/\x01!--([\s\S]*?)--\x02/g,
    (_, c) => '<span class="xc">&lt;!--' + c + '--&gt;</span>');

  // Tags with attributes
  s = s.replace(/(\x01\/?)([A-Za-z][\w:.\-]*)((?:\s+[\w:.\-]+=(?:"[^"]*"|'[^']*'))*)(\s*\/?\x02)/g,
    function(_, open, tag, attrs, close) {
      const coloredAttrs = attrs.replace(/(\s+)([\w:.\-]+)(=)("(?:[^"]*)")/g,
        function(m, sp, n, eq, v) {
          return sp + '<span class="xa">' + n + '</span>' + eq + '<span class="xv">' + v + '</span>';
        });
      return '<span class="xt">'
        + open.replace(/\x01/g,'&lt;') + tag
        + '</span>' + coloredAttrs
        + '<span class="xt">' + close.replace(/\x02/g,'&gt;') + '</span>';
    });

  // Restore remaining sentinels
  s = s
    .replace(/\x00/g, '&')
    .replace(/\x01/g, '&lt;')
    .replace(/\x02/g, '&gt;');

  // Search highlight (operates on final HTML : only text nodes effectively)
  if (S.search && S.searchRe) {
    try { s = s.replace(S.searchRe, m => '<span class="xh">' + m + '</span>'); }
    catch(e) {}
  }
  return s;
}

function renderXml(xml) {
  if (!xml) return;
  document.getElementById('empty-state').style.display = 'none';
  virtLoad(xml);
}


function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── SEARCH (debounced) ───────────────────────────────────────────────
let _searchTimer = null;
// ── SEARCH ───────────────────────────────────────────────────────────
S.matchLines  = [];
S.matchCursor = -1;

function doSearch(q) {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(() => _execSearch(q), 160);
}

function searchNav(dir) {
  if (!S.matchLines.length) return;
  S.matchCursor = (S.matchCursor + dir + S.matchLines.length) % S.matchLines.length;
  _updateSearchCount();
  virtScrollToLine(S.matchLines[S.matchCursor]);
}

function virtScrollToLine(lineIdx) {
  if (!VIRT.ready || !VIRT.scroller) return;
  const lh    = VIRT.lh;
  const viewH = VIRT.scroller.clientHeight || 600;
  const top   = Math.max(0, lineIdx * lh - viewH / 2 + lh / 2);
  VIRT.scroller.scrollTop = top;
  VIRT.startIdx = -1;
  requestAnimationFrame(virtPaint);
}

function _updateSearchCount() {
  const n = S.matchLines.length;
  if (!n) { document.getElementById('search-ct').textContent = '0 results'; return; }
  document.getElementById('search-ct').textContent =
    (S.matchCursor + 1) + ' / ' + n + ' result' + (n !== 1 ? 's' : '');
}

function _execSearch(q) {
  S.search      = q ? q : '';
  S.searchRe    = null;
  S.matchLines  = [];
  S.matchCursor = -1;
  if (!S.xml) return;
  if (q) {
    const esc_q = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    try { S.searchRe = new RegExp(esc_q, 'i'); } catch(e) {}
    const lineRe = new RegExp(esc_q, 'i');
    VIRT.lines.forEach((line, i) => { if (lineRe.test(line)) S.matchLines.push(i); });
    if (S.matchLines.length) {
      S.matchCursor = 0;
      _updateSearchCount();
      virtScrollToLine(S.matchLines[0]);
      return;
    }
    _updateSearchCount();
  } else {
    document.getElementById('search-ct').textContent = '';
  }
  VIRT.startIdx = -1;
  requestAnimationFrame(virtPaint);
}

// ── PANEL RESIZER ─────────────────────────────────────────────────────
(function initResizers() {
  function makeResizer(handleId, panelId, dir) {
    const handle = document.getElementById(handleId);
    const panel  = document.getElementById(panelId);
    if (!handle || !panel) return;
    let startX, startW;
    handle.addEventListener('mousedown', function(e) {
      e.preventDefault();
      startX = e.clientX;
      startW = panel.getBoundingClientRect().width;
      handle.classList.add('active');
      document.body.style.cursor    = 'col-resize';
      document.body.style.userSelect = 'none';
      function onMove(e) {
        const delta = dir === 'right' ? startX - e.clientX : e.clientX - startX;
        const w = Math.max(140, Math.min(500, startW + delta));
        panel.style.width = w + 'px';
        VIRT.startIdx = -1;
        requestAnimationFrame(virtPaint);
      }
      function onUp() {
        handle.classList.remove('active');
        document.body.style.cursor    = '';
        document.body.style.userSelect = '';
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup',   onUp);
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup',   onUp);
    });
  }
  makeResizer('resizer-left',  'sidebar-left',  'left');
  makeResizer('resizer-right', 'sidebar-right', 'right');
})();

function updateCharCount(xml) {
  document.getElementById('char-count').textContent = xml ? xml.length.toLocaleString() + ' chars' : '';
}

// ── STATS (async, non-blocking) ───────────────────────────────────────
function updateStats(xml) {
  setTimeout(() => _doStats(xml), 0);
}
function _doStats(xml) {
  const nodes  = (xml.match(/<NODE>/g) || []).length;
  const ptVals = [];
  let m; const ptRe = /<POINTS>(\d+(?:\.\d+)?)<\/POINTS>/g;
  let ptCount = 0;
  while ((m = ptRe.exec(xml)) !== null && ptCount < 200) { ptVals.push(+m[1]); ptCount++; }
  const devs   = (xml.match(/<DEVICE>/g) || []).length || (xml.match(/deviceType\s*=/g) || []).length;
  const locks  = (xml.match(/locked="true"/g) || []).length + (xml.match(/<LOCKED>true<\/LOCKED>/g) || []).length;
  const pwds   = (xml.match(/<PASSWORD>[^<]+<\/PASSWORD>/g) || []).length +
                 (xml.match(/<SECRET>[^<]+<\/SECRET>/g) || []).length;
  const timer  = /timerEnabled="true"|<TIMER_ENABLED>true/.test(xml);
  const hints  = (xml.match(/hintsEnabled="true"/g) || []).length;

  document.getElementById('s-nodes').textContent = nodes || '0';
  document.getElementById('s-pts').textContent   = ptVals.length ? Math.round(ptVals.reduce((a,b)=>a+b,0)/ptVals.length) + '%' : '0%';
  document.getElementById('s-dev').textContent   = devs || '0';
  document.getElementById('s-size').textContent  = (xml.length/1024).toFixed(1) + ' KB';

  const kv = (id, val, cls) => {
    const el = document.getElementById(id);
    el.textContent = val;
    el.className = 'kv-val' + (cls ? ' ' + cls : '');
  };
  kv('a-timer',  timer  ? 'Active'               : 'None',  timer  ? 'warn'  : '');
  kv('a-locks',  locks  ? locks + ' locked'       : 'None',  locks  ? 'alert' : '');
  kv('a-pwds',   pwds   ? pwds + ' found'         : 'None',  pwds   ? 'warn'  : '');
  kv('a-vnodes', nodes  > 1 ? String(nodes)       : '1',     nodes > 1 ? 'warn' : '');
  kv('a-hints',  hints  ? hints + ' active'       : 'None',  '');
}

// ── HISTORY ───────────────────────────────────────────────────────────
function addHistory(msg) {
  const list = document.getElementById('history-list');
  const ph = list.querySelector('[style]');
  if (ph) ph.remove();
  const el = document.createElement('div');
  el.className = 'history-entry';
  el.textContent = msg;
  list.insertBefore(el, list.firstChild);
}

// ── LOG ───────────────────────────────────────────────────────────────
function log(msg, type) {
  const box   = document.getElementById('log-scroll');
  const line  = document.createElement('div');
  const now   = new Date();
  const t     = [now.getHours(), now.getMinutes(), now.getSeconds()].map(n => String(n).padStart(2,'0')).join(':');
  line.className = 'log-line ' + (type || '');
  line.innerHTML = '<span class="log-time">' + t + '</span><span class="log-msg">' + msg + '</span>';
  box.appendChild(line);
  box.scrollTop = 99999;
  if (box.children.length > 300) box.removeChild(box.firstChild);
}

function clearLog() {
  document.getElementById('log-scroll').innerHTML = '';
}

// ── STATUS ────────────────────────────────────────────────────────────
function setStatus(msg) {
  document.getElementById('sb-status').textContent = msg;
}

// ── TOAST ─────────────────────────────────────────────────────────────
function toast(msg, type) {
  const c = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = 'toast ' + (type || '');
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 220); }, 2600);
}

// ── UTILS ─────────────────────────────────────────────────────────────
function fmtBytes(b) {
  return b < 1024 ? b + ' B' : b < 1048576 ? (b/1024).toFixed(1) + ' KB' : (b/1048576).toFixed(2) + ' MB';
}
</script>
</body>
</html>"""


def main():
    api    = API()
    window = webview.create_window(
        "PKA Decipher",
        html=HTML,
        js_api=api,
        width=1280,
        height=800,
        min_size=(960, 640),
        background_color="#1e1e1e",
    )
    api.set_window(window)
    webview.start(debug=False)


if __name__ == "__main__":
    main()