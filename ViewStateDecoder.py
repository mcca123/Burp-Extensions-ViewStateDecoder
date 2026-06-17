# -*- coding: utf-8 -*-
# ViewState Decoder - Burp Suite Extension
# Language: Python (Jython 2.7)

from burp import (IBurpExtender, ITab, IContextMenuFactory,
                  IMessageEditorTabFactory, IMessageEditorTab)
from javax.swing import (JPanel, JTextArea, JButton, JLabel, JScrollPane,
                         JSplitPane, BorderFactory, SwingConstants, ButtonGroup,
                         JToggleButton, JMenuItem, SwingUtilities)
from javax.swing.border import EmptyBorder
from javax.swing.text import DefaultHighlighter
from java.awt import (BorderLayout, Color, Font, Dimension, FlowLayout)
from java.util import ArrayList
import base64
import zlib
import struct
import urllib
import re
import java.awt.event

# ── Palette ───────────────────────────────────────────────────────────────────
BG_WHITE   = Color(255, 255, 255)
BG_LIGHT   = Color(245, 246, 248)
BG_PANEL   = Color(235, 237, 241)
BG_HEADER  = Color(225, 227, 232)
ACCENT     = Color(30,  130,  80)
ACCENT2    = Color(180,  90,   0)
FG_MAIN    = Color(30,   30,  30)
FG_DIM     = Color(120, 120, 130)
FG_RED     = Color(180,  30,  30)
BTN_DEF_BG = Color(210, 212, 218)
BORDER_CLR = Color(200, 202, 208)

MONO_FONT  = Font("Monospaced", Font.PLAIN, 12)
LABEL_FONT = Font("SansSerif",  Font.BOLD,  11)

VIEW_STRINGS = "STRINGS"
VIEW_HEX     = "HEX DUMP"
VIEW_TOKENS  = "TOKENS"

# ── Highlight rules ───────────────────────────────────────────────────────────
# (label, color, [keywords...], case_sensitive)
HIGHLIGHT_RULES = [
    ("Role / Privilege",
     Color(255, 200,  80),   # amber
     ["role", "admin", "superuser", "privilege", "permission",
      "isadmin", "isauthenticated", "isauthorized", "access"],
     False),

    ("Credentials",
     Color(255, 130, 130),   # red-pink
     ["password", "passwd", "pwd", "secret", "token",
      "apikey", "api_key", "credential"],
     False),

    ("User Identity",
     Color(130, 200, 255),   # sky blue
     ["username", "userid", "user_id", "uid", "email",
      "fullname", "displayname", "firstname", "lastname"],
     False),

    ("Boolean Flag",
     Color(160, 230, 160),   # green
     ["true", "false", "enabled", "disabled",
      "active", "inactive", "locked", "verified"],
     False),

    ("Version / Build",
     Color(210, 170, 255),   # lavender
     ["version", "ver=", "build", "release", "revision",
      "publickey", "publickeytoken"],
     False),

    ("Session / ID",
     Color(255, 200, 150),   # peach
     ["session", "sessionid", "viewstate", "requestid",
      "correlationid", "transactionid"],
     False),
]


def apply_highlights(text_area, text):
    """Scan text and apply background highlights for interesting keywords."""
    hl      = text_area.getHighlighter()
    hl.removeAllHighlights()
    if not text:
        return

    low = text.lower()
    for (label, color, keywords, case_sensitive) in HIGHLIGHT_RULES:
        painter = DefaultHighlighter.DefaultHighlightPainter(color)
        haystack = text if case_sensitive else low
        for kw in keywords:
            needle = kw if case_sensitive else kw.lower()
            start  = 0
            while True:
                idx = haystack.find(needle, start)
                if idx == -1:
                    break
                try:
                    hl.addHighlight(idx, idx + len(needle), painter)
                except Exception:
                    pass
                start = idx + 1


# ── Legend panel ──────────────────────────────────────────────────────────────
def build_legend():
    panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
    panel.setBackground(BG_LIGHT)
    panel.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER_CLR),
        EmptyBorder(3, 8, 3, 8)
    ))

    lbl = JLabel("Highlight: ")
    lbl.setFont(Font("SansSerif", Font.BOLD, 10))
    lbl.setForeground(FG_DIM)
    panel.add(lbl)

    for (label, color, _, _) in HIGHLIGHT_RULES:
        chip = JLabel("  %s  " % label)
        chip.setFont(Font("SansSerif", Font.PLAIN, 10))
        chip.setForeground(FG_MAIN)
        chip.setOpaque(True)
        chip.setBackground(color)
        chip.setBorder(BorderFactory.createLineBorder(color.darker(), 1))
        panel.add(chip)

    return panel


# ── ViewState parser ──────────────────────────────────────────────────────────
class ViewStateParser(object):

    def extract_viewstate(self, body_str):
        match = re.search(r'__VIEWSTATE(?:X\d+)?=([^&\s"\'<>]+)', body_str)
        if match:
            return match.group(1)
        match2 = re.search(r'id="__VIEWSTATE[^"]*"[^>]*value="([^"]+)"', body_str)
        if match2:
            return match2.group(1)
        return None

    def decode_all(self, vs_string):
        vs_string = vs_string.strip()
        result = {"strings": "", "hex": "", "tokens": "", "error": ""}

        url_decoded = False
        if "%" in vs_string:
            try:
                vs_string = urllib.unquote(vs_string)
                url_decoded = True
            except Exception as e:
                result["error"] = "[ERROR] URL decode failed: %s" % str(e)
                return result

        vs_b64 = vs_string
        pad = len(vs_b64) % 4
        if pad:
            vs_b64 += "=" * (4 - pad)

        try:
            raw = base64.b64decode(vs_b64)
        except Exception as e:
            result["error"] = "[ERROR] Base64 decode failed: %s" % str(e)
            return result

        decompressed = raw
        compress_info = "No compression (raw)"
        try:
            decompressed = zlib.decompress(raw, 16 + zlib.MAX_WBITS)
            compress_info = "Decompressed: gzip"
        except Exception:
            try:
                decompressed = zlib.decompress(raw, -zlib.MAX_WBITS)
                compress_info = "Decompressed: deflate"
            except Exception:
                pass

        steps = []
        if url_decoded:
            steps.append("[Step 1] URL Decode        : OK")
        steps.append("[Step 2] Base64 Decode     : OK  (%d bytes)" % len(raw))
        steps.append("[Step 3] %s" % compress_info)
        steps.append("[INFO]   Total bytes       : %d" % len(decompressed))
        header = "\n".join(steps) + "\n"

        strings = self._extract_strings(decompressed)
        result["strings"] = header + "\n" + "\n".join("  " + s for s in strings)
        result["hex"]     = header + "\n" + self._hex_dump(decompressed[:4096])
        try:
            tokens = self._parse_losformatter(decompressed)
            result["tokens"] = header + "\n" + "\n".join(tokens)
        except Exception as e:
            result["tokens"] = header + "\n[WARN] %s" % str(e)

        return result

    def _hex_dump(self, data):
        rows = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            byte_list = [ord(c) for c in chunk] if isinstance(chunk, str) else list(chunk)
            hex_part  = " ".join("%02x" % b for b in byte_list)
            asc_part  = "".join(chr(b) if 32 <= b < 127 else "." for b in byte_list)
            rows.append("%06x  %-47s  %s" % (i, hex_part, asc_part))
        return "\n".join(rows)

    def _extract_strings(self, data):
        result  = []
        current = []
        byte_iter = (ord(c) for c in data) if isinstance(data, str) else iter(data)
        for b in byte_iter:
            if 32 <= b < 127:
                current.append(chr(b))
            else:
                if len(current) >= 3:
                    result.append("".join(current))
                current = []
        if len(current) >= 3:
            result.append("".join(current))
        return result if result else ["(no printable strings found)"]

    def _parse_losformatter(self, data):
        data   = bytearray(data) if not isinstance(data, bytearray) else data
        tokens = []
        i      = 0
        while i < len(data):
            marker = data[i]; i += 1
            if marker == 0x02:
                if i + 4 <= len(data):
                    val = struct.unpack_from('<i', bytes(data[i:i+4]))[0]
                    tokens.append("[Int32]  %d" % val); i += 4
                else: break
            elif marker == 0x05:
                if i < len(data):
                    length = data[i]; i += 1
                    if i + length <= len(data):
                        s = bytes(data[i:i+length]).decode('utf-8', errors='replace')
                        tokens.append("[String] %s" % s); i += length
                    else: break
                else: break
            elif marker == 0x64:
                tokens.append("[Pair]   at offset %d" % (i - 1))
            elif marker == 0x66:
                tokens.append("[Bool]   False")
            elif marker == 0x67:
                tokens.append("[Bool]   True")
            elif marker == 0x68:
                tokens.append("[Null]   at offset %d" % (i - 1))
        return tokens if tokens else ["(no recognisable LosFormatter tokens found)"]


# ── Reusable output panel (used in both main tab & editor tab) ────────────────
class OutputPanel(JPanel):

    def __init__(self):
        JPanel.__init__(self, BorderLayout())
        self.setBackground(BG_WHITE)
        self._decoded   = {}
        self._cur_view  = VIEW_STRINGS

        # Toggle bar
        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 6))
        top.setBackground(BG_LIGHT)
        top.setBorder(EmptyBorder(4, 8, 4, 8))

        lbl = JLabel("Show: ")
        lbl.setFont(LABEL_FONT)
        lbl.setForeground(FG_DIM)
        top.add(lbl)

        bg = ButtonGroup()
        self._btn_strings = self._make_toggle("STRINGS",  VIEW_STRINGS, bg, top, True)
        self._btn_hex     = self._make_toggle("HEX DUMP", VIEW_HEX,     bg, top)
        self._btn_tokens  = self._make_toggle("TOKENS",   VIEW_TOKENS,  bg, top)

        # Output textarea
        self._txt = JTextArea()
        self._txt.setFont(MONO_FONT)
        self._txt.setBackground(BG_WHITE)
        self._txt.setForeground(FG_MAIN)
        self._txt.setCaretColor(FG_MAIN)
        self._txt.setEditable(False)
        self._txt.setLineWrap(False)
        self._txt.setBorder(EmptyBorder(8, 8, 8, 8))

        scroll = JScrollPane(self._txt)
        scroll.setBorder(BorderFactory.createLineBorder(BORDER_CLR, 1))

        legend = build_legend()

        center = JPanel(BorderLayout())
        center.setBackground(BG_WHITE)
        center.add(scroll,  BorderLayout.CENTER)
        center.add(legend,  BorderLayout.SOUTH)

        self.add(top,    BorderLayout.NORTH)
        self.add(center, BorderLayout.CENTER)

    def _make_toggle(self, label, view_key, group, parent, selected=False):
        btn = JToggleButton(label, selected)
        btn.setFont(Font("SansSerif", Font.BOLD, 11))
        btn.setPreferredSize(Dimension(110, 26))
        btn.setFocusPainted(False)
        btn.setOpaque(True)

        if selected:
            btn.setBackground(ACCENT)
            btn.setForeground(BG_WHITE)
        else:
            btn.setBackground(BTN_DEF_BG)
            btn.setForeground(FG_DIM)

        group.add(btn)
        parent.add(btn)
        panel = self

        class Listener(java.awt.event.ActionListener):
            def actionPerformed(self, e):
                panel._cur_view = view_key
                for b, k in [(panel._btn_strings, VIEW_STRINGS),
                             (panel._btn_hex,     VIEW_HEX),
                             (panel._btn_tokens,  VIEW_TOKENS)]:
                    if k == view_key:
                        b.setBackground(ACCENT)
                        b.setForeground(BG_WHITE)
                    else:
                        b.setBackground(BTN_DEF_BG)
                        b.setForeground(FG_DIM)
                panel.refresh()

        btn.addActionListener(Listener())
        return btn

    def set_decoded(self, decoded):
        self._decoded = decoded
        self.refresh()

    def refresh(self):
        if not self._decoded:
            return
        if self._decoded.get("error"):
            self._txt.setText(self._decoded["error"])
            self._txt.getHighlighter().removeAllHighlights()
            return

        if self._cur_view == VIEW_STRINGS:
            text = self._decoded.get("strings", "")
        elif self._cur_view == VIEW_HEX:
            text = self._decoded.get("hex", "")
        else:
            text = self._decoded.get("tokens", "")

        self._txt.setText(text)
        self._txt.setCaretPosition(0)

        # Apply highlights only on STRINGS view
        if self._cur_view == VIEW_STRINGS:
            apply_highlights(self._txt, text)
        else:
            self._txt.getHighlighter().removeAllHighlights()

    def get_text(self):
        return self._txt.getText()


# ── Message Editor Tab ────────────────────────────────────────────────────────
class ViewStateEditorTab(IMessageEditorTab):

    def __init__(self, helpers):
        self._helpers = helpers
        self._parser  = ViewStateParser()
        self._out     = OutputPanel()

    def getTabCaption(self):
        return "ViewState"

    def getUiComponent(self):
        return self._out

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            body = self._helpers.bytesToString(content)
            return bool(self._parser.extract_viewstate(body))
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        if content is None:
            self._out.set_decoded({})
            return
        try:
            body     = self._helpers.bytesToString(content)
            vs_value = self._parser.extract_viewstate(body)
            if vs_value:
                self._out.set_decoded(self._parser.decode_all(vs_value))
            else:
                self._out.set_decoded({"error": "(no __VIEWSTATE found)"})
        except Exception as e:
            self._out.set_decoded({"error": "[ERROR] " + str(e)})

    def getMessage(self):
        return None

    def isModified(self):
        return False

    def getSelectedData(self):
        sel = self._out.get_text()
        return self._helpers.stringToBytes(sel or "")


class ViewStateTabFactory(IMessageEditorTabFactory):
    def __init__(self, helpers):
        self._helpers = helpers

    def createNewInstance(self, controller, editable):
        return ViewStateEditorTab(self._helpers)


# ── Context Menu ──────────────────────────────────────────────────────────────
class ViewStateContextMenu(IContextMenuFactory):

    def __init__(self, extender):
        self._ext = extender

    def createMenuItems(self, invocation):
        items  = ArrayList()
        item   = JMenuItem("Send __VIEWSTATE to Decoder")
        ext    = self._ext
        inv    = invocation
        parser = ViewStateParser()

        class ML(java.awt.event.ActionListener):
            def actionPerformed(self, e):
                try:
                    msgs = inv.getSelectedMessages()
                    if not msgs:
                        return
                    msg = msgs[0]
                    vs  = None
                    req = msg.getRequest()
                    if req:
                        vs = parser.extract_viewstate(
                            ext._helpers.bytesToString(req))
                    if vs is None:
                        resp = msg.getResponse()
                        if resp:
                            vs = parser.extract_viewstate(
                                ext._helpers.bytesToString(resp))
                    if vs is None:
                        ext._set_status("No __VIEWSTATE found.", FG_RED)
                        return

                    def run():
                        ext._input_area.setText(vs)
                        ext._do_decode(vs)
                    SwingUtilities.invokeLater(run)
                except Exception as ex:
                    ext._set_status("Error: %s" % str(ex), FG_RED)

        item.addActionListener(ML())
        items.add(item)
        return items


# ── Main Extender ─────────────────────────────────────────────────────────────
class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("ViewState Decoder")
        self._parser    = ViewStateParser()
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(ViewStateContextMenu(self))
        callbacks.registerMessageEditorTabFactory(
            ViewStateTabFactory(self._helpers))
        print("[ViewState Decoder] Loaded OK")

    def getTabCaption(self):
        return "ViewState"

    def getUiComponent(self):
        return self._root

    def _build_ui(self):
        self._root = JPanel(BorderLayout())
        self._root.setBackground(BG_WHITE)

        # Header
        header = JPanel(BorderLayout())
        header.setBackground(BG_HEADER)
        header.setBorder(EmptyBorder(12, 18, 12, 18))

        title = JLabel("ViewState Decoder")
        title.setFont(Font("SansSerif", Font.BOLD, 16))
        title.setForeground(ACCENT)

        subtitle = JLabel(
            "Telerik / ASP.NET  |  URL + Base64 + LosFormatter  |  Auto-highlight",
            SwingConstants.RIGHT)
        subtitle.setFont(Font("SansSerif", Font.PLAIN, 11))
        subtitle.setForeground(FG_DIM)

        header.add(title,    BorderLayout.WEST)
        header.add(subtitle, BorderLayout.EAST)

        # Input
        input_panel = JPanel(BorderLayout())
        input_panel.setBackground(BG_LIGHT)
        input_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_CLR),
            EmptyBorder(10, 10, 10, 10)
        ))

        input_label = JLabel("  __VIEWSTATE  (paste Base64 or URL-encoded value here)")
        input_label.setFont(LABEL_FONT)
        input_label.setForeground(ACCENT2)
        input_label.setBorder(EmptyBorder(0, 0, 6, 0))

        self._input_area = JTextArea(6, 80)
        self._input_area.setFont(MONO_FONT)
        self._input_area.setBackground(BG_WHITE)
        self._input_area.setForeground(FG_MAIN)
        self._input_area.setCaretColor(FG_MAIN)
        self._input_area.setLineWrap(True)
        self._input_area.setWrapStyleWord(False)
        self._input_area.setBorder(EmptyBorder(8, 8, 8, 8))

        input_scroll = JScrollPane(self._input_area)
        input_scroll.setBorder(BorderFactory.createLineBorder(BORDER_CLR, 1))

        input_panel.add(input_label,  BorderLayout.NORTH)
        input_panel.add(input_scroll, BorderLayout.CENTER)

        # Action buttons
        action_panel = JPanel(FlowLayout(FlowLayout.CENTER, 12, 8))
        action_panel.setBackground(BG_PANEL)

        self._decode_btn = self._make_btn("[DECODE]",      ACCENT,  Color(220, 240, 228), self._on_decode)
        self._clear_btn  = self._make_btn("[CLEAR]",       ACCENT2, Color(245, 230, 210), self._on_clear)
        self._copy_btn   = self._make_btn("[COPY OUTPUT]", FG_DIM,  BG_PANEL,             self._on_copy)

        action_panel.add(self._decode_btn)
        action_panel.add(self._clear_btn)
        action_panel.add(self._copy_btn)

        # Output (reuse OutputPanel)
        self._out_panel = OutputPanel()

        # Status
        self._status = JLabel("  Ready")
        self._status.setFont(Font("SansSerif", Font.PLAIN, 11))
        self._status.setForeground(FG_DIM)
        self._status.setBorder(EmptyBorder(4, 12, 4, 12))

        status_panel = JPanel(BorderLayout())
        status_panel.setBackground(BG_PANEL)
        status_panel.add(self._status, BorderLayout.WEST)

        top_half = JPanel(BorderLayout())
        top_half.setBackground(BG_WHITE)
        top_half.add(input_panel,  BorderLayout.CENTER)
        top_half.add(action_panel, BorderLayout.SOUTH)

        splitter = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_half, self._out_panel)
        splitter.setDividerLocation(220)
        splitter.setDividerSize(3)
        splitter.setBackground(BORDER_CLR)
        splitter.setBorder(EmptyBorder(0, 0, 0, 0))

        self._root.add(header,       BorderLayout.NORTH)
        self._root.add(splitter,     BorderLayout.CENTER)
        self._root.add(status_panel, BorderLayout.SOUTH)

    def _make_btn(self, text, fg, bg, listener):
        btn = JButton(text)
        btn.setFont(Font("SansSerif", Font.BOLD, 12))
        btn.setForeground(fg)
        btn.setBackground(bg)
        btn.setFocusPainted(False)
        btn.setBorderPainted(True)
        btn.setOpaque(True)
        btn.setPreferredSize(Dimension(160, 32))
        btn.addActionListener(listener)
        return btn

    def _do_decode(self, vs_value):
        self._set_status("Decoding...", FG_DIM)
        try:
            decoded = self._parser.decode_all(vs_value)
            self._out_panel.set_decoded(decoded)
            if decoded.get("error"):
                self._set_status(decoded["error"], FG_RED)
            else:
                url_note = "  [URL-decoded first]" if "%" in vs_value else ""
                self._set_status(
                    "Done  %d chars decoded.%s" % (len(vs_value), url_note), ACCENT)
        except Exception as e:
            self._out_panel.set_decoded({"error": "[ERROR] " + str(e)})
            self._set_status("Error during decode.", FG_RED)

    def _on_decode(self, event):
        vs = self._input_area.getText().strip()
        if not vs:
            self._set_status("No input.", FG_RED)
            return
        self._do_decode(vs)

    def _on_clear(self, event):
        self._input_area.setText("")
        self._out_panel.set_decoded({})
        self._set_status("Cleared.", FG_DIM)

    def _on_copy(self, event):
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        text = self._out_panel.get_text()
        if text:
            sel = StringSelection(text)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, None)
            self._set_status("Output copied to clipboard.", ACCENT2)

    def _set_status(self, msg, color=None):
        self._status.setText("  " + msg)
        if color:
            self._status.setForeground(color)