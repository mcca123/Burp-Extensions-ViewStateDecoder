# -*- coding: utf-8 -*-
# ViewState Decoder - Burp Suite Extension
# Language: Python (Jython 2.7)
# Install: Extender > Extensions > Add > Extension type: Python

from burp import IBurpExtender, ITab
from javax.swing import (JPanel, JTextArea, JButton, JLabel, JScrollPane,
                         JSplitPane, BorderFactory, SwingConstants, ButtonGroup,
                         JToggleButton)
from javax.swing.border import EmptyBorder
from java.awt import (BorderLayout, Color, Font, Dimension, FlowLayout)
import base64
import zlib
import struct

BG_WHITE   = Color(255, 255, 255)
BG_LIGHT   = Color(245, 246, 248)
BG_PANEL   = Color(235, 237, 241)
BG_HEADER  = Color(225, 227, 232)
ACCENT     = Color(30,  130,  80)
ACCENT2    = Color(180,  90,   0)
FG_MAIN    = Color(30,   30,  30)
FG_DIM     = Color(120, 120, 130)
FG_RED     = Color(180,  30,  30)
BTN_SEL_BG = Color(200, 220, 205)
BTN_DEF_BG = Color(210, 212, 218)
BORDER_CLR = Color(200, 202, 208)

MONO_FONT  = Font("Monospaced", Font.PLAIN, 12)
LABEL_FONT = Font("SansSerif",  Font.BOLD,  11)

VIEW_STRINGS = "STRINGS"
VIEW_HEX     = "HEX DUMP"
VIEW_TOKENS  = "TOKENS"

import java.awt.event


class ViewStateParser(object):

    def decode_all(self, vs_string):
        vs_string = vs_string.strip()
        result = {"strings": "", "hex": "", "tokens": "", "error": ""}
        try:
            raw = base64.b64decode(vs_string)
        except Exception as e:
            result["error"] = "[ERROR] Base64 decode failed: %s" % str(e)
            return result

        decompressed = raw
        info_line = "[INFO] No compression detected (raw)"
        try:
            decompressed = zlib.decompress(raw, 16 + zlib.MAX_WBITS)
            info_line = "[INFO] Decompressed with gzip"
        except Exception:
            try:
                decompressed = zlib.decompress(raw, -zlib.MAX_WBITS)
                info_line = "[INFO] Decompressed with deflate"
            except Exception:
                pass

        header = "%s\n[INFO] Total bytes: %d\n" % (info_line, len(decompressed))

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
            hex_part = " ".join("%02x" % b for b in byte_list)
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in byte_list)
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


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("ViewState Decoder")
        self._parser   = ViewStateParser()
        self._decoded  = {}
        self._cur_view = VIEW_STRINGS
        self._build_ui()
        callbacks.addSuiteTab(self)
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

        subtitle = JLabel("Telerik / ASP.NET  |  Base64 + LosFormatter", SwingConstants.RIGHT)
        subtitle.setFont(Font("SansSerif", Font.PLAIN, 11))
        subtitle.setForeground(FG_DIM)

        header.add(title,    BorderLayout.WEST)
        header.add(subtitle, BorderLayout.EAST)

        # Input panel
        input_panel = JPanel(BorderLayout())
        input_panel.setBackground(BG_LIGHT)
        input_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_CLR),
            EmptyBorder(10, 10, 10, 10)
        ))

        input_label = JLabel("  __VIEWSTATE  (paste Base64 value here)")
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

        self._decode_btn = self._make_btn("[DECODE]",      ACCENT,  Color(220,240,228), self._on_decode)
        self._clear_btn  = self._make_btn("[CLEAR]",       ACCENT2, Color(245,230,210), self._on_clear)
        self._copy_btn   = self._make_btn("[COPY OUTPUT]", FG_DIM,  BG_PANEL,           self._on_copy)

        action_panel.add(self._decode_btn)
        action_panel.add(self._clear_btn)
        action_panel.add(self._copy_btn)

        # View toggle buttons
        view_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 8))
        view_panel.setBackground(BG_LIGHT)
        view_panel.setBorder(EmptyBorder(4, 8, 0, 8))

        view_lbl = JLabel("Show: ")
        view_lbl.setFont(LABEL_FONT)
        view_lbl.setForeground(FG_DIM)
        view_panel.add(view_lbl)

        bg = ButtonGroup()
        self._btn_strings = self._make_toggle("STRINGS",  VIEW_STRINGS, bg, view_panel, selected=True)
        self._btn_hex     = self._make_toggle("HEX DUMP", VIEW_HEX,     bg, view_panel)
        self._btn_tokens  = self._make_toggle("TOKENS",   VIEW_TOKENS,  bg, view_panel)

        # Output panel
        output_panel = JPanel(BorderLayout())
        output_panel.setBackground(BG_WHITE)
        output_panel.setBorder(EmptyBorder(0, 10, 10, 10))

        output_panel.add(view_panel, BorderLayout.NORTH)

        self._output_area = JTextArea()
        self._output_area.setFont(MONO_FONT)
        self._output_area.setBackground(BG_WHITE)
        self._output_area.setForeground(FG_MAIN)
        self._output_area.setCaretColor(FG_MAIN)
        self._output_area.setEditable(False)
        self._output_area.setLineWrap(False)
        self._output_area.setBorder(EmptyBorder(8, 8, 8, 8))

        output_scroll = JScrollPane(self._output_area)
        output_scroll.setBorder(BorderFactory.createLineBorder(BORDER_CLR, 1))
        output_panel.add(output_scroll, BorderLayout.CENTER)

        # Status bar
        self._status = JLabel("  Ready")
        self._status.setFont(Font("SansSerif", Font.PLAIN, 11))
        self._status.setForeground(FG_DIM)
        self._status.setBorder(EmptyBorder(4, 12, 4, 12))

        status_panel = JPanel(BorderLayout())
        status_panel.setBackground(BG_PANEL)
        status_panel.add(self._status, BorderLayout.WEST)

        # Split
        top_half = JPanel(BorderLayout())
        top_half.setBackground(BG_WHITE)
        top_half.add(input_panel,  BorderLayout.CENTER)
        top_half.add(action_panel, BorderLayout.SOUTH)

        splitter = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_half, output_panel)
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

        ext = self

        class Listener(java.awt.event.ActionListener):
            def actionPerformed(self, e):
                ext._cur_view = view_key
                for b, k in [(ext._btn_strings, VIEW_STRINGS),
                             (ext._btn_hex,     VIEW_HEX),
                             (ext._btn_tokens,  VIEW_TOKENS)]:
                    if k == view_key:
                        b.setBackground(ACCENT)
                        b.setForeground(BG_WHITE)
                    else:
                        b.setBackground(BTN_DEF_BG)
                        b.setForeground(FG_DIM)
                ext._refresh_output()

        btn.addActionListener(Listener())
        return btn

    def _refresh_output(self):
        if not self._decoded:
            return
        if self._decoded.get("error"):
            self._output_area.setText(self._decoded["error"])
            return
        if self._cur_view == VIEW_STRINGS:
            self._output_area.setText(self._decoded.get("strings", ""))
        elif self._cur_view == VIEW_HEX:
            self._output_area.setText(self._decoded.get("hex", ""))
        else:
            self._output_area.setText(self._decoded.get("tokens", ""))
        self._output_area.setCaretPosition(0)

    def _on_decode(self, event):
        vs = self._input_area.getText().strip()
        if not vs:
            self._set_status("No input.", FG_RED)
            return
        self._set_status("Decoding...", FG_DIM)
        try:
            self._decoded = self._parser.decode_all(vs)
            self._refresh_output()
            if self._decoded.get("error"):
                self._set_status(self._decoded["error"], FG_RED)
            else:
                self._set_status("Done  %d bytes decoded." % len(vs), ACCENT)
        except Exception as e:
            self._output_area.setText("[ERROR] " + str(e))
            self._set_status("Error during decode.", FG_RED)

    def _on_clear(self, event):
        self._input_area.setText("")
        self._output_area.setText("")
        self._decoded = {}
        self._set_status("Cleared.", FG_DIM)

    def _on_copy(self, event):
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        text = self._output_area.getText()
        if text:
            sel = StringSelection(text)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, None)
            self._set_status("Output copied to clipboard.", ACCENT2)

    def _set_status(self, msg, color=None):
        self._status.setText("  " + msg)
        if color:
            self._status.setForeground(color)