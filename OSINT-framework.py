#!/usr/bin/env python3
# Orwellish — Local OSINT + D&D Node Editor (PySide6)
# Shift-click to connect edges. Edges selectable/deletable. Tags isolated per-node.

import json, os, re, sys, webbrowser
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from PySide6.QtGui import QFontDatabase, QFont, QFontInfo
import platform

import requests, tldextract, validators, dns.resolver, whois
from PySide6.QtCore import Qt, QPointF, QRectF, QMimeData, QUrl, QSize, QLineF, QTimer
from PySide6.QtGui import (
    QAction, QBrush, QColor, QFont, QPainter, QPainterPath, QPen,
    QPixmap, QPolygonF, QPalette, QKeySequence, QPainterPathStroker
)
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QGraphicsItem, QGraphicsPathItem, QGraphicsRectItem,
    QGraphicsScene, QGraphicsTextItem, QGraphicsView, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QComboBox, QPushButton, QVBoxLayout, QWidget, QListWidget,
    QListWidgetItem, QFormLayout, QTextEdit, QCheckBox, QSplitter, QMessageBox,
    QStyleOptionGraphicsItem, QDialog, QDialogButtonBox, QInputDialog
)

# ----------------------------
# Config / Constants
# ----------------------------

GROUPS = {
    "npc":       {"name": "NPC",      "color": "#8ecae6"},
    "location":  {"name": "Location", "color": "#90be6d"},
    "quest":     {"name": "Quest",    "color": "#f9c74f"},
    "item":      {"name": "Item",     "color": "#f8961e"},
    "faction":   {"name": "Faction",  "color": "#bdb2ff"},
    "person":    {"name": "Person",   "color": "#ffd6a5"},
    "org":       {"name": "Org",      "color": "#caffbf"},
    "domain":    {"name": "Domain",   "color": "#a0c4ff"},
    "ip":        {"name": "IP",       "color": "#ffadad"},
    "url":       {"name": "URL",      "color": "#fdffb6"},
    "note":      {"name": "Note",     "color": "#e9ecef"},
}
STATUS_COLORS = {
    "confirmed": QColor("#16a34a"),
    "suspected": QColor("#f59e0b"),
    "false":     QColor("#ef4444"),
    "unknown":   QColor("#64748b"),
}
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
SOCIAL_HOST_BADGES = {
    "twitter.com": "X", "x.com": "X",
    "instagram.com": "IG",
    "github.com": "GH",
    "linkedin.com": "IN",
    "facebook.com": "FB",
    "youtube.com": "YT",
}

# --- Theme state ---
IS_DARK = True

def apply_dark_palette(app: QApplication):
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor("#0f172a"))
    pal.setColor(QPalette.Base, QColor("#0b1222"))
    pal.setColor(QPalette.AlternateBase, QColor("#111827"))
    pal.setColor(QPalette.WindowText, QColor("#e5e7eb"))
    pal.setColor(QPalette.Text, QColor("#e5e7eb"))
    pal.setColor(QPalette.Button, QColor("#111827"))
    pal.setColor(QPalette.ButtonText, QColor("#e5e7eb"))
    pal.setColor(QPalette.Highlight, QColor("#3b82f6"))
    pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ToolTipBase, QColor("#111827"))
    pal.setColor(QPalette.ToolTipText, QColor("#e5e7eb"))
    app.setPalette(pal)

def apply_light_palette(app: QApplication):
    app.setPalette(QPalette())

def apply_qss(app: QApplication, dark: bool):
    if dark:
        app.setStyleSheet("""
        QMainWindow { background: #0f172a; }
        QWidget#inspectorPanel { background: rgba(2,6,23,0.72); }
        QLineEdit, QTextEdit, QComboBox, QListWidget {
            background: #0b1222; color: #e5e7eb;
            border: 1px solid #334155; border-radius: 10px; padding: 8px;
        }
        QComboBox QAbstractItemView { background: #0b1222; color: #e5e7eb; }
        QPushButton {
            background: #111827; color: #e5e7eb;
            border: 1px solid #334155; border-radius: 12px; padding: 8px 12px;
        }
        QPushButton:hover { background: #1f2937; }
        QLabel { color: #cbd5e1; }
        QToolBar { background: #0f172a; border: none; }
        """)
    else:
        app.setStyleSheet("""
        QMainWindow { background: #ffffff; }
        QWidget#inspectorPanel { background: rgba(255,255,255,0.96); }
        QLineEdit, QTextEdit, QComboBox, QListWidget {
            border: 1px solid #e5e7eb; border-radius: 10px; padding: 8px; background: #ffffff; color: #111827;
        }
        QComboBox QAbstractItemView { background: #ffffff; color: #111827; }
        QPushButton {
            background: #ffffff; color: #111827;
            border: 1px solid #e5e7eb; border-radius: 12px; padding: 8px 12px;
        }
        QPushButton:hover { background: #f7f7f8; }
        QLabel { color: #374151; }
        QToolBar { background: #ffffff; border: none; }
        """)

# ----------------------------
# Data Model
# ----------------------------

@dataclass
class Attachment:
    label: str = "link"
    url: str = ""

@dataclass
class NodeData:
    id: str = ""
    label: str = "Untitled"
    group: str = "note"
    tags: List[str] = field(default_factory=list)
    status: str = "unknown"
    confidence: int = 50
    attachments: List[Attachment] = field(default_factory=list)
    notes: str = ""
    x: float = 0.0
    y: float = 0.0

@dataclass
class EdgeData:
    source: str = ""
    target: str = ""
    label: str = ""
    style: str = "solid"  # solid/dashed/dotted

@dataclass
class GraphData:
    nodes: List[NodeData] = field(default_factory=list)
    edges: List[EdgeData] = field(default_factory=list)

# ----------------------------
# OSINT helpers (local)
# ----------------------------

def whois_domain(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": list(w.name_servers) if isinstance(w.name_servers, (list, set, tuple)) else ([w.name_servers] if w.name_servers else []),
        }
    except Exception:
        return {}

def dns_records(domain: str) -> Dict[str, Any]:
    out = {}
    try:
        out["A"] = [a.to_text() for a in dns.resolver.resolve(domain, "A")]
    except Exception: pass
    try:
        out["MX"] = [r.exchange.to_text() for r in dns.resolver.resolve(domain, "MX")]
    except Exception: pass
    try:
        out["TXT"] = [r.to_text() for r in dns.resolver.resolve(domain, "TXT")]
    except Exception: pass
    return out

def social_badge_for(url: str) -> Optional[str]:
    try:
        host = QUrl(url).host().lower()
        for h, b in SOCIAL_HOST_BADGES.items():
            if host.endswith(h):
                return b
    except Exception:
        pass
    return None

def urls_for_person(label: str) -> List[Attachment]:
    q = requests.utils.quote(label)
    return [
        Attachment("Google", f"https://www.google.com/search?q={q}"),
        Attachment("LinkedIn", f"https://www.linkedin.com/search/results/all/?keywords={q}"),
        Attachment("HaveIBeenPwned", "https://haveibeenpwned.com/"),
    ]

def urls_for_domain(target: str) -> List[Attachment]:
    atts = []
    fav = f"https://{target}/favicon.ico"
    try:
        r = requests.get(fav, timeout=5)
        if r.ok:
            atts.append(Attachment("favicon", fav))
    except Exception:
        pass
    return atts

def urls_for_ip(ip: str) -> List[Attachment]:
    return [
        Attachment("Shodan", f"https://www.shodan.io/host/{ip}"),
        Attachment("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}"),
    ]

def qt_color(hexstr: str) -> QColor:
    try: return QColor(hexstr)
    except Exception: return QColor("#94a3b8")

# ----------------------------
# Graphics Items
# ----------------------------

class EdgeItem(QGraphicsPathItem):
    def __init__(self, srcItem, dstItem, style="solid", label_text=""):
        super().__init__()
        self.src = srcItem
        self.dst = dstItem
        self.style = style

        # selectable & hoverable
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(-1)

        # pen + style
        self.pen = QPen(QColor("#9aa4b2" if IS_DARK else "#64748b"), 2)
        if style == "dashed":
            self.pen.setStyle(Qt.DashLine)
        elif style == "dotted":
            self.pen.setStyle(Qt.DotLine)
        self.setPen(self.pen)

        # label
        self.label = QGraphicsTextItem(label_text, self)
        self.updatePath()

    def updatePath(self):
        p1 = self.src.scenePos() + QPointF(self.src.rect().width()/2, self.src.rect().height()/2)
        p2 = self.dst.scenePos() + QPointF(self.dst.rect().width()/2, self.dst.rect().height()/2)
        path = QPainterPath(p1)
        mid = (p1 + p2) / 2
        path.cubicTo(QPointF(mid.x(), p1.y()), QPointF(mid.x(), p2.y()), p2)
        self.setPath(path)
        self.label.setDefaultTextColor(QColor("#cbd5e1") if IS_DARK else QColor("#334155"))
        self.label.setPos((p1.x()+p2.x())/2, (p1.y()+p2.y())/2 - 10)

    def shape(self):
        stroker = QPainterPathStroker()
        stroker.setWidth(12)
        return stroker.createStroke(self.path())

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget=None):
        pen = QPen(self.pen)
        if self.isSelected():
            pen.setWidth(3)
            pen.setColor(QColor("#60a5fa"))
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(self.path())

        path = self.path()
        end  = path.pointAtPercent(1.0)
        prev = path.pointAtPercent(0.99)
        base_len, spread = 12.0, 30.0
        l1 = QLineF(end, prev); l1.setLength(base_len); l1.setAngle(l1.angle() + spread)
        l2 = QLineF(end, prev); l2.setLength(base_len); l2.setAngle(l2.angle() - spread)
        painter.setBrush(pen.color()); painter.setPen(Qt.NoPen)
        tri = QPolygonF([end, l1.p2(), l2.p2()])
        painter.drawPolygon(tri)

    def mouseDoubleClickEvent(self, event):
        current = self.label.toPlainText()
        text, ok = QInputDialog.getText(None, "Edit Relationship Label", "Label:", text=current)
        if ok:
            self.label.setPlainText(text)
            if hasattr(self.scene(), "on_update_edge_label") and callable(self.scene().on_update_edge_label):
                self.scene().on_update_edge_label(self, text)
        super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event):
        from PySide6.QtWidgets import QMenu
        m = QMenu()
        act_del = m.addAction("Delete Edge")
        chosen = m.exec(event.screenPos().toPoint())
        if chosen == act_del:
            sc = self.scene()
            if hasattr(sc, "on_delete_edge") and callable(sc.on_delete_edge):
                sc.on_delete_edge(self)
            sc.removeItem(self)
            if hasattr(sc, "edges"):
                try:
                    sc.edges.remove(self)
                except ValueError:
                    pass

class NodeItem(QGraphicsRectItem):
    def __init__(self, model: NodeData):
        super().__init__(0,0,240,140)
        self.model = model
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setAcceptDrops(True)

        self.title = QGraphicsTextItem(model.label, self)
        f = QFont(); f.setPointSize(10); f.setBold(True)
        self.title.setFont(f)
        self.title.setPos(12, 12)

        self.tagsText = QGraphicsTextItem("", self)
        self.tagsText.setPos(12, 40)

        self.linksText = QGraphicsTextItem("", self)
        self.linksText.setPos(12, 64)

        self.setPos(model.x, model.y)
        self.update_tags(); self.update_attachments()

    def rect(self): return QRectF(0,0,240,140)

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget=None):
        r = self.rect(); radius = 12

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setBrush(QColor(0,0,0, 160 if IS_DARK else 28))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(r.adjusted(2,6,6,10), radius, radius)
        painter.restore()

        bg = QColor("#111827") if IS_DARK else QColor("#ffffff")
        border_col = qt_color(GROUPS.get(self.model.group, {}).get("color", "#94a3b8"))
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setBrush(bg)
        painter.setPen(QPen(border_col, 2))
        painter.drawRoundedRect(r, radius, radius)

        status_col = STATUS_COLORS.get(self.model.status, STATUS_COLORS["unknown"])
        pill_text = f"{self.model.status.upper()} ({self.model.confidence}%)"
        painter.setFont(QFont("", 8))
        metrics = painter.boundingRect(r, Qt.AlignLeft, pill_text)
        pill_w, pill_h = metrics.width() + 16, metrics.height() + 4
        pill_x, pill_y = r.right() - pill_w - 8, r.top() - pill_h/2
        painter.setPen(Qt.NoPen); painter.setBrush(status_col)
        painter.drawRoundedRect(QRectF(pill_x, pill_y, pill_w, pill_h), 8, 8)
        painter.setPen(QColor("#ffffff"))
        painter.drawText(QRectF(pill_x, pill_y, pill_w, pill_h), Qt.AlignCenter, pill_text)

        self.title.setDefaultTextColor(QColor("#e5e7eb") if IS_DARK else QColor("#111827"))
        self.tagsText.setDefaultTextColor(QColor("#94a3b8") if IS_DARK else QColor("#334155"))
        self.linksText.setDefaultTextColor(QColor("#cbd5e1") if IS_DARK else QColor("#475569"))

    def update_tags(self):
        # read-only rendering from the node’s own tag list
        tags_preview = list(self.model.tags)  # defensive copy
        t = ", ".join(tags_preview[:4]) + (" …" if len(tags_preview) > 4 else "")
        self.tagsText.setPlainText(t)

    def update_attachments(self):
        parts = []
        for a in list(self.model.attachments)[:4]:  # defensive copy
            badge = social_badge_for(a.url) or ""
            parts.append(f"{('['+badge+'] ') if badge else ''}{a.label or a.url}")
        self.linksText.setPlainText(", ".join(parts) + (" …" if len(self.model.attachments) > 4 else ""))

    def mousePressEvent(self, event):
        if QApplication.keyboardModifiers() & Qt.ShiftModifier:
            sc = self.scene()
            if hasattr(sc, "edge_click"):
                sc.edge_click(self)
                event.accept()
                return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        if self.model.attachments:
            url = self.model.attachments[0].url
            if url:
                if url.startswith("file://"):
                    path = QUrl(url).toLocalFile()
                    if os.path.exists(path):
                        if sys.platform.startswith("win"): os.startfile(path)
                        elif sys.platform.startswith("linux"): os.system(f'xdg-open "{path}"')
                        else: os.system(f'open "{path}"')
                else:
                    webbrowser.open(url)
        super().mouseDoubleClickEvent(event)

    def dragEnterEvent(self, event): event.acceptProposedAction()
    def dropEvent(self, event):
        md: QMimeData = event.mimeData()
        if md.hasUrls():
            for u in md.urls():
                self.model.attachments.append(Attachment(label="link", url=u.toString()))
            self.update_attachments(); event.acceptProposedAction(); return
        if md.hasText():
            t = md.text().strip()
            if validators.url(t):
                self.model.attachments.append(Attachment(label="link", url=t))
                self.update_attachments(); event.acceptProposedAction(); return
        super().dropEvent(event)

# ----------------------------
# Image Preview
# ----------------------------

class ImagePreview(QDialog):
    def __init__(self, url: str, parent=None):
        super().__init__(parent); self.setWindowTitle("Image Preview")
        v = QVBoxLayout(self)
        self.lbl = QLabel("Loading…"); self.lbl.setAlignment(Qt.AlignCenter); v.addWidget(self.lbl)
        try:
            if url.startswith("http"):
                r = requests.get(url, timeout=8); r.raise_for_status()
                img = QPixmap(); img.loadFromData(r.content)
            elif url.startswith("file://"):
                img = QPixmap(QUrl(url).toLocalFile())
            else: img = QPixmap()
            if not img.isNull():
                self.lbl.setPixmap(img.scaled(QSize(900, 700), Qt.KeepAspectRatio, Qt.SmoothTransformation)); self.lbl.setText("")
            else: self.lbl.setText("Failed to load image.")
        except Exception as e:
            self.lbl.setText(f"Error: {e}")
        bb = QDialogButtonBox(QDialogButtonBox.Close); bb.rejected.connect(self.reject); v.addWidget(bb)

# ----------------------------
# Scene / View
# ----------------------------

class GraphScene(QGraphicsScene):
    def __init__(self):
        super().__init__()
        self.nodes: Dict[str, NodeItem] = {}
        self.edges: List[EdgeItem] = []
        self._edgeSource: Optional[NodeItem] = None

        self.on_add_edge = None
        self.on_delete_edge = None
        self.on_update_edge_label = None

    def add_node(self, nd: NodeData):
        item = NodeItem(nd); self.addItem(item); self.nodes[nd.id] = item; return item

    def add_edge(self, ed: EdgeData):
        src = self.nodes.get(ed.source); dst = self.nodes.get(ed.target)
        if not src or not dst: return None
        e = EdgeItem(src, dst, style=ed.style, label_text=ed.label)
        self.addItem(e); self.edges.append(e); return e

    def update_edges(self):
        for e in self.edges: e.updatePath()

    def edge_click(self, node_item: NodeItem):
        if self._edgeSource is None:
            self._edgeSource = node_item
            node_item.setSelected(True)
            return
        if node_item is self._edgeSource:
            self._edgeSource = None
            return
        src_id = self._edgeSource.model.id
        dst_id = node_item.model.id
        label, ok = QInputDialog.getText(None, "Edge Label (optional)", "Label:")
        if not ok: label = ""
        ed = EdgeData(source=src_id, target=dst_id, label=label, style="solid")
        if callable(self.on_add_edge): self.on_add_edge(ed)
        self.add_edge(ed)
        self._edgeSource = None

class GraphView(QGraphicsView):
    def __init__(self, scene: QGraphicsScene):
        super().__init__(scene)
        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.ScrollHandDrag)

        self.controls = QWidget(self); self.controls.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.controls.setStyleSheet("""
            QWidget { background: rgba(2,6,23,0.75); border: 1px solid #334155; border-radius: 12px; }
            QPushButton { color:#e5e7eb; border: none; padding: 6px 10px; }
            QPushButton:hover { background: #1f2937; }
        """)
        hb = QHBoxLayout(self.controls); hb.setContentsMargins(8,6,8,6); hb.setSpacing(6)
        zi = QPushButton("+"); zo = QPushButton("–"); fit = QPushButton("Fit")
        hb.addWidget(zi); hb.addWidget(zo); hb.addWidget(fit)
        zi.clicked.connect(lambda: self.scale(1.15, 1.15))
        zo.clicked.connect(lambda: self.scale(1/1.15, 1/1.15))
        fit.clicked.connect(self.fit_to_items)
        self.controls.resize(140, 36)

        self.hint = QLabel("Hold Shift: click source → target to connect")
        self.hint.setStyleSheet("color:#e5e7eb; background:rgba(2,6,23,0.65); padding:4px 8px; border-radius:8px;")
        self.hint.setParent(self)
        self.hint.adjustSize()
        self.hint.hide()
        self._hintTimer = QTimer(self); self._hintTimer.setInterval(1500); self._hintTimer.setSingleShot(True)
        self._hintTimer.timeout.connect(self.hint.hide)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.controls.move(12, self.viewport().height() - self.controls.height() - 12)
        self.hint.move(12, self.viewport().height() - self.controls.height() - 12 - self.hint.height() - 8)

    def fit_to_items(self):
        rect = self.scene().itemsBoundingRect()
        if rect.isNull(): return
        self.fitInView(rect.adjusted(-80,-80,80,80), Qt.KeepAspectRatio)

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1/1.15
        self.scale(factor, factor)

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Space:
            self._prev = self.dragMode(); self.setDragMode(QGraphicsView.ScrollHandDrag); return
        if e.key() == Qt.Key_Shift:
            self.hint.show(); self._hintTimer.start()
        super().keyPressEvent(e)

    def keyReleaseEvent(self, e):
        if e.key() == Qt.Key_Space:
            self.setDragMode(getattr(self, "_prev", QGraphicsView.ScrollHandDrag)); return
        if e.key() == Qt.Key_Shift:
            self._hintTimer.start()
        super().keyReleaseEvent(e)

    def drawBackground(self, painter: QPainter, rect: QRectF):
        if IS_DARK:
            painter.fillRect(rect, QBrush(QColor("#0f172a")))
            pen = QPen(QColor("#334155"))
        else:
            painter.fillRect(rect, QBrush(QColor("#ffffff")))
            pen = QPen(QColor(220, 224, 230))
        painter.setPen(pen)
        step = 16
        left = int(rect.left()) - (int(rect.left()) % step)
        top  = int(rect.top())  - (int(rect.top())  % step)
        for x in range(left, int(rect.right()), step):
            for y in range(top, int(rect.bottom()), step):
                painter.drawPoint(x, y)

# ----------------------------
# Main Window
# ----------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._syncing = False
        self.setWindowTitle("Local OSINT + D&D Node Editor")
        self.resize(1400, 900)

        self.graph = GraphData()
        self.scene = GraphScene()
        self.view = GraphView(self.scene)
        self.view.setSceneRect(-5000, -5000, 10000, 10000)

        # hooks for scene <-> model
        self.scene.on_add_edge = self._model_add_edge
        self.scene.on_delete_edge = self._model_delete_edge
        self.scene.on_update_edge_label = self._model_update_edge_label

        self.inspector = self.build_inspector()
        splitter = QSplitter(); splitter.addWidget(self.view); splitter.addWidget(self.inspector)
        splitter.setSizes([1000, 400]); self.setCentralWidget(splitter)

        tb = self.addToolBar("toolbar")
        self.searchBox = QLineEdit(); self.searchBox.setPlaceholderText("Search by name, tag, link…")
        self.searchBox.textChanged.connect(self.apply_search); tb.addWidget(self.searchBox)
        tb.addSeparator()
        self.osintToggle = QCheckBox("OSINT"); self.osintToggle.setChecked(True); tb.addWidget(self.osintToggle)
        tb.addSeparator()
        addNodeAct = QAction("Add Node", self); addNodeAct.triggered.connect(self.add_node_ui); tb.addAction(addNodeAct)
        importAct = QAction("Import JSON", self); importAct.triggered.connect(self.import_json); tb.addAction(importAct)
        exportAct = QAction("Export JSON", self); exportAct.triggered.connect(self.export_json); tb.addAction(exportAct)
        tb.addSeparator()
        self.themeAct = QAction("Dark Mode", self); self.themeAct.setCheckable(True); self.themeAct.setChecked(IS_DARK)
        self.themeAct.setShortcut(QKeySequence("Ctrl+D")); self.themeAct.toggled.connect(self.toggle_theme)
        self.addAction(self.themeAct); tb.addAction(self.themeAct)

        self.seed_example()
        self.scene.selectionChanged.connect(self.sync_inspector)
        self.scene.changed.connect(self.scene.update_edges)

    # ----- Inspector -----
    def build_inspector(self) -> QWidget:
        panel = QWidget(); panel.setObjectName("inspectorPanel")
        layout = QVBoxLayout(panel)

        form = QFormLayout()
        self.nameEdit = QLineEdit()
        self.groupBox = QComboBox()
        for k, v in GROUPS.items(): self.groupBox.addItem(v["name"], k)
        self.statusBox = QComboBox(); self.statusBox.addItems(["unknown","confirmed","suspected","false"])
        self.confEdit = QLineEdit("50")
        self.tagsEdit = QLineEdit()
        self.notesEdit = QTextEdit()

        form.addRow("Name", self.nameEdit)
        form.addRow("Type", self.groupBox)
        form.addRow("Status", self.statusBox)
        form.addRow("Confidence %", self.confEdit)
        form.addRow("Tags (comma)", self.tagsEdit)
        form.addRow("Notes", self.notesEdit)
        layout.addLayout(form)

        layout.addWidget(QLabel("Attachments"))
        self.attachList = QListWidget(); layout.addWidget(self.attachList)

        row = QHBoxLayout()
        self.addAttachBtn = QPushButton("Add"); self.delAttachBtn = QPushButton("Remove")
        self.openAttachBtn = QPushButton("Open"); self.previewAttachBtn = QPushButton("Preview Image")
        row.addWidget(self.addAttachBtn); row.addWidget(self.delAttachBtn)
        row.addWidget(self.openAttachBtn); row.addWidget(self.previewAttachBtn)
        layout.addLayout(row)

        self.enrichBtn = QPushButton("Auto-Enrich (local Python)"); layout.addWidget(self.enrichBtn)
        layout.addStretch()

        # connections (only user edits trigger textEdited)
        self.nameEdit.textEdited.connect(self.update_selected_from_ui)
        self.groupBox.currentIndexChanged.connect(self.update_selected_from_ui)
        self.statusBox.currentIndexChanged.connect(self.update_selected_from_ui)
        self.confEdit.textEdited.connect(self.update_selected_from_ui)
        self.tagsEdit.textEdited.connect(self.update_selected_from_ui)
        self.notesEdit.textChanged.connect(self.update_selected_from_ui)
        self.addAttachBtn.clicked.connect(self.add_attachment)
        self.delAttachBtn.clicked.connect(self.del_attachment)
        self.openAttachBtn.clicked.connect(self.open_attachment)
        self.previewAttachBtn.clicked.connect(self.preview_attachment)
        self.enrichBtn.clicked.connect(self.enrich_selected)
        return panel

    # ----- Graph ops -----
    def seed_example(self):
        import uuid
        a, b, c = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        self.graph.nodes = [
            NodeData(id=a, label="Campaign Core", group="note", tags=["hub"], status="confirmed", confidence=90, x=0, y=0),
            NodeData(id=b, label="Hügelfurt", group="location", tags=["village"], x=350, y=-60),
            NodeData(id=c, label="Garin Windspiel", group="npc", tags=["bard"], status="suspected", confidence=60, x=350, y=120),
        ]
        self.graph.edges = [
            EdgeData(source=a, target=b, label="starts in", style="solid"),
            EdgeData(source=c, target=b, label="lives in",  style="solid"),
        ]
        for nd in self.graph.nodes: self.scene.add_node(nd)
        for ed in self.graph.edges: self.scene.add_edge(ed)

    def current_node_item(self) -> Optional[NodeItem]:
        for it in self.scene.selectedItems():
            if isinstance(it, NodeItem): return it
        return None

    def sync_inspector(self):
        it = self.current_node_item()
        if not it:
            return
        nd = it.model

        # prevent update_selected_from_ui() from running while we refresh fields
        self._syncing = True

        # block signals on all inputs that can trigger update_selected_from_ui
        widgets = [self.nameEdit, self.groupBox, self.statusBox, self.confEdit, self.tagsEdit, self.notesEdit]
        for w in widgets:
            w.blockSignals(True)

        # write values (order no longer matters because signals are blocked)
        self.nameEdit.setText(nd.label)
        self.groupBox.setCurrentIndex(self.groupBox.findData(nd.group))
        self.statusBox.setCurrentText(nd.status)
        self.confEdit.setText(str(nd.confidence))
        self.tagsEdit.setText(", ".join(list(nd.tags)))  # copy for safety
        self.notesEdit.setPlainText(nd.notes or "")

        self.attachList.clear()
        for a in list(nd.attachments):
            badge = social_badge_for(a.url) or ""
            QListWidgetItem(f"{('['+badge+'] ') if badge else ''}{a.label}  |  {a.url}", self.attachList)

        # unblock signals
        for w in widgets:
            w.blockSignals(False)

        self._syncing = False


    def apply_search(self, text: str):
        q = (text or "").strip().lower()
        for it in self.scene.nodes.values():
            nd = it.model
            if not q:
                it.setVisible(True); continue
            hit = (
                q in (nd.label or "").lower() or
                any(q in t.lower() for t in nd.tags) or
                any(q in ((a.label or "") + " " + (a.url or "")).lower() for a in nd.attachments) or
                q in (nd.notes or "").lower()
            )
            it.setVisible(hit)

    def add_node_ui(self):
        import uuid
        nid = str(uuid.uuid4())
        center = self.view.mapToScene(self.view.viewport().rect().center())
        nd = NodeData(id=nid, x=center.x(), y=center.y())
        self.graph.nodes.append(nd); self.scene.add_node(nd)

    def update_selected_from_ui(self):
        it = self.current_node_item()
        if not it: return
        nd = it.model
        # write back with defensive copies
        nd.label = self.nameEdit.text().strip() or "Untitled"
        nd.group = self.groupBox.currentData()
        nd.status = self.statusBox.currentText()
        try: nd.confidence = max(0, min(100, int(self.confEdit.text())))
        except Exception: nd.confidence = 50
        # TAGS: split -> unique -> sorted (copy)
        tags = [t.strip() for t in self.tagsEdit.text().split(",") if t.strip()]
        nd.tags = list(dict.fromkeys(tags))  # unique & copy
        nd.notes = str(self.notesEdit.toPlainText())

        it.title.setPlainText(nd.label)
        it.update_tags(); it.update_attachments()
        it.update()

    def add_attachment(self):
        it = self.current_node_item()
        if not it: return
        url, _ = QFileDialog.getOpenFileUrl(self, "Pick a file (or Cancel to enter URL)")
        if url.isValid():
            it.model.attachments.append(Attachment(label="file", url=url.toString()))
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Enter URL in filename box, press Save (quick input)")
            if path and validators.url(path):
                it.model.attachments.append(Attachment(label="link", url=path))
            elif path:
                QMessageBox.warning(self, "Invalid URL", "That doesn't look like a valid URL.")
        it.update_attachments(); self.sync_inspector()

    def del_attachment(self):
        it = self.current_node_item()
        if not it: return
        row = self.attachList.currentRow()
        if row < 0: return
        del it.model.attachments[row]; it.update_attachments(); self.sync_inspector()

    def open_attachment(self):
        it = self.current_node_item()
        if not it: return
        row = self.attachList.currentRow()
        if row < 0: return
        a = it.model.attachments[row]
        if not a.url: return
        if a.url.lower().endswith((".png",".jpg",".jpeg",".gif",".webp",".bmp",".svg")):
            dlg = ImagePreview(a.url, self); dlg.exec()
        else:
            if a.url.startswith("file://"):
                p = QUrl(a.url).toLocalFile()
                if os.path.exists(p):
                    if sys.platform.startswith("win"): os.startfile(p)
                    elif sys.platform.startswith("linux"): os.system(f'xdg-open "{p}"')
                    else: os.system(f'open "{p}"')
            else:
                webbrowser.open(a.url)

    def preview_attachment(self): self.open_attachment()

    # ----- Enrich + Email detect -----
    def extract_emails(self, nd: NodeData) -> List[str]:
        found = set()
        for a in nd.attachments:
            for m in EMAIL_RE.findall((a.url or "") + " " + (a.label or "")): found.add(m)
        for m in EMAIL_RE.findall(nd.label or ""): found.add(m)
        for m in EMAIL_RE.findall(nd.notes or ""): found.add(m)
        return sorted(found)

    def enrich_selected(self):
        it = self.current_node_item()
        if not it: return
        nd = it.model

        if nd.group == "person" and nd.label:
            for att in urls_for_person(nd.label):
                if not any(att.url == a.url for a in nd.attachments):
                    nd.attachments.append(Attachment(label=att.label, url=att.url))  # rewrap => new objects

        if nd.group in ("domain","url"):
            target = nd.label
            if nd.group == "url":
                try:
                    ext = tldextract.extract(nd.label)
                    target = ".".join([p for p in [ext.domain, ext.suffix] if p])
                except Exception: pass
            if target:
                w = whois_domain(target)
                if w.get("registrar"):
                    tag = f"registrar:{w['registrar']}"
                    if tag not in nd.tags: nd.tags = nd.tags + [tag]  # new list
                for ns in w.get("name_servers", []):
                    tag = f"ns:{ns}"
                    if tag not in nd.tags: nd.tags = nd.tags + [tag]
                for k, vals in dns_records(target).items():
                    for v in vals:
                        tag = f"dns:{k}:{v}"
                        if tag not in nd.tags: nd.tags = nd.tags + [tag]
                for fav in urls_for_domain(target):
                    if not any(fav.url == a.url for a in nd.attachments):
                        nd.attachments.append(Attachment(label=fav.label, url=fav.url))

        if nd.group == "ip":
            for att in urls_for_ip(nd.label):
                if not any(att.url == a.url for a in nd.attachments):
                    nd.attachments.append(Attachment(label=att.label, url=att.url))

        emails = self.extract_emails(nd)
        if emails:
            # extend via new list to avoid in-place sharing
            new_tags = list(nd.tags)
            for e in emails:
                t = f"email:{e}"
                if t not in new_tags: new_tags.append(t)
            nd.tags = new_tags
            if nd.status == "unknown": nd.status = "suspected"
            nd.confidence = max(nd.confidence, 60)

        it.update_tags(); it.update_attachments(); it.update()
        self.sync_inspector()
        QMessageBox.information(self, "Enrich", "Enrichment complete.")

    # ----- Model sync for edges -----
    def _model_add_edge(self, ed: EdgeData):
        if any(e.source == ed.source and e.target == ed.target and e.label == ed.label for e in self.graph.edges):
            return
        self.graph.edges.append(ed)

    def _model_delete_edge(self, edge_item: EdgeItem):
        src_id = edge_item.src.model.id
        dst_id = edge_item.dst.model.id
        lab = edge_item.label.toPlainText()
        self.graph.edges = [e for e in self.graph.edges if not (e.source == src_id and e.target == dst_id and e.label == lab)]

    def _model_update_edge_label(self, edge_item: EdgeItem, new_text: str):
        src_id = edge_item.src.model.id
        dst_id = edge_item.dst.model.id
        for e in self.graph.edges:
            if e.source == src_id and e.target == dst_id:
                e.label = new_text
                break

    # ----- Deletion & shortcuts -----
    def keyPressEvent(self, e):
        if e.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            removed = False
            # remove selected edges
            for it in list(self.scene.selectedItems()):
                if isinstance(it, EdgeItem):
                    if callable(self.scene.on_delete_edge): self.scene.on_delete_edge(it)
                    self.scene.removeItem(it)
                    if it in self.scene.edges: self.scene.edges.remove(it)
                    removed = True
            # remove selected nodes (and their edges)
            for it in list(self.scene.selectedItems()):
                if isinstance(it, NodeItem):
                    nid = it.model.id
                    for ed in list(self.scene.edges):
                        if ed.src is it or ed.dst is it:
                            if callable(self.scene.on_delete_edge): self.scene.on_delete_edge(ed)
                            self.scene.removeItem(ed)
                            if ed in self.scene.edges: self.scene.edges.remove(ed)
                    self.scene.removeItem(it)
                    self.scene.nodes.pop(nid, None)
                    self.graph.nodes = [n for n in self.graph.nodes if n.id != nid]
                    removed = True
            if removed: return

        if e.key() == Qt.Key_F:
            self.view.fit_to_items(); return
        if e.key() in (Qt.Key_Plus, Qt.Key_Equal):
            self.view.scale(1.15, 1.15); return
        if e.key() in (Qt.Key_Minus, Qt.Key_Underscore):
            self.view.scale(1/1.15, 1/1.15); return

        super().keyPressEvent(e)

    # ----- Theme toggle -----
    def toggle_theme(self, on: bool):
        global IS_DARK
        IS_DARK = on
        app = QApplication.instance()
        if IS_DARK: apply_dark_palette(app)
        else: apply_light_palette(app)
        apply_qss(app, IS_DARK)
        for it in self.scene.items(): it.update()
        self.view.viewport().update()

    # ----- JSON I/O -----
    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "mindmap.json", "JSON (*.json)")
        if not path: return
        # update node positions before save
        for nd in self.graph.nodes:
            item = self.scene.nodes.get(nd.id)
            if item:
                pos = item.pos(); nd.x, nd.y = pos.x(), pos.y()
        # deep-ish copy to avoid sharing on re-import
        data = {
            "nodes": [
                {
                    **asdict(n),
                    "tags": list(n.tags),
                    "attachments": [asdict(Attachment(a.label, a.url)) for a in n.attachments],
                }
                for n in self.graph.nodes
            ],
            "edges": [asdict(e) for e in self.graph.edges]
        }
        with open(path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)
        QMessageBox.information(self, "Export", f"Saved to {path}")

    def import_json(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import JSON", "", "JSON (*.json)")
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f: data = json.load(f)
            self.scene.clear(); self.scene.nodes.clear(); self.scene.edges.clear()
            self.graph.nodes, self.graph.edges = [], []

            for n in data.get("nodes", []):
                nd = NodeData(
                    id=n.get("id",""),
                    label=n.get("label","Untitled"),
                    group=n.get("group","note"),
                    # **copy** lists to ensure isolation
                    tags=list(n.get("tags", [])),
                    status=n.get("status","unknown"),
                    confidence=int(n.get("confidence", 50)),
                    attachments=[Attachment(**a) for a in n.get("attachments", [])],
                    notes=n.get("notes",""),
                    x=float(n.get("x", 0.0)),
                    y=float(n.get("y", 0.0)),
                )
                self.graph.nodes.append(nd)
                self.scene.add_node(nd)

            for e in data.get("edges", []):
                ed = EdgeData(**e)
                self.graph.edges.append(ed)
                self.scene.add_edge(ed)

            QMessageBox.information(self, "Import", f"Loaded {len(self.graph.nodes)} nodes.")
        except Exception as e:
            QMessageBox.critical(self, "Import error", str(e))

# ----------------------------
# Entry
# ----------------------------
def set_safe_app_font(app: QApplication):
    """
    Force a modern, scalable UI font so Qt doesn't fall back to legacy 'MS Sans Serif'.
    Tries system fonts first; if none found, stays with Qt default.
    """
    preferred = []
    if platform.system() == "Windows":
        preferred = ["Segoe UI", "Arial", "Tahoma", "Verdana"]
    elif platform.system() == "Darwin":
        preferred = ["SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"]
    else:
        preferred = ["Noto Sans", "DejaVu Sans", "Liberation Sans", "Arial"]

    available = set(QFontDatabase.families())
    for fam in preferred:
        if fam in available:
            app.setFont(QFont(fam, 10))   # 10pt is a comfortable default
            return

    # Last resort: if Arial is present under a slightly different name
    for fam in available:
        if "arial" in fam.lower():
            app.setFont(QFont(fam, 10))
            return
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    set_safe_app_font(app)          # <-- add this line

    if IS_DARK: apply_dark_palette(app)
    apply_qss(app, IS_DARK)
    w = MainWindow(); w.show()
    sys.exit(app.exec())
if __name__ == "__main__":
    main()
