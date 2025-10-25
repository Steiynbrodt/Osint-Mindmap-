#!/usr/bin/env python3
# orwellish.py - Local Orwell-like OSINT + D&D Node Editor (pure Python, PySide6)

import json
import math
import os
import re
import sys
import webbrowser
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

import requests
import tldextract
import validators
import dns.resolver
import whois

from PySide6.QtCore import (
    Qt, QPointF, QRectF, QMimeData, QUrl, QSize, QLineF, Signal, QObject
)
from PySide6.QtGui import (
    QAction, QBrush, QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap, QTransform
)
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QGraphicsEllipseItem, QGraphicsItem, QGraphicsPathItem,
    QGraphicsPixmapItem, QGraphicsRectItem, QGraphicsScene, QGraphicsTextItem, QGraphicsView,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QComboBox, QPushButton, QVBoxLayout, QWidget,
    QListWidget, QListWidgetItem, QFormLayout, QTextEdit, QCheckBox, QSplitter, QMessageBox,
    QStyleOptionGraphicsItem, QDialog, QDialogButtonBox
)
from PIL import Image
from io import BytesIO

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
EDGE_STYLES = ["solid", "dashed", "dotted"]
STATUS_COLORS = {
    "confirmed": QColor("#16a34a"),
    "suspected": QColor("#f59e0b"),
    "false":     QColor("#ef4444"),
    "unknown":   QColor("#64748b"),
}
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

SOCIAL_HOST_ICONS = {
    "twitter.com": "X", "x.com": "X",
    "instagram.com": "IG",
    "github.com": "GH",
    "linkedin.com": "IN",
    "facebook.com": "FB",
    "youtube.com": "YT",
}

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
    notes: str = ""       # freeform text for email auto-detect
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
# OSINT helpers (local only)
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
        answers = dns.resolver.resolve(domain, "A")
        out["A"] = [a.to_text() for a in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "MX")
        out["MX"] = [r.exchange.to_text() for r in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        out["TXT"] = [r.to_text() for r in answers]
    except Exception:
        pass
    return out

def favicon_for(url: str) -> Optional[QPixmap]:
    try:
        u = QUrl(url)
        origin = f"{u.scheme()}://{u.host()}"
        fav_url = origin + "/favicon.ico"
        r = requests.get(fav_url, timeout=5)
        if r.ok and r.content:
            img = Image.open(BytesIO(r.content))
            img = img.resize((16, 16))
            b = BytesIO()
            img.save(b, format='PNG')
            qp = QPixmap()
            qp.loadFromData(b.getvalue(), "PNG")
            return qp
    except Exception:
        pass
    return None

def social_badge_for(url: str) -> Optional[str]:
    try:
        u = QUrl(url)
        host = u.host().lower()
        for h, badge in SOCIAL_HOST_ICONS.items():
            if host.endswith(h):
                return badge
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
    # try favicon
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
        Attachment("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}")
    ]

# ----------------------------
# Graphics Items
# ----------------------------

def qt_color(hexstr: str) -> QColor:
    try:
        return QColor(hexstr)
    except Exception:
        return QColor("#f8f9fa")

class EdgeItem(QGraphicsPathItem):
    def __init__(self, srcItem, dstItem, style="solid", label_text=""):
        super().__init__()
        self.src = srcItem
        self.dst = dstItem
        self.style = style
        self.label = QGraphicsTextItem(label_text, self)
        self.setZValue(-1)
        self.pen = QPen(QColor("#64748b"), 2)
        if style == "dashed":
            self.pen.setStyle(Qt.DashLine)
        elif style == "dotted":
            self.pen.setStyle(Qt.DotLine)
        self.setPen(self.pen)
        self.updatePath()

    def updatePath(self):
        p1 = self.src.scenePos() + QPointF(self.src.rect().width()/2, self.src.rect().height()/2)
        p2 = self.dst.scenePos() + QPointF(self.dst.rect().width()/2, self.dst.rect().height()/2)
        path = QPainterPath(p1)
        mid = (p1 + p2) / 2
        # Smooth cubic curve
        path.cubicTo(QPointF(mid.x(), p1.y()), QPointF(mid.x(), p2.y()), p2)
        self.setPath(path)

        # Position label
        self.label.setDefaultTextColor(QColor("#334155"))
        self.label.setPos((p1.x()+p2.x())/2, (p1.y()+p2.y())/2 - 10)

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget=None):
        super().paint(painter, option, widget)
        # Arrowhead
        path = self.path()
        length = path.length()
        end = path.pointAtPercent(1.0)
        angle = path.angleAtPercent(1.0)
        painter.setBrush(self.pen.color())
        painter.setPen(Qt.NoPen)
        tri = QPainterPath()
        size = 8
        # build triangle pointing towards dst
        p = QPolygonF([
            end + QPointF(0, 0),
            end + QPointF(-size, -size/2),
            end + QPointF(-size,  size/2),
        ])
        t = QTransform()
        t.translate(end.x(), end.y())
        t.rotate(-angle)
        t.translate(-end.x(), -end.y())
        p = t.map(p)
        tri.addPolygon(p)
        painter.drawPath(tri)

class NodeItem(QGraphicsRectItem):
    def __init__(self, model: NodeData):
        super().__init__(0,0,240,140)
        self.model = model
        self.setBrush(QBrush(QColor("#ffffff")))
        self.setPen(QPen(qt_color(GROUPS.get(model.group, {}).get("color", "#adb5bd")), 2))
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setAcceptDrops(True)

        self.title = QGraphicsTextItem(model.label, self)
        self.title.setDefaultTextColor(QColor("#111827"))
        f = QFont()
        f.setPointSize(10)
        f.setBold(True)
        self.title.setFont(f)
        self.title.setPos(10, 10)

        self.badge = QGraphicsTextItem("", self)  # status / confidence
        self.badge.setDefaultTextColor(QColor("#ffffff"))
        self.badge_bg = QGraphicsRectItem(self)
        self.badge_bg.setBrush(QBrush(STATUS_COLORS.get(model.status, STATUS_COLORS["unknown"])))
        self.badge_bg.setPen(Qt.NoPen)
        self.update_badge()

        self.tagsText = QGraphicsTextItem("", self)
        self.tagsText.setDefaultTextColor(QColor("#334155"))
        self.tagsText.setPos(10, 36)
        self.update_tags()

        self.linksText = QGraphicsTextItem("", self)
        self.linksText.setDefaultTextColor(QColor("#475569"))
        self.linksText.setPos(10, 60)
        self.update_attachments()

        self.setPos(model.x, model.y)

    def rect(self):
        return QRectF(0,0,240,140)

    def update_badge(self):
        txt = f"{self.model.status.upper()} ({self.model.confidence}%)"
        self.badge.setPlainText(txt)
        self.badge_bg.setBrush(QBrush(STATUS_COLORS.get(self.model.status, STATUS_COLORS["unknown"])))
        br = self.badge.boundingRect()
        self.badge_bg.setRect(240 - br.width() - 20, -8, br.width()+12, br.height()+6)
        self.badge.setPos(240 - br.width() - 14, -6)

    def update_tags(self):
        if self.model.tags:
            self.tagsText.setPlainText(", ".join(self.model.tags[:4]) + (" …" if len(self.model.tags) > 4 else ""))
        else:
            self.tagsText.setPlainText("")

    def update_attachments(self):
        display = []
        for a in self.model.attachments[:4]:
            # Social badge?
            badge = ""
            b = social_badge_for(a.url) if a.url else None
            if b: badge = f"[{b}] "
            label = a.label or a.url
            display.append(f"{badge}{label}")
        self.linksText.setPlainText(", ".join(display) + (" …" if len(self.model.attachments) > 4 else ""))

    def mouseDoubleClickEvent(self, event):
        # open first attachment if exists; otherwise nothing
        if self.model.attachments:
            url = self.model.attachments[0].url
            if url:
                if url.startswith("file://"):
                    # open local file
                    path = QUrl(url).toLocalFile()
                    if os.path.exists(path):
                        os.startfile(path) if sys.platform.startswith("win") else os.system(f'xdg-open "{path}"' if sys.platform.startswith("linux") else f'open "{path}"')
                else:
                    webbrowser.open(url)
        super().mouseDoubleClickEvent(event)

    def dragEnterEvent(self, event):
        event.acceptProposedAction()

    def dropEvent(self, event):
        md: QMimeData = event.mimeData()
        # URL dropped
        if md.hasUrls():
            for u in md.urls():
                s = u.toString()
                self.model.attachments.append(Attachment(label="link", url=s))
            self.update_attachments()
            event.acceptProposedAction()
            return
        if md.hasText():
            t = md.text().strip()
            if validators.url(t):
                self.model.attachments.append(Attachment(label="link", url=t))
                self.update_attachments()
                event.acceptProposedAction()
                return
        super().dropEvent(event)

# ----------------------------
# Image Preview Dialog
# ----------------------------

class ImagePreview(QDialog):
    def __init__(self, url: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Image Preview")
        v = QVBoxLayout(self)
        label = QLabel("Loading...")
        label.setAlignment(Qt.AlignCenter)
        v.addWidget(label)
        try:
            if url.startswith("http"):
                r = requests.get(url, timeout=8)
                r.raise_for_status()
                img = QPixmap()
                img.loadFromData(r.content)
            elif url.startswith("file://"):
                path = QUrl(url).toLocalFile()
                img = QPixmap(path)
            else:
                img = QPixmap()
            if not img.isNull():
                label.setPixmap(img.scaled(QSize(900, 700), Qt.KeepAspectRatio, Qt.SmoothTransformation))
                label.setText("")
            else:
                label.setText("Failed to load image.")
        except Exception as e:
            label.setText(f"Error: {e}")

        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)

# ----------------------------
# Main Window / Scene
# ----------------------------

class GraphScene(QGraphicsScene):
    def __init__(self):
        super().__init__()
        self.nodes: Dict[str, NodeItem] = {}
        self.edges: List[EdgeItem] = []

    def add_node(self, nd: NodeData):
        item = NodeItem(nd)
        self.addItem(item)
        self.nodes[nd.id] = item
        return item

    def add_edge(self, ed: EdgeData):
        src = self.nodes.get(ed.source)
        dst = self.nodes.get(ed.target)
        if not src or not dst: return None
        e = EdgeItem(src, dst, style=ed.style, label_text=ed.label)
        self.addItem(e)
        self.edges.append(e)
        return e

    def update_edges(self):
        for e in self.edges:
            e.updatePath()

class GraphView(QGraphicsView):
    def __init__(self, scene: GraphScene):
        super().__init__(scene)
        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.RubberBandDrag)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setAcceptDrops(True)

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1/1.15
        self.scale(factor, factor)

    def drawBackground(self, painter: QPainter, rect: QRectF):
        # dotted background
        painter.fillRect(rect, QBrush(QColor("#ffffff")))
        pen = QPen(QColor(220, 224, 230))
        painter.setPen(pen)
        step = 16
        left = int(math.floor(rect.left())) - (int(math.floor(rect.left())) % step)
        top = int(math.floor(rect.top())) - (int(math.floor(rect.top())) % step)
        for x in range(left, int(rect.right()), step):
            for y in range(top, int(rect.bottom()), step):
                painter.drawPoint(x, y)

# ----------------------------
# Main App
# ----------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Orwellish – Local OSINT + D&D Node Editor (Python)")
        self.resize(1400, 900)

        self.graph = GraphData()
        self.scene = GraphScene()
        self.view = GraphView(self.scene)
        self.view.setSceneRect(-5000, -5000, 10000, 10000)

        # UI: left canvas + right inspector
        self.inspector = self.build_inspector()
        splitter = QSplitter()
        splitter.addWidget(self.view)
        splitter.addWidget(self.inspector)
        splitter.setSizes([1000, 400])
        self.setCentralWidget(splitter)

        # toolbar
        tb = self.addToolBar("toolbar")
        self.searchBox = QLineEdit()
        self.searchBox.setPlaceholderText("Search by name, tag, link…")
        self.searchBox.textChanged.connect(self.apply_search)
        tb.addWidget(self.searchBox)

        tb.addSeparator()
        self.osintToggle = QCheckBox("OSINT")
        self.osintToggle.setChecked(True)
        tb.addWidget(self.osintToggle)

        tb.addSeparator()
        addNodeAct = QAction("Add Node", self)
        addNodeAct.triggered.connect(self.add_node_ui)
        tb.addAction(addNodeAct)

        importAct = QAction("Import JSON", self)
        importAct.triggered.connect(self.import_json)
        tb.addAction(importAct)

        exportAct = QAction("Export JSON", self)
        exportAct.triggered.connect(self.export_json)
        tb.addAction(exportAct)

        # seed example
        self.seed_example()

        # timers/updates
        self.scene.selectionChanged.connect(self.sync_inspector)
        self.scene.changed.connect(self.scene.update_edges)

    # ---------- Inspector ----------
    def build_inspector(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)

        form = QFormLayout()
        self.nameEdit = QLineEdit()
        self.groupBox = QComboBox()
        for k, v in GROUPS.items():
            self.groupBox.addItem(v["name"], k)
        self.statusBox = QComboBox()
        self.statusBox.addItems(["unknown", "confirmed", "suspected", "false"])
        self.confSlider = QLineEdit("50")  # simpler numeric for brevity
        self.tagsEdit = QLineEdit()
        self.notesEdit = QTextEdit()

        form.addRow("Name", self.nameEdit)
        form.addRow("Type", self.groupBox)
        form.addRow("Status", self.statusBox)
        form.addRow("Confidence %", self.confSlider)
        form.addRow("Tags (comma)", self.tagsEdit)
        form.addRow("Notes", self.notesEdit)

        layout.addLayout(form)

        layout.addWidget(QLabel("Attachments"))
        self.attachList = QListWidget()
        layout.addWidget(self.attachList)

        attachBtns = QHBoxLayout()
        self.addAttachBtn = QPushButton("Add")
        self.delAttachBtn = QPushButton("Remove")
        self.openAttachBtn = QPushButton("Open")
        self.previewAttachBtn = QPushButton("Preview Image")
        attachBtns.addWidget(self.addAttachBtn)
        attachBtns.addWidget(self.delAttachBtn)
        attachBtns.addWidget(self.openAttachBtn)
        attachBtns.addWidget(self.previewAttachBtn)
        layout.addLayout(attachBtns)

        # OSINT enrich
        self.enrichBtn = QPushButton("Auto-Enrich (local Python)")
        layout.addWidget(self.enrichBtn)

        layout.addStretch()

        # connections
        self.nameEdit.textEdited.connect(self.update_selected_from_ui)
        self.groupBox.currentIndexChanged.connect(self.update_selected_from_ui)
        self.statusBox.currentIndexChanged.connect(self.update_selected_from_ui)
        self.confSlider.textEdited.connect(self.update_selected_from_ui)
        self.tagsEdit.textEdited.connect(self.update_selected_from_ui)
        self.notesEdit.textChanged.connect(self.update_selected_from_ui)

        self.addAttachBtn.clicked.connect(self.add_attachment)
        self.delAttachBtn.clicked.connect(self.del_attachment)
        self.openAttachBtn.clicked.connect(self.open_attachment)
        self.previewAttachBtn.clicked.connect(self.preview_attachment)
        self.enrichBtn.clicked.connect(self.enrich_selected)

        return panel

    # ---------- Graph ops ----------
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
            EdgeData(source=c, target=b, label="lives in", style="solid"),
        ]
        for nd in self.graph.nodes:
            self.scene.add_node(nd)
        for ed in self.graph.edges:
            self.scene.add_edge(ed)

    def current_node_item(self) -> Optional[NodeItem]:
        sel = self.scene.selectedItems()
        for it in sel:
            if isinstance(it, NodeItem):
                return it
        return None

    def sync_inspector(self):
        it = self.current_node_item()
        if not it:
            return
        nd = it.model
        self.nameEdit.setText(nd.label)
        self.groupBox.setCurrentIndex(self.groupBox.findData(nd.group))
        self.statusBox.setCurrentText(nd.status)
        self.confSlider.setText(str(nd.confidence))
        self.tagsEdit.setText(", ".join(nd.tags))
        self.notesEdit.blockSignals(True)
        self.notesEdit.setPlainText(nd.notes or "")
        self.notesEdit.blockSignals(False)

        self.attachList.clear()
        for a in nd.attachments:
            badge = social_badge_for(a.url) or ""
            txt = f"{badge + ' ' if badge else ''}{a.label}  |  {a.url}"
            QListWidgetItem(txt, self.attachList)

    def apply_search(self, text: str):
        q = (text or "").strip().lower()
        for it in self.scene.nodes.values():
            nd = it.model
            visible = True
            if q:
                def hit():
                    if q in (nd.label or "").lower(): return True
                    if any(q in (t.lower()) for t in nd.tags): return True
                    for a in nd.attachments:
                        if q in (a.label or "").lower() or q in (a.url or "").lower():
                            return True
                    if q in (nd.notes or "").lower(): return True
                    return False
                visible = hit()
            it.setVisible(visible)

    def add_node_ui(self):
        import uuid
        nid = str(uuid.uuid4())
        nd = NodeData(id=nid, x=self.view.mapToScene(self.view.viewport().rect().center()).x(),
                      y=self.view.mapToScene(self.view.viewport().rect().center()).y())
        self.graph.nodes.append(nd)
        self.scene.add_node(nd)

    def update_selected_from_ui(self):
        it = self.current_node_item()
        if not it: return
        nd = it.model
        nd.label = self.nameEdit.text().strip() or "Untitled"
        nd.group = self.groupBox.currentData()
        nd.status = self.statusBox.currentText()
        try:
            nd.confidence = max(0, min(100, int(self.confSlider.text())))
        except Exception:
            nd.confidence = 50
        nd.tags = [t.strip() for t in self.tagsEdit.text().split(",") if t.strip()]
        nd.notes = self.notesEdit.toPlainText()
        it.title.setPlainText(nd.label)
        it.setPen(QPen(qt_color(GROUPS.get(nd.group, {}).get("color", "#adb5bd")), 2))
        it.update_badge()
        it.update_tags()

    def add_attachment(self):
        it = self.current_node_item()
        if not it: return
        # allow either URL input or file picker
        url, _ = QFileDialog.getOpenFileUrl(self, "Pick a file (or Cancel to enter URL)")
        if url.isValid():
            it.model.attachments.append(Attachment(label="file", url=url.toString()))
        else:
            # prompt for URL
            u, ok = QFileDialog.getSaveFileName(self, "Enter URL in filename box then press Save (hacky quick input)")
            # (Simple inline prompt alternatives require extra widgets; keeping single-file.)
            if ok and u:
                if validators.url(u):
                    it.model.attachments.append(Attachment(label="link", url=u))
                else:
                    QMessageBox.warning(self, "Invalid", "Not a valid URL.")
        it.update_attachments()
        self.sync_inspector()

    def del_attachment(self):
        it = self.current_node_item()
        if not it: return
        row = self.attachList.currentRow()
        if row < 0: return
        del it.model.attachments[row]
        it.update_attachments()
        self.sync_inspector()

    def open_attachment(self):
        it = self.current_node_item()
        if not it: return
        row = self.attachList.currentRow()
        if row < 0: return
        a = it.model.attachments[row]
        if not a.url: return
        if a.url.lower().endswith((".png",".jpg",".jpeg",".gif",".webp",".bmp",".svg")):
            dlg = ImagePreview(a.url, self)
            dlg.exec()
        else:
            if a.url.startswith("file://"):
                path = QUrl(a.url).toLocalFile()
                if os.path.exists(path):
                    os.startfile(path) if sys.platform.startswith("win") else os.system(f'xdg-open "{path}"' if sys.platform.startswith("linux") else f'open "{path}"')
            else:
                webbrowser.open(a.url)

    def preview_attachment(self):
        # forced image preview
        self.open_attachment()

    # ---------- Enrich + Email detect ----------
    def extract_emails(self, nd: NodeData) -> List[str]:
        found = set()
        for a in nd.attachments:
            for m in EMAIL_RE.findall((a.url or "") + " " + (a.label or "")):
                found.add(m)
        for m in EMAIL_RE.findall(nd.label or ""):
            found.add(m)
        for m in EMAIL_RE.findall(nd.notes or ""):
            found.add(m)
        return sorted(found)

    def enrich_selected(self):
        it = self.current_node_item()
        if not it: return
        nd = it.model

        # PERSON → add shortcuts
        if nd.group == "person" and nd.label:
            for att in urls_for_person(nd.label):
                if not any(att.url == a.url for a in nd.attachments):
                    nd.attachments.append(att)

        # DOMAIN/URL → whois + dns + favicon
        if nd.group in ("domain","url"):
            target = nd.label
            if nd.group == "url":
                try:
                    ext = tldextract.extract(nd.label)
                    target = ".".join([p for p in [ext.domain, ext.suffix] if p])
                except Exception:
                    pass
            if target:
                w = whois_domain(target)
                if w.get("registrar"):
                    if f"registrar:{w['registrar']}" not in nd.tags:
                        nd.tags.append(f"registrar:{w['registrar']}")
                for ns in w.get("name_servers", []):
                    tag = f"ns:{ns}"
                    if tag not in nd.tags: nd.tags.append(tag)
                dnsr = dns_records(target)
                for k, vals in dnsr.items():
                    for v in vals:
                        tag = f"dns:{k}:{v}"
                        if tag not in nd.tags: nd.tags.append(tag)
                for fav in urls_for_domain(target):
                    if not any(fav.url == a.url for a in nd.attachments):
                        nd.attachments.append(fav)

        # IP → add Shodan/AbuseIPDB links
        if nd.group == "ip":
            for att in urls_for_ip(nd.label):
                if not any(att.url == a.url for a in nd.attachments):
                    nd.attachments.append(att)

        # Email detection across label/notes/attachments
        emails = self.extract_emails(nd)
        if emails:
            for e in emails:
                tag = f"email:{e}"
                if tag not in nd.tags:
                    nd.tags.append(tag)
            nd.status = "suspected" if nd.status == "unknown" else nd.status
            nd.confidence = max(nd.confidence, 60)

        it.update_badge()
        it.update_tags()
        it.update_attachments()
        self.sync_inspector()
        QMessageBox.information(self, "Enrich", "Enrichment complete.")

    # ---------- JSON I/O ----------
    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "mindmap.json", "JSON (*.json)")
        if not path: return
        # pull positions from items
        for nd in self.graph.nodes:
            item = self.scene.nodes.get(nd.id)
            if item:
                pos = item.pos()
                nd.x, nd.y = pos.x(), pos.y()
        data = {
            "nodes": [asdict(n) for n in self.graph.nodes],
            "edges": [asdict(e) for e in self.graph.edges],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        QMessageBox.information(self, "Export", f"Saved to {path}")

    def import_json(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import JSON", "", "JSON (*.json)")
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # clear scene
            self.scene.clear()
            self.scene.nodes.clear()
            self.scene.edges.clear()
            self.graph.nodes = []
            self.graph.edges = []

            # load
            for n in data.get("nodes", []):
                nd = NodeData(**{
                    **n,
                    "attachments": [Attachment(**a) for a in n.get("attachments", [])]
                })
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

def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
