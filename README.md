# Osint-Mindmap-


🗺️ Infinite canvas with pan, zoom, and minimap

🧍 Node types: NPC, Location, Quest, Item, Faction, Person, Org, Domain, IP, URL, Note

🔗 Attachments: multiple links, local files, and image previews per node

🌐 Auto favicon/social icon detection for links (Twitter, Instagram, GitHub, etc.)

📨 Automatic email detection inside labels/attachments

🕵️ Contextual OSINT shortcuts (e.g., WHOIS, Shodan, LinkedIn, HIBP)

🧭 Drag & drop files or URLs to auto-create nodes

🪄 JSON import/export + local autosave

⚡ Optional Python backend for enrichment (e.g., WHOIS lookups, scraping, tagging)
🖱️ Canvas Interaction



Drag canvas: Right-click drag or hold Space + Left drag

Zoom: Mouse wheel

MiniMap: Navigate by clicking/dragging the minimap

➕ Nodes & Edges

Create Node: Toolbar + Node

Drag & Drop: Drop any file or URL to auto-create a node

Connect Nodes: Click a node’s port (handle) and drag to another node

Delete Node/Edge: Select → Delete or Backspace

Change Edge Style: Toolbar dropdown (Solid / Dashed / Dotted)

🧭 Inspector Panel

Edit node name, type, status, confidence slider

Add/remove tags (press Enter to add)

Add/remove attachments (links, files, or emails)

Automatic social icons and email extraction

OSINT Shortcuts appear based on node type:

Domain/URL → WHOIS, DNSViz, ViewDNS

IP → Shodan, RIPE, AbuseIPDB

Person → Google, LinkedIn, HaveIBeenPwned

🧰 Import/Export

Export entire canvas as mindmap.json

Import saved mindmap JSON to restore

Data is auto-saved in your browser’s localStorage.

⌨️ Keyboard Shortcuts
Key	Action
Delete / Backspace	Delete selected node or edge
+ / -	Zoom in/out
Shift + Drag	Pan canvas
Enter	Add tag
Ctrl/Cmd + S	Export JSON
Ctrl/Cmd + O	Import JSON
Space (hold)	Hand tool / pan
1 / 2 / 3	Edge style: solid / dashed / dotted
🧠 OSINT Automation (Optional)

If the Python backend is running (http://127.0.0.1:8795 by default), you can:

Enrich selected node with WHOIS/DNS/IP lookups.

Auto-add tags, status, confidence, and attachments.

Extend backend with your own enrichment scripts.
