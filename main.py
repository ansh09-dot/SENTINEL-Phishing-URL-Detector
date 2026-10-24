import csv
import ipaddress
import re
import sqlite3
import tkinter as tk

from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox
from urllib.parse import urlparse

# SENTINEL - Phishing URL Analysis Tool

APP_NAME = "SENTINEL // Phishing URL Analysis"
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "sentinel_history.db"

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "update",
    "account", "password", "banking", "signin", "confirm",
    "free", "prize", "reward", "claim", "wallet", "suspended",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rebrand.ly", "shorturl.at",
}

KNOWN_BRANDS = {
    "paypal", "google", "microsoft", "apple",
    "amazon", "facebook", "instagram",
}

EXAMPLE_URLS = [
    "https://www.google.com",
    "https://www.github.com",
    "http://paypal.com.security-check.example.com/login",
    "http://192.0.2.1/secure/login.php?verify=account",
]

COLORS = {
    "background": "#10131c",
    "sidebar": "#191e2b",
    "panel": "#1b2130",
    "panel_dark": "#11151e",
    "border": "#30394b",
    "text": "#dce5f2",
    "muted": "#8996aa",
    "cyan": "#55c7e8",
    "green": "#55d6a2",
    "yellow": "#ffc857",
    "orange": "#ff914d",
    "red": "#ff4d67",
    "white": "#f4f7fb",
}

# DATABASE

def get_connection():
    """Open a connection to the local scan-history database."""
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Create the scan-history table if it does not already exist."""
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                scan_time TEXT NOT NULL,
                detection_reasons TEXT NOT NULL,
                recommendation TEXT NOT NULL
            )
        """)


def save_scan(result):
    """Save one successful analysis and return its record ID."""
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO scan_history (
                scanned_url, hostname, risk_level, risk_score,
                scan_time, detection_reasons, recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result["url"],
            result["hostname"],
            result["risk"],
            result["score"],
            scan_time,
            "\n".join(result["reasons"]),
            result["advice"],
        ))
        return cursor.lastrowid


def get_total_scans():
    """Return the number of saved scans."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM scan_history"
        ).fetchone()
    return row["total"]


def get_scan_history(search_text=""):
    """Return saved scans, newest first, with optional search filtering."""
    query = "SELECT * FROM scan_history"
    parameters = []

    if search_text.strip():
        query += """
            WHERE scanned_url LIKE ?
               OR hostname LIKE ?
               OR risk_level LIKE ?
        """
        term = f"%{search_text.strip()}%"
        parameters = [term, term, term]

    query += " ORDER BY id DESC"

    with get_connection() as connection:
        return connection.execute(query, parameters).fetchall()


def get_scan_by_id(scan_id):
    """Return a single saved scan."""
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM scan_history WHERE id = ?",
            (scan_id,),
        ).fetchone()


def clear_scan_history():
    """Remove all stored scan records."""
    with get_connection() as connection:
        connection.execute("DELETE FROM scan_history")

# URL ANALYSIS

def prepare_url(user_input):
    """Add HTTPS if the user enters a URL without a scheme."""
    url = user_input.strip()
    if not url:
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    return url


def is_ip_address(hostname):
    """Check whether a hostname is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_hostname(hostname):
    """Normalize internationalized domain names to ASCII."""
    return hostname.rstrip(".").encode("idna").decode("ascii").lower()

def analyze_url(user_input):
    """
    Check common URL warning signs and return a heuristic risk score.
    This does not visit the URL or query a threat-intelligence service.
    """
    url = prepare_url(user_input)

    if not url:
        return None, "Enter a URL to start the analysis."

    if any(ord(character) < 32 for character in url):
        return None, "The URL contains invalid control characters."

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return None, "Only HTTP and HTTPS URLs are supported."

        if not parsed.hostname:
            return None, "This URL does not contain a valid hostname."

        hostname = normalize_hostname(parsed.hostname)
        _ = parsed.port  # Accessing port validates malformed port numbers.

    except (ValueError, UnicodeError):
        return None, "The URL format looks invalid. Check it and try again."

    if not hostname or any(character.isspace() for character in hostname):
        return None, "The hostname is invalid."

    score = 0
    reasons = []

    def flag(points, explanation):
        nonlocal score
        score += points
        reasons.append(explanation)

    if is_ip_address(hostname):
        flag(3, "The host is an IP address rather than a regular domain.")

    if parsed.scheme.lower() == "http":
        flag(1, "The connection uses HTTP instead of HTTPS.")

    found_words = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
            url.lower(),
        )
    )
    if found_words:
        flag(
            min(len(found_words), 3),
            "Potentially suspicious words: " + ", ".join(found_words),
        )

    if len(url) > 100:
        flag(1, "The URL is unusually long.")

    if len(hostname.split(".")) >= 5:
        flag(2, "The hostname contains several subdomain levels.")

    if hostname in SHORTENERS:
        flag(2, "The domain is a known URL-shortening service.")

    if "@" in parsed.netloc:
        flag(3, "The network location contains '@', which can obscure the destination.")

    if "-" in hostname:
        flag(1, "The hostname contains a hyphen. This alone does not prove risk.")

    labels = hostname.split(".")
    registered_domain_guess = ".".join(labels[-2:]) if len(labels) >= 2 else hostname

    for brand in KNOWN_BRANDS:
        if brand in hostname:
            is_brand_domain = (
                hostname == f"{brand}.com"
                or hostname.endswith(f".{brand}.com")
            )
            brand_is_domain_label = brand in registered_domain_guess.split(".")

            if not is_brand_domain and not brand_is_domain_label:
                flag(
                    3,
                    f"The hostname may be using the brand name '{brand}' misleadingly.",
                )
                break

    if score >= 5:
        risk = "HIGH RISK"
        advice = (
            "Avoid opening this URL unless you can independently "
            "verify its destination."
        )
    elif score >= 2:
        risk = "MEDIUM RISK"
        advice = (
            "Inspect the registered domain and verify the destination "
            "before proceeding."
        )
    else:
        risk = "LOW RISK"
        advice = (
            "No major warning signs were detected by these rules. "
            "This does not guarantee that the URL is safe."
        )

    if not reasons:
        reasons.append("No obvious warning signs were found by the current rules.")

    return {
        "url": url,
        "hostname": hostname,
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "advice": advice,
    }, None

# APPLICATION INITIALIZATION

try:
    initialize_database()
except sqlite3.Error as error:
    raise SystemExit(f"Could not initialize scan history: {error}")


root = tk.Tk()
root.title(APP_NAME)
root.geometry("1240x820")
root.minsize(1000, 700)
root.configure(bg=COLORS["background"])

style = ttk.Style()
style.theme_use("clam")

style.configure(
    "SOC.TEntry",
    fieldbackground=COLORS["panel_dark"],
    foreground=COLORS["text"],
    insertcolor=COLORS["white"],
    bordercolor=COLORS["border"],
    padding=10,
)
style.configure(
    "SOC.TButton",
    background=COLORS["panel"],
    foreground=COLORS["text"],
    bordercolor=COLORS["border"],
    padding=(12, 9),
    font=("Consolas", 9, "bold"),
)
style.map("SOC.TButton", background=[("active", "#29354a")])
style.configure(
    "Treeview",
    background=COLORS["panel_dark"],
    foreground=COLORS["text"],
    fieldbackground=COLORS["panel_dark"],
    bordercolor=COLORS["border"],
    rowheight=28,
    font=("Consolas", 9),
)
style.configure(
    "Treeview.Heading",
    background=COLORS["panel"],
    foreground=COLORS["cyan"],
    font=("Consolas", 9, "bold"),
)
style.map(
    "Treeview",
    background=[("selected", "#293d55")],
    foreground=[("selected", COLORS["white"])],
)
style.configure(
    "Vertical.TScrollbar",
    background=COLORS["panel"],
    troughcolor=COLORS["panel_dark"],
)

# MAIN LAYOUT

sidebar = tk.Frame(root, bg=COLORS["sidebar"], width=205)
sidebar.pack(side="left", fill="y")
sidebar.pack_propagate(False)

brand = tk.Frame(sidebar, bg=COLORS["sidebar"], padx=18, pady=22)
brand.pack(fill="x")

tk.Label(
    brand, text="✣  SENTINEL",
    font=("Consolas", 16, "bold"),
    fg=COLORS["cyan"], bg=COLORS["sidebar"],
).pack(anchor="w")

tk.Label(
    brand, text="THREAT ANALYSIS CONSOLE",
    font=("Consolas", 8),
    fg=COLORS["muted"], bg=COLORS["sidebar"],
).pack(anchor="w", pady=(6, 0))

tk.Frame(
    sidebar, bg=COLORS["border"], height=1
).pack(fill="x", padx=12, pady=(8, 18))


def sidebar_item(label, active=False):
    """Create a styled sidebar navigation item."""
    background = "#243447" if active else COLORS["sidebar"]
    row = tk.Frame(sidebar, bg=background, padx=16, pady=12)
    row.pack(fill="x", padx=7, pady=2)

    tk.Label(
        row,
        text=("▣  " if active else "›  ") + label,
        font=("Segoe UI", 10, "bold" if active else "normal"),
        fg=COLORS["cyan"] if active else COLORS["muted"],
        bg=background,
    ).pack(anchor="w")


sidebar_item("URL Dashboard", True)
sidebar_item("Threat Analysis")
sidebar_item("Detection Rules")
sidebar_item("Test Samples")

tk.Label(
    sidebar, text="WORKSPACE",
    font=("Consolas", 8, "bold"),
    fg="#65738a", bg=COLORS["sidebar"],
).pack(anchor="w", padx=20, pady=(28, 10))

sidebar_item("Scan History")
sidebar_item("Local Analysis")

sidebar_bottom = tk.Frame(
    sidebar, bg=COLORS["sidebar"], padx=15, pady=15
)
sidebar_bottom.pack(side="bottom", fill="x")

tk.Frame(
    sidebar_bottom, bg=COLORS["border"], height=1
).pack(fill="x", pady=(0, 12))

tk.Label(
    sidebar_bottom, text="●  ANALYZER READY",
    font=("Consolas", 9, "bold"),
    fg=COLORS["green"], bg=COLORS["sidebar"],
).pack(anchor="w")

tk.Label(
    sidebar_bottom, text="Rule-based local checks",
    font=("Segoe UI", 8),
    fg=COLORS["muted"], bg=COLORS["sidebar"],
).pack(anchor="w", pady=(5, 0))


workspace = tk.Frame(root, bg=COLORS["background"])
workspace.pack(side="left", fill="both", expand=True)

topbar = tk.Frame(
    workspace, bg=COLORS["panel"], height=56, padx=20
)
topbar.pack(fill="x")
topbar.pack_propagate(False)

tk.Label(
    topbar, text="THREAT LEVEL: LOCAL ANALYSIS",
    font=("Consolas", 9, "bold"),
    fg=COLORS["yellow"], bg=COLORS["panel"],
).pack(side="left", pady=18)

tk.Label(
    topbar, text="●  ENGINE ONLINE",
    font=("Consolas", 9, "bold"),
    fg=COLORS["green"], bg=COLORS["panel"],
).pack(side="right", pady=18)

content = tk.Frame(
    workspace, bg=COLORS["background"], padx=20, pady=18
)
content.pack(fill="both", expand=True)

heading_row = tk.Frame(content, bg=COLORS["background"])
heading_row.pack(fill="x")

tk.Label(
    heading_row, text="Phishing URL Detector",
    font=("Segoe UI", 22, "bold"),
    fg=COLORS["white"], bg=COLORS["background"],
).pack(side="left")

tk.Label(
    heading_row, text="SECURITY OPERATIONS / URL TRIAGE",
    font=("Consolas", 9),
    fg=COLORS["cyan"], bg=COLORS["background"],
).pack(side="right", pady=(10, 0))

tk.Label(
    content,
    text="Inspect a link for common phishing indicators before opening it.",
    font=("Segoe UI", 10),
    fg=COLORS["muted"], bg=COLORS["background"],
).pack(anchor="w", pady=(5, 18))

# DASHBOARD CARDS

cards = tk.Frame(content, bg=COLORS["background"])
cards.pack(fill="x", pady=(0, 16))

def make_card(parent, title, initial, accent, subtitle):
    """Create one dashboard summary card and return its value label."""
    card = tk.Frame(
        parent,
        bg=COLORS["panel"],
        highlightbackground=COLORS["border"],
        highlightthickness=1,
    )
    card.pack(side="left", fill="both", expand=True, padx=(0, 10))

    tk.Frame(card, bg=accent, height=3).pack(fill="x")

    tk.Label(
        card, text=title,
        font=("Consolas", 8, "bold"),
        fg=COLORS["muted"], bg=COLORS["panel"],
    ).pack(anchor="w", padx=12, pady=(12, 4))

    value = tk.Label(
        card, text=initial,
        font=("Consolas", 15, "bold"),
        fg=accent, bg=COLORS["panel"],
    )
    value.pack(anchor="w", padx=12)

    tk.Label(
        card, text=subtitle,
        font=("Segoe UI", 8),
        fg=COLORS["muted"], bg=COLORS["panel"],
    ).pack(anchor="w", padx=12, pady=(3, 12))

    return value


risk_card_value = make_card(
    cards, "CURRENT RISK", "NOT SCANNED",
    COLORS["cyan"], "Awaiting a URL",
)
score_card_value = make_card(
    cards, "RISK SCORE", "—",
    COLORS["yellow"], "Heuristic points",
)
host_card_value = make_card(
    cards, "HOST STATUS", "UNKNOWN",
    COLORS["orange"], "Domain not checked",
)
scan_card_value = make_card(
    cards, "TOTAL SCANS", str(get_total_scans()),
    COLORS["green"], "Saved local scans",
)

# URL INPUT

input_panel = tk.Frame(
    content, bg=COLORS["panel"],
    highlightbackground=COLORS["border"], highlightthickness=1,
)
input_panel.pack(fill="x", pady=(0, 16))

tk.Label(
    input_panel, text="  URL INVESTIGATION",
    font=("Consolas", 10, "bold"),
    fg=COLORS["cyan"], bg=COLORS["panel"],
).pack(anchor="w", padx=12, pady=(12, 8))

entry_row = tk.Frame(input_panel, bg=COLORS["panel"], padx=14)
entry_row.pack(fill="x", pady=(0, 12))

url_entry = ttk.Entry(
    entry_row, style="SOC.TEntry", font=("Consolas", 11)
)
url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

# RESULTS AND ACTIVITY PANELS

lower = tk.Frame(content, bg=COLORS["background"])
lower.pack(fill="both", expand=True)

details_panel = tk.Frame(
    lower, bg=COLORS["panel"],
    highlightbackground=COLORS["border"], highlightthickness=1,
)
details_panel.pack(side="left", fill="both", expand=True, padx=(0, 12))

tk.Label(
    details_panel, text="  DETECTION REPORT",
    font=("Consolas", 10, "bold"),
    fg=COLORS["cyan"], bg=COLORS["panel"],
).pack(anchor="w", padx=10, pady=(12, 8))

result_box = tk.Text(
    details_panel, height=13, wrap="word",
    font=("Consolas", 9),
    bg=COLORS["panel_dark"], fg=COLORS["text"],
    insertbackground=COLORS["white"], relief="flat",
    padx=12, pady=12, borderwidth=0,
)
result_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
result_box.insert(
    "1.0",
    "SYSTEM READY\n\n"
    "Enter a URL above and select ANALYZE URL.\n\n"
    "This tool checks URL patterns only. It does not visit the site "
    "or query a threat-intelligence service.",
)
result_box.config(state="disabled")

feed_panel = tk.Frame(
    lower, bg=COLORS["panel"], width=245,
    highlightbackground=COLORS["border"], highlightthickness=1,
)
feed_panel.pack(side="right", fill="y")
feed_panel.pack_propagate(False)

tk.Label(
    feed_panel, text="  SCAN ACTIVITY",
    font=("Consolas", 10, "bold"),
    fg=COLORS["cyan"], bg=COLORS["panel"],
).pack(anchor="w", padx=10, pady=(12, 8))

feed_box = tk.Text(
    feed_panel, height=12, wrap="word",
    font=("Consolas", 8),
    bg=COLORS["panel_dark"], fg=COLORS["muted"],
    relief="flat", padx=10, pady=10, borderwidth=0,
)
feed_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
feed_box.insert("1.0", "No scans yet.\n\nRecent scan events will appear here.")
feed_box.config(state="disabled")

footer = tk.Frame(
    workspace, bg=COLORS["panel"], padx=20, pady=8
)
footer.pack(fill="x", side="bottom")

tk.Label(
    footer,
    text="MODE: HEURISTIC  |  NETWORK ACCESS: NONE  |  EDUCATIONAL TOOL",
    font=("Consolas", 8),
    fg=COLORS["muted"], bg=COLORS["panel"],
).pack(side="left")

tk.Label(
    footer, text="● READY",
    font=("Consolas", 8, "bold"),
    fg=COLORS["green"], bg=COLORS["panel"],
).pack(side="right")

# UI HELPERS

def write_result(text):
    """Replace the report text and make the report read-only."""
    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, text)
    result_box.config(state="disabled")


def add_activity(risk, hostname, scan_time=None):
    """Add a scan event to the activity panel."""
    feed_box.config(state="normal")

    current_text = feed_box.get("1.0", tk.END).strip()
    if current_text.startswith("No scans yet."):
        feed_box.delete("1.0", tk.END)

    if scan_time is None:
        scan_time = datetime.now().strftime("%H:%M:%S")
    else:
        try:
            scan_time = datetime.strptime(
                scan_time, "%Y-%m-%d %H:%M:%S"
            ).strftime("%H:%M:%S")
        except ValueError:
            pass

    feed_box.insert("1.0", f"[{scan_time}]  {risk}\n{hostname}\n\n")
    feed_box.config(state="disabled")


def refresh_dashboard():
    """Refresh the saved scan count shown on the dashboard."""
    try:
        scan_card_value.config(text=str(get_total_scans()))
    except sqlite3.Error as error:
        messagebox.showerror(
            "Database Error",
            f"Could not read scan history:\n{error}",
            parent=root,
        )


def format_scan_report(result):
    """Build a readable text report from an analysis result."""
    lines = [
        "SENTINEL - URL ANALYSIS REPORT",
        "=" * 52,
        f"Scan time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Risk level : {result['risk']}",
        f"Risk score : {result['score']}",
        f"Hostname   : {result['hostname']}",
        f"Full URL   : {result['url']}",
        "",
        "DETECTION NOTES",
        "-" * 52,
    ]

    lines.extend(
        f"[{index}] {reason}"
        for index, reason in enumerate(result["reasons"], start=1)
    )

    lines.extend([
        "",
        "RECOMMENDATION",
        "-" * 52,
        result["advice"],
        "",
        "LIMITATIONS",
        "-" * 52,
        "This report was generated by local heuristic rules.",
        "No website was visited and no live reputation service was queried.",
        "A low-risk result does not guarantee that a URL is safe.",
    ])

    return "\n".join(lines)

# SCAN ACTIONS

def analyze_button():
    """Analyze the entered URL and update the dashboard."""
    user_input = url_entry.get()
    result, error = analyze_url(user_input)

    if error:
        write_result("INPUT ERROR\n\n" + error)
        risk_card_value.config(text="INVALID INPUT", fg=COLORS["orange"])
        score_card_value.config(text="—", fg=COLORS["yellow"])
        host_card_value.config(text="NOT CHECKED", fg=COLORS["orange"])
        return

    try:
        save_scan(result)
    except sqlite3.Error as error:
        messagebox.showerror(
            "Database Error",
            f"The URL was analyzed, but its history could not be saved.\n\n{error}",
            parent=root,
        )

    risk_colors = {
        "LOW RISK": COLORS["green"],
        "MEDIUM RISK": COLORS["yellow"],
        "HIGH RISK": COLORS["red"],
    }
    risk_color = risk_colors[result["risk"]]

    risk_card_value.config(text=result["risk"], fg=risk_color)
    score_card_value.config(text=str(result["score"]), fg=risk_color)
    host_card_value.config(
        text="IP ADDRESS" if is_ip_address(result["hostname"]) else "DOMAIN",
        fg=COLORS["orange"],
    )

    report = format_scan_report(result)
    write_result(report)
    add_activity(result["risk"], result["hostname"])
    refresh_dashboard()


def clear_fields():
    """Clear the input and report without deleting saved history."""
    url_entry.delete(0, tk.END)
    risk_card_value.config(text="NOT SCANNED", fg=COLORS["cyan"])
    score_card_value.config(text="—", fg=COLORS["yellow"])
    host_card_value.config(text="UNKNOWN", fg=COLORS["orange"])

    write_result(
        "SYSTEM READY\n\n"
        "Enter a URL above and select ANALYZE URL.\n\n"
        "Clearing this screen does not delete saved scan history."
    )
    url_entry.focus_set()


def insert_example():
    """Insert the next sample URL and analyze it."""
    if not hasattr(insert_example, "index"):
        insert_example.index = 0

    url_entry.delete(0, tk.END)
    url_entry.insert(0, EXAMPLE_URLS[insert_example.index])
    insert_example.index = (insert_example.index + 1) % len(EXAMPLE_URLS)
    analyze_button()


def export_current_report():
    """Export the report currently shown in the results panel."""
    report_text = result_box.get("1.0", tk.END).strip()

    if not report_text or report_text.startswith("SYSTEM READY"):
        messagebox.showinfo(
            "No Report",
            "Analyze a URL before exporting a report.",
            parent=root,
        )
        return

    destination = filedialog.asksaveasfilename(
        parent=root,
        title="Export Analysis Report",
        defaultextension=".txt",
        filetypes=[("Text report", "*.txt"), ("All files", "*.*")],
        initialfile="sentinel_report.txt",
    )

    if not destination:
        return

    try:
        Path(destination).write_text(report_text, encoding="utf-8")
        messagebox.showinfo(
            "Export Complete",
            "The report was exported successfully.",
            parent=root,
        )
    except OSError as error:
        messagebox.showerror(
            "Export Error",
            f"Could not export the report:\n{error}",
            parent=root,
        )


def export_history_csv():
    """Export all saved scan records to a CSV file."""
    try:
        rows = get_scan_history()
    except sqlite3.Error as error:
        messagebox.showerror(
            "Database Error", str(error), parent=root
        )
        return

    if not rows:
        messagebox.showinfo(
            "No History",
            "There are no saved scans to export.",
            parent=root,
        )
        return

    destination = filedialog.asksaveasfilename(
        parent=root,
        title="Export Scan History",
        defaultextension=".csv",
        filetypes=[("CSV file", "*.csv"), ("All files", "*.*")],
        initialfile="sentinel_scan_history.csv",
    )

    if not destination:
        return

    try:
        with open(destination, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.writer(file)
            writer.writerow([
                "ID", "Scanned URL", "Hostname", "Risk Level",
                "Risk Score", "Scan Time", "Detection Reasons",
                "Recommendation",
            ])

            for row in rows:
                writer.writerow([
                    row["id"],
                    row["scanned_url"],
                    row["hostname"],
                    row["risk_level"],
                    row["risk_score"],
                    row["scan_time"],
                    row["detection_reasons"],
                    row["recommendation"],
                ])

        messagebox.showinfo(
            "Export Complete",
            "Scan history was exported successfully.",
            parent=root,
        )
    except OSError as error:
        messagebox.showerror(
            "Export Error", str(error), parent=root
        )

# SCAN HISTORY WINDOW

def show_scan_details(event=None):
    """Display details for the selected history row."""
    selection = history_tree.selection()

    if not selection:
        return

    values = history_tree.item(selection[0], "values")
    if not values:
        return

    try:
        scan = get_scan_by_id(int(values[0]))
    except (ValueError, sqlite3.Error) as error:
        messagebox.showerror(
            "History Error", str(error), parent=history_window
        )
        return

    if scan is None:
        messagebox.showwarning(
            "Record Not Found",
            "This scan record could not be found.",
            parent=history_window,
        )
        return

    report = [
        "SAVED SCAN DETAILS",
        "=" * 48,
        f"Record ID  : {scan['id']}",
        f"Scan time  : {scan['scan_time']}",
        f"Risk level : {scan['risk_level']}",
        f"Risk score : {scan['risk_score']}",
        f"Hostname   : {scan['hostname']}",
        f"Full URL   : {scan['scanned_url']}",
        "",
        "DETECTION NOTES",
        "-" * 48,
        scan["detection_reasons"],
        "",
        "RECOMMENDATION",
        "-" * 48,
        scan["recommendation"],
    ]

    details_text.config(state="normal")
    details_text.delete("1.0", tk.END)
    details_text.insert("1.0", "\n".join(report))
    details_text.config(state="disabled")


def populate_history(search_text=""):
    """Reload the history table using the current search filter."""
    for item in history_tree.get_children():
        history_tree.delete(item)

    try:
        rows = get_scan_history(search_text)
    except sqlite3.Error as error:
        messagebox.showerror(
            "Database Error", str(error), parent=history_window
        )
        return

    for row in rows:
        history_tree.insert("", tk.END, values=(
            row["id"],
            row["scan_time"],
            row["hostname"],
            row["risk_level"],
            row["risk_score"],
            row["scanned_url"],
        ))

    history_count_label.config(text=f"Records: {len(rows)}")


def clear_history_action():
    """Ask for confirmation before deleting all history."""
    confirmed = messagebox.askyesno(
        "Clear Scan History",
        "Permanently delete all saved scan records?\n\nThis cannot be undone.",
        parent=history_window,
    )

    if not confirmed:
        return

    try:
        clear_scan_history()
        populate_history(search_var.get())
        details_text.config(state="normal")
        details_text.delete("1.0", tk.END)
        details_text.insert("1.0", "Scan history has been cleared.")
        details_text.config(state="disabled")
        refresh_dashboard()
        feed_box.config(state="normal")
        feed_box.delete("1.0", tk.END)
        feed_box.insert("1.0", "No scans yet.\n\nRecent scan events will appear here.")
        feed_box.config(state="disabled")
    except sqlite3.Error as error:
        messagebox.showerror(
            "Database Error", str(error), parent=history_window
        )


def open_history_window():
    """Open a searchable window containing saved scan history."""
    global history_window, history_tree, details_text
    global history_count_label, search_var

    if "history_window" in globals() and history_window.winfo_exists():
        history_window.deiconify()
        history_window.lift()
        populate_history(search_var.get())
        return

    history_window = tk.Toplevel(root)
    history_window.title("SENTINEL // Scan History")
    history_window.geometry("1100x650")
    history_window.minsize(850, 500)
    history_window.configure(bg=COLORS["background"])

    heading = tk.Frame(
        history_window, bg=COLORS["panel"], padx=16, pady=12
    )
    heading.pack(fill="x")

    tk.Label(
        heading, text="Saved Scan History",
        font=("Segoe UI", 18, "bold"),
        fg=COLORS["white"], bg=COLORS["panel"],
    ).pack(side="left")

    history_count_label = tk.Label(
        heading, text="Records: 0",
        font=("Consolas", 9, "bold"),
        fg=COLORS["cyan"], bg=COLORS["panel"],
    )
    history_count_label.pack(side="right")

    search_row = tk.Frame(
        history_window, bg=COLORS["background"], padx=14, pady=12
    )
    search_row.pack(fill="x")

    tk.Label(
        search_row, text="Search URL, hostname or risk:",
        font=("Segoe UI", 9),
        fg=COLORS["text"], bg=COLORS["background"],
    ).pack(side="left", padx=(0, 8))

    search_var = tk.StringVar()
    search_entry = ttk.Entry(
        search_row, textvariable=search_var,
        style="SOC.TEntry", width=32,
    )
    search_entry.pack(side="left", padx=(0, 8))

    ttk.Button(
        search_row, text="SEARCH",
        style="SOC.TButton",
        command=lambda: populate_history(search_var.get()),
    ).pack(side="left", padx=(0, 8))

    ttk.Button(
        search_row, text="REFRESH",
        style="SOC.TButton",
        command=lambda: populate_history(search_var.get()),
    ).pack(side="left", padx=(0, 8))

    ttk.Button(
        search_row, text="EXPORT CSV",
        style="SOC.TButton",
        command=export_history_csv,
    ).pack(side="left", padx=(0, 8))

    ttk.Button(
        search_row, text="CLEAR HISTORY",
        style="SOC.TButton",
        command=clear_history_action,
    ).pack(side="right")

    table_frame = tk.Frame(
        history_window, bg=COLORS["background"], padx=14
    )
    table_frame.pack(fill="both", expand=True)

    columns = ("id", "time", "hostname", "risk", "score", "url")
    history_tree = ttk.Treeview(
        table_frame, columns=columns, show="headings",
        selectmode="browse",
    )

    column_settings = {
        "id": ("ID", 55),
        "time": ("SCAN TIME", 155),
        "hostname": ("HOSTNAME", 170),
        "risk": ("RISK LEVEL", 115),
        "score": ("SCORE", 65),
        "url": ("SCANNED URL", 390),
    }

    for column, (heading_text, width) in column_settings.items():
        history_tree.heading(column, text=heading_text)
        history_tree.column(column, width=width, minwidth=50, anchor="w")

    vertical_scroll = ttk.Scrollbar(
        table_frame, orient="vertical", command=history_tree.yview
    )
    horizontal_scroll = ttk.Scrollbar(
        table_frame, orient="horizontal", command=history_tree.xview
    )

    history_tree.configure(
        yscrollcommand=vertical_scroll.set,
        xscrollcommand=horizontal_scroll.set,
    )

    history_tree.grid(row=0, column=0, sticky="nsew")
    vertical_scroll.grid(row=0, column=1, sticky="ns")
    horizontal_scroll.grid(row=1, column=0, sticky="ew")

    table_frame.rowconfigure(0, weight=1)
    table_frame.columnconfigure(0, weight=1)

    history_tree.bind("<<TreeviewSelect>>", show_scan_details)
    history_tree.bind("<Double-1>", show_scan_details)

    tk.Label(
        history_window, text="SELECT A RECORD TO VIEW DETAILS",
        font=("Consolas", 9, "bold"),
        fg=COLORS["cyan"], bg=COLORS["background"],
    ).pack(anchor="w", padx=14, pady=(12, 4))

    details_text = tk.Text(
        history_window, height=8, wrap="word",
        font=("Consolas", 9),
        bg=COLORS["panel_dark"], fg=COLORS["text"],
        relief="flat", padx=10, pady=8,
    )
    details_text.pack(fill="x", padx=14, pady=(0, 14))
    details_text.insert("1.0", "Select a scan record above to see its details.")
    details_text.config(state="disabled")

    search_entry.bind(
        "<Return>",
        lambda event: populate_history(search_var.get()),
    )

    populate_history()

# BUTTONS AND KEYBOARD SHORTCUTS

ttk.Button(
    entry_row, text="ANALYZE URL",
    style="SOC.TButton", command=analyze_button,
).pack(side="left", padx=(0, 7))

ttk.Button(
    entry_row, text="TRY SAMPLE",
    style="SOC.TButton", command=insert_example,
).pack(side="left", padx=(0, 7))

ttk.Button(
    entry_row, text="CLEAR",
    style="SOC.TButton", command=clear_fields,
).pack(side="left", padx=(0, 7))

ttk.Button(
    entry_row, text="HISTORY",
    style="SOC.TButton", command=open_history_window,
).pack(side="left")

actions_row = tk.Frame(content, bg=COLORS["background"])
actions_row.pack(fill="x", pady=(0, 10))

ttk.Button(
    actions_row, text="OPEN SCAN HISTORY",
    style="SOC.TButton", command=open_history_window,
).pack(side="left", padx=(0, 8))

ttk.Button(
    actions_row, text="EXPORT CURRENT REPORT",
    style="SOC.TButton", command=export_current_report,
).pack(side="left", padx=(0, 8))

ttk.Button(
    actions_row, text="EXPORT ALL SCANS (CSV)",
    style="SOC.TButton", command=export_history_csv,
).pack(side="left")

url_entry.bind("<Return>", lambda event: analyze_button())
root.bind("<Control-l>", lambda event: url_entry.focus_set())
root.bind("<Control-h>", lambda event: open_history_window())

url_entry.focus_set()
root.mainloop()
