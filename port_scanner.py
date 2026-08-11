#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Scanner + Banner Grabber
=============================

Semplice port scanner didattico scritto in Python puro (solo libreria
standard, nessuna dipendenza esterna richiesta).

Funzionalità:
- Scansione multithread di un range di porte su un host
- Banner grabbing per identificare il servizio in ascolto
- Confronto con un piccolo database di versioni note per segnalare
  software potenzialmente datato
- Report finale in formato testo e HTML

⚠️  USO LEGALE ED ETICO
Questo strumento va usato ESCLUSIVAMENTE su:
  - sistemi di tua proprietà
  - macchine di laboratorio (es. VM locali)
  - ambienti pensati per il training (TryHackMe, HackTheBox, ecc.)
Scansionare porte di sistemi altrui senza autorizzazione esplicita è
illegale in molte giurisdizioni, Italia inclusa (art. 615-ter c.p. e
normative simili). L'autore non si assume responsabilità per usi impropri.

Autore: (il tuo nome)
Licenza: MIT
"""

import argparse
import socket
import sys
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ----------------------------------------------------------------------
# CONFIGURAZIONE
# ----------------------------------------------------------------------

DEFAULT_TIMEOUT = 1.0          # secondi di attesa per ogni connessione
DEFAULT_THREADS = 100          # connessioni parallele
BANNER_READ_TIMEOUT = 1.5      # secondi di attesa per leggere il banner
BANNER_MAX_BYTES = 256         # quanti byte leggere al massimo dal banner

# Porte più comuni, usate se l'utente non specifica un range custom
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

# Mappa porta -> nome servizio "atteso" (solo indicativo, il banner reale
# ha sempre la precedenza se disponibile)
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

# Database (volutamente piccolo e didattico) di versioni note come datate.
# Il confronto è una semplice ricerca di sottostringa nel banner, quindi
# è pensato per dare un'idea del concetto, NON come fonte affidabile di
# vulnerability intelligence reale (per quello servono CVE feed veri,
# es. NVD, Vulners, ecc.).
KNOWN_OUTDATED_SIGNATURES = {
    "OpenSSH_5": "OpenSSH 5.x è molto datato (rilasciato ~2008-2011): valuta l'aggiornamento.",
    "OpenSSH_6": "OpenSSH 6.x è datato (rilasciato ~2011-2014): valuta l'aggiornamento.",
    "Apache/2.2": "Apache 2.2 ha raggiunto End-of-Life: aggiornamento fortemente consigliato.",
    "Apache/2.4.6": "Versione Apache 2.4.6 nota per diverse CVE storiche: verifica la versione installata.",
    "nginx/1.1": "Nginx 1.1.x è molto datato: valuta l'aggiornamento.",
    "vsFTPd 2.3.4": "Versione storicamente associata a una backdoor nota (CVE-2011-2523).",
    "ProFTPD 1.3.3": "Versione con vulnerabilità note (CVE-2010-4221 e altre).",
}


# ----------------------------------------------------------------------
# CORE SCANNER
# ----------------------------------------------------------------------

def scan_port(host, port, timeout):
    """
    Prova ad aprire una connessione TCP verso host:port.
    Ritorna True se la porta risulta aperta, False altrimenti.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except socket.error:
        return False


def grab_banner(host, port, timeout):
    """
    Tenta di leggere il banner inviato dal servizio in ascolto sulla porta.
    Molti servizi (SSH, FTP, SMTP...) inviano una stringa di benvenuto
    non appena si stabilisce la connessione. Per servizi che invece
    aspettano una richiesta (es. HTTP), inviamo una richiesta minima.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Alcuni servizi (es. HTTP) non mandano nulla finché non
            # ricevono una richiesta: proviamo a stimolarli.
            if port in (80, 8080, 8000):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in (443, 8443):
                # Il banner grabbing "in chiaro" su TLS non funziona senza
                # handshake TLS: qui ci limitiamo a segnalarlo.
                return "(HTTPS/TLS - banner grabbing in chiaro non disponibile)"

            data = sock.recv(BANNER_MAX_BYTES)
            banner = data.decode(errors="ignore").strip()
            return banner if banner else None
    except (socket.error, UnicodeDecodeError):
        return None


def check_known_vulnerable(banner):
    """
    Confronta il banner con il piccolo database di firme datate.
    Ritorna un messaggio di warning se trova una corrispondenza, altrimenti None.
    """
    if not banner:
        return None
    for signature, warning in KNOWN_OUTDATED_SIGNATURES.items():
        if signature in banner:
            return warning
    return None


def scan_host(host, ports, timeout, threads, grab_banners=True):
    """
    Scansiona una lista di porte su un host, in parallelo.
    Ritorna una lista di dizionari con i risultati delle porte aperte.
    """
    open_ports = []

    print(f"[*] Scansione di {host} su {len(ports)} porte (timeout={timeout}s, thread={threads})...\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
            except Exception:
                is_open = False

            if is_open:
                service_guess = KNOWN_SERVICES.get(port, "sconosciuto")
                print(f"[+] Porta {port:>5} APERTA  (servizio atteso: {service_guess})")
                open_ports.append({
                    "port": port,
                    "service_guess": service_guess,
                    "banner": None,
                    "warning": None,
                })

    # Banner grabbing eseguito dopo, solo sulle porte aperte, per non
    # rallentare/interferire con lo scan iniziale.
    if grab_banners and open_ports:
        print("\n[*] Banner grabbing sulle porte aperte...\n")
        for entry in open_ports:
            banner = grab_banner(host, entry["port"], BANNER_READ_TIMEOUT)
            entry["banner"] = banner
            if banner:
                print(f"    Porta {entry['port']:>5}: {banner[:100]}")
                entry["warning"] = check_known_vulnerable(banner)
                if entry["warning"]:
                    print(f"    ⚠  {entry['warning']}")

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


# ----------------------------------------------------------------------
# REPORT
# ----------------------------------------------------------------------

def build_report_data(host, open_ports, duration_seconds):
    return {
        "host": host,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round(duration_seconds, 2),
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
    }


def save_text_report(report_data, filepath):
    lines = []
    lines.append("=" * 60)
    lines.append("PORT SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Host:           {report_data['host']}")
    lines.append(f"Data scansione: {report_data['scan_date']}")
    lines.append(f"Durata:         {report_data['duration_seconds']}s")
    lines.append(f"Porte aperte:   {report_data['open_ports_count']}")
    lines.append("-" * 60)

    if not report_data["open_ports"]:
        lines.append("Nessuna porta aperta trovata nel range scansionato.")
    else:
        for entry in report_data["open_ports"]:
            lines.append(f"\nPorta {entry['port']} ({entry['service_guess']})")
            if entry["banner"]:
                lines.append(f"  Banner:  {entry['banner']}")
            else:
                lines.append("  Banner:  (nessun banner ricevuto)")
            if entry["warning"]:
                lines.append(f"  ⚠ WARNING: {entry['warning']}")

    lines.append("\n" + "=" * 60)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n[*] Report testuale salvato in: {filepath}")


def save_html_report(report_data, filepath):
    rows_html = ""
    if not report_data["open_ports"]:
        rows_html = '<tr><td colspan="4" style="text-align:center;">Nessuna porta aperta trovata</td></tr>'
    else:
        for entry in report_data["open_ports"]:
            banner = entry["banner"] or "-"
            warning = entry["warning"] or ""
            warning_html = f'<span class="warning">⚠ {warning}</span>' if warning else ""
            rows_html += f"""
            <tr>
                <td>{entry['port']}</td>
                <td>{entry['service_guess']}</td>
                <td>{banner}</td>
                <td>{warning_html}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<title>Port Scan Report - {report_data['host']}</title>
<style>
    body {{ font-family: -apple-system, Segoe UI, sans-serif; background:#0f1115; color:#e6e6e6; padding:2rem; }}
    h1 {{ color:#4fd1c5; }}
    .meta {{ color:#9aa0a6; margin-bottom:1.5rem; }}
    table {{ width:100%; border-collapse:collapse; background:#181b21; }}
    th, td {{ text-align:left; padding:0.6rem 0.8rem; border-bottom:1px solid #2a2e35; }}
    th {{ background:#20242c; color:#4fd1c5; }}
    tr:hover {{ background:#20242c; }}
    .warning {{ color:#f6ad55; }}
    .footer {{ margin-top:2rem; color:#666; font-size:0.85rem; }}
</style>
</head>
<body>
    <h1>Port Scan Report</h1>
    <div class="meta">
        Host: <strong>{report_data['host']}</strong> &middot;
        Data: {report_data['scan_date']} &middot;
        Durata: {report_data['duration_seconds']}s &middot;
        Porte aperte: {report_data['open_ports_count']}
    </div>
    <table>
        <thead>
            <tr><th>Porta</th><th>Servizio atteso</th><th>Banner</th><th>Note</th></tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
    <div class="footer">
        Generato con port-scanner-toolkit &middot; solo per uso su sistemi propri o autorizzati.
    </div>
</body>
</html>
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[*] Report HTML salvato in: {filepath}")


def save_json_report(report_data, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f"[*] Report JSON salvato in: {filepath}")


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def parse_port_range(port_arg):
    """
    Converte l'argomento --ports in una lista di interi.
    Supporta: singola porta ("80"), range ("1-1024"), lista ("22,80,443").
    """
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="Port scanner + banner grabber didattico (solo per uso etico/autorizzato).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("host", help="IP o hostname da scansionare (es. 127.0.0.1)")
    parser.add_argument(
        "-p", "--ports", default=None,
        help="Porte da scansionare: singola (80), range (1-1024) o lista (22,80,443). "
             "Se omesso, usa un set di porte comuni."
    )
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                         help="Timeout in secondi per ogni connessione")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_THREADS,
                         help="Numero di thread paralleli")
    parser.add_argument("--no-banner", action="store_true",
                         help="Disattiva il banner grabbing (solo scan porte)")
    parser.add_argument("-o", "--output-dir", default="reports",
                         help="Cartella dove salvare i report")
    parser.add_argument("--formats", default="txt,html",
                         help="Formati di report da generare, separati da virgola: txt,html,json")

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[!] Impossibile risolvere l'host: {args.host}")
        sys.exit(1)

    ports = parse_port_range(args.ports) if args.ports else COMMON_PORTS

    print(f"[*] Target: {args.host} ({target_ip})")

    start_time = datetime.now()
    open_ports = scan_host(
        target_ip, ports,
        timeout=args.timeout,
        threads=args.workers,
        grab_banners=not args.no_banner,
    )
    duration = (datetime.now() - start_time).total_seconds()

    print(f"\n[*] Scansione completata in {duration:.2f}s. "
          f"Porte aperte trovate: {len(open_ports)}")

    report_data = build_report_data(args.host, open_ports, duration)

    os.makedirs(args.output_dir, exist_ok=True)
    safe_host = args.host.replace(":", "_").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"scan_{safe_host}_{timestamp}"

    formats = [f.strip().lower() for f in args.formats.split(",")]
    if "txt" in formats:
        save_text_report(report_data, os.path.join(args.output_dir, base_filename + ".txt"))
    if "html" in formats:
        save_html_report(report_data, os.path.join(args.output_dir, base_filename + ".html"))
    if "json" in formats:
        save_json_report(report_data, os.path.join(args.output_dir, base_filename + ".json"))


if __name__ == "__main__":
    main()
