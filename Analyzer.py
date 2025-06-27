import sys, socket, logging
from datetime import datetime
from scapy.all import rdpcap, sniff, IP, TCP, UDP, get_if_list
try:
    from scapy.arch.windows import get_windows_if_list # For Windows
except ImportError:
    get_windows_if_list = get_if_list # For Linux/MacOS
import pandas as pd
from tabulate import tabulate
from tqdm import tqdm
import geoip2.database, geoip2.errors

# ---------------------- Constants & Logging ----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("network-analyzer")
# ---------------------- Constants & Logging ----------------------

def protocol_name(num):
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(num, f"OTHER({num})")

def load_blacklist_entries(path):
    entries = set()
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.split("#",1)[0].strip() # Removes comments
                if line:
                    entries.add(line)
    except FileNotFoundError:
        logger.error(f"Blacklist file not found: {path}")
        sys.exit(1)
    logger.info(f"Loaded Blacklist Entries: {entries}")
    return entries

def build_blacklist(entries):
    ips = set()
    for e in entries:
        # if valid IPv4 literal
        try:
            socket.inet_aton(e)
            ips.add(e)
            continue
        except socket.error:
            pass
        # otherwise resolve hostname
        try:
            for res in socket.getaddrinfo(e, None, family=socket.AF_INET):
                ips.add(res[4][0])
        except socket.gaierror as ge:
            logger.warning(f"Could not resolve '{e}': {ge}")
    logger.info(f"Resolved Blacklisted IPs: {ips}")
    return ips

def geo_lookup(reader, ip):
    try:
        rec = reader.city(ip)
        return (
            rec.city.name or "Unknown",
            rec.subdivisions.most_specific.iso_code or "Unknown",
            rec.country.name or "Unknown",
            rec.location.latitude  or 0.0,
            rec.location.longitude or 0.0
        )
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception as e:
        logger.error(f"GeoIP lookup error for {ip}: {e}")
        return None

def analyze_packets(packets, blacklist_ips, port_scan_threshold, geo_db):
    try:
        reader = geoip2.database.Reader(geo_db)
    except FileNotFoundError:
        logger.error(f"GeoIP database not found: {geo_db}")
        sys.exit(1)
    
    total_captured = len(packets)
    logger.info(f"Captured {total_captured} packets, processing IPv4 only…")

    rows = []
    seen_blacklist = set()

    for i, pkt in enumerate(tqdm(packets, desc="Processing packets"), start=1):
        if IP not in pkt:
            continue
        try:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            size = len(pkt)
            dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

            rows.append({
                "src": src,
                "dst": dst,
                "protocol": protocol_name(proto),
                "size": size,
                "dst_port": dst_port
            })

            if src in blacklist_ips:
                seen_blacklist.add(src)
            if dst in blacklist_ips:
                seen_blacklist.add(dst)

        except Exception as e:
            logger.error(f"Error processing packet {pkt.summary()}: {e}")
            continue

    df = pd.DataFrame(rows)
    if df.empty or "size" not in df.columns:
        logger.warning("No IP packet data found; nothing to analyze.")
        reader.close()
        return

    # ------------- Overall Stats --------------
    total_bytes = df["size"].sum()
    bw = total_bytes / 1e6
    logger.info(f"Total traffic: {total_bytes} bytes ({bw:.4f} MB)")
    print()

    # ------------ Protocol Breakdown ------------ 
    proto_counts = (
        df["protocol"]
        .value_counts()
        .rename_axis("protocol")
        .reset_index(name="count")
    )
    proto_counts["percentage"] = 100 * proto_counts["count"] / proto_counts["count"].sum()
    logger.info("\nProtocol breakdown:\n%s", tabulate(proto_counts, headers="keys", tablefmt="fancy_grid", floatfmt=".1f"))
    print()

    # ------------ Top Talkers ------------
    talkers = (
        df.groupby(["src","dst"])
          .size()
          .reset_index(name="count")
          .sort_values("count", ascending=False)
          .head(10)
          .reset_index(drop=True)
    )
    logger.info("\nTop 10 src --> dst flows:\n%s", tabulate(talkers, headers="keys", tablefmt="fancy_grid"))
    print()

    # ------------ Port-Scan Detection ------------
    scans = (
        df.dropna(subset=["dst_port"])
          .groupby(["src","dst_port"])
          .size()
          .reset_index(name="cnt")
          .reset_index(drop=True)
    )
    uniq_ports = scans.groupby("src").size().reset_index(name="ports_scanned")
    suspects = (uniq_ports[uniq_ports["ports_scanned"] >= port_scan_threshold] .reset_index(drop=True))
    if not suspects.empty:
        logger.warning("\nPort-scan suspects:\n%s", tabulate(suspects, headers="keys", tablefmt="fancy_grid"))
        print()

    # ---------- Geolocate blacklisted IPs ----------
    if seen_blacklist:
        logger.info("Blacklisted IPs seen: %s", seen_blacklist)

        # Collect peers that communicated with blacklisted IPs
        peers = set()
        for i, row in df.iterrows():
            if row["src"] in seen_blacklist:
                peers.add(row["dst"])
            if row["dst"] in seen_blacklist:
                peers.add(row["src"])

        # Combine blacklisted IPs + peers for geolocation
        geo_targets = seen_blacklist.union(peers)

        geo_rows = []
        for ip in geo_targets:
            info = geo_lookup(reader, ip)
            if info:
                city, region, country, lat, lon = info
                if city == "Unknown" and region == "Unknown" and country == "Unknown":
                    continue
                geo_rows.append(dict(ip=ip, city=city, region=region, country=country, lat=lat, lon=lon))
            else:
                continue


        geo_df = pd.DataFrame(geo_rows)
        logger.info("\nGeolocation of Blacklisted IPs and peers:\n%s", tabulate(geo_df, headers="keys", tablefmt="fancy_grid", floatfmt=".4f"))
        print()

        # ---------- KML ----------
        kml_name = f"blacklist_{datetime.now().strftime('%m%d%Y_%Hh%Mm')}.kml"
        try:
            with open(kml_name,"w") as kml:
                kml.write("""<?xml version="1.0"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>Blacklisted IPs and Peers</name>""")
                for i,r in geo_df.iterrows():
                    kml.write(f"""<Placemark><name>{r.ip} ({r.city}, {r.country})</name><Point><coordinates>{r.lon},{r.lat},0</coordinates></Point></Placemark>""")
                kml.write("</Document></kml>")
            logger.info("Wrote %s", kml_name)
        except Exception as e:
            logger.error(f"Failed to write KML: {e}")
    else:
        logger.info("No blacklisted IPs found.")

    reader.close()

live_packets = []
packet_counter = {"count": 0}  # Dictionary to mutate count inside nested function

def handle_live_packet(pkt):
    if IP not in pkt:
        return
    live_packets.append(pkt)
    packet_counter["count"] += 1
    if packet_counter["count"] % 1000 == 0:
        logger.info(f"Processed {packet_counter['count']} packets so far…")

def select_interface():
    """List available interfaces and let the user pick one."""
    interfaces = get_windows_if_list()
    logger.info("Available interfaces:")
    for i, iface in enumerate(interfaces, 1):
        name = iface["name"] if isinstance(iface, dict) else iface
        desc = iface.get("description", "") if isinstance(iface, dict) else ""
        logger.info(f"  {i}) {name} - {desc}")
    sel = input("Select interface by number or name (blank for default): ").strip()

    if not sel:
        return None
    if sel.isdigit():
        idx = int(sel)
        if 1 <= idx <= len(interfaces):
            choice = interfaces[idx - 1]
            return choice["name"] if isinstance(choice, dict) else choice
        else:
            logger.error(f"Invalid selection {sel}; exiting.")
            sys.exit(1)
    return sel 

def main():
    # 1) Load GeoLite2 Database
    GEO_DB = input("Enter path to GeoLite2-City.mmdb: ").strip() or "GeoLite2-City.mmdb"

    # 2) load blacklist
    blacklist_path = input("Enter path to blacklist file: ").strip() or "blacklist.txt"
    raw = load_blacklist_entries(blacklist_path)
    blacklist_ips = build_blacklist(raw)
    logger.info(f"Using {len(blacklist_ips)} blacklisted IP(s)")

    # 3) Menu
    while True:
        print("\nMenu:\n  1) Analyze from PCAP file\n  2) Analyze live traffic\n  q) Quit\n")
        choice = input("Select [1, 2, or q]: ").strip().lower()

        if choice == "q":
            logger.info("Shutting Down!")
            break
        
        elif choice == "1":
            pcap_path = input("PCAP/PCAPNG file path: ").strip() or "sample.pcap"
            thresh = int(input("Port-scan threshold (e.g. 100): ").strip() or "100")
            packets = rdpcap(pcap_path)
            analyze_packets(packets, blacklist_ips, thresh, GEO_DB)

        elif choice == "2":
            iface = select_interface()
            logger.info(f"Starting live capture on {iface or 'default interface'}…")
            thresh = int(input("Port-scan threshold (e.g. 100): ").strip() or "100")
            logger.info("Sniffing for 300 seconds! Press Ctrl+C to stop capture and analyze traffic.")
            try:
                packets = sniff(iface=iface, filter="ip", timeout=300, prn=handle_live_packet)
            except KeyboardInterrupt:
                logger.info("Live capture stopped by user")
            except Exception as e:
                logger.error(f"Sniff failed on '{iface}': {e}")
                continue
            analyze_packets(packets, blacklist_ips, thresh, GEO_DB)

        else:
            logger.error("Invalid choice; please enter 1, 2, or q.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("User aborted, exiting.")
        sys.exit(0)
    except Exception:
        logger.exception("Fatal error in main")
        sys.exit(1)
