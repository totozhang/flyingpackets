# -*- coding: utf-8 -*-

import logger
import scapy.all
import config


def packet_handler(pkt):
    """Handle and save packets to the pcap file."""
    scapy.all.wrpcap(config.PCAP_FILE, pkt, append=True)


def start_sniffer(interface, target_ip, gateway_ip):
    """Start packet sniffing."""
    logger.logging.info(f"Starting packet sniffing and saving to {config.PCAP_FILE}")
    try:
        scapy.all.sniff(
            iface=interface,
            filter=f"host {target_ip} or host {gateway_ip}",  # Only capture target traffic
            prn=packet_handler,
            store=0
        )
    except KeyboardInterrupt:
        logger.logging.info("Packet sniffing stopped")