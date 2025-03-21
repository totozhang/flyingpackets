import subprocess
import logger
import scapy.layers.l2
import scapy.sendrecv
import config


def get_mac(ip):
    """Get the MAC address corresponding to the given IP."""
    try:
        ans = scapy.layers.l2.srp(
            scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.layers.l2.ARP(pdst=ip),
            iface=config.INTERFACE,
            timeout=2,
            verbose=False
        )[0]
        return ans[0][1].hwsrc if ans else None
    except Exception as e:
        logger.logging.error(f"Failed to get MAC address for {ip}: {e}")
        return None


def enable_ip_forward():
    """Enable IP forwarding on macOS."""
    try:
        subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=1"], check=True)
        logger.logging.info("IP forwarding enabled")
    except subprocess.CalledProcessError as e:
        logger.logging.error(f"Failed to enable IP forwarding: {e}")
        raise


def disable_ip_forward():
    """Disable IP forwarding on macOS."""
    try:
        subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=0"], check=True)
        logger.logging.info("IP forwarding disabled")
    except subprocess.CalledProcessError as e:
        logger.logging.error(f"Failed to disable IP forwarding: {e}")
        raise


def restore_arp(target_ip, gateway_ip, interface):
    """Restore the ARP tables."""
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if target_mac and gateway_mac:
        logger.logging.info("Restoring ARP tables...")
        # Restore target host's ARP table
        scapy.sendrecv.send(
            scapy.layers.l2.ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=gateway_ip,
                hwsrc=gateway_mac
            ),
            count=5,
            iface=interface,
            verbose=False
        )
        # Restore gateway's ARP table
        scapy.sendrecv.send(
            scapy.layers.l2.ARP(
                op=2,
                pdst=gateway_ip,
                hwdst=gateway_mac,
                psrc=target_ip,
                hwsrc=target_mac
            ),
            count=5,
            iface=interface,
            verbose=False
        )
    else:
        logger.logging.warning("Failed to restore ARP tables: MAC addresses not found")
