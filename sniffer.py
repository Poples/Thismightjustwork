#!/usr/bin/env python3
"""
Packet Sniffer Core - Stage 1
Captures network packets using scapy and processes them with multiprocessing.
"""

import logging
import argparse
import signal
import sys
import time
from multiprocessing import Process, Queue
from scapy.all import sniff, get_if_list

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class PacketSniffer:
    def __init__(self, interface=None, packet_count=0):
        """
        Initialize the packet sniffer.
        
        Args:
            interface: Network interface to sniff on (None for all)
            packet_count: Number of packets to capture (0 for infinite)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packet_queue = Queue()
        self.running = True
        
    def packet_handler(self, pkt):
        """
        Handle captured packets and add them to the queue.
        
        Args:
            pkt: Captured packet from scapy
        """
        try:
            packet_info = {
                'timestamp': time.time(),
                'summary': pkt.summary(),
                'src': pkt.src if hasattr(pkt, 'src') else 'Unknown',
                'dst': pkt.dst if hasattr(pkt, 'dst') else 'Unknown',
                'protocol': pkt.name if hasattr(pkt, 'name') else 'Unknown',
                'length': len(pkt)
            }
            self.packet_queue.put(packet_info)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def sniff_packets(self):
        """
        Start packet sniffing using scapy.
        """
        try:
            logger.info(f"Starting packet capture on interface: {self.interface or 'ALL'}")
            logger.info(f"Packet count limit: {'Unlimited' if self.packet_count == 0 else self.packet_count}")
            
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,
                count=self.packet_count if self.packet_count > 0 else 0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            logger.info("Packet capture stopped")

    def process_packets(self):
        """
        Process packets from the queue and log them.
        """
        packet_counter = 0
        try:
            while self.running or not self.packet_queue.empty():
                try:
                    # Get packet from queue with timeout
                    packet_info = self.packet_queue.get(timeout=1)
                    packet_counter += 1
                    
                    # Log packet information
                    logger.info(f"Packet #{packet_counter}:")
                    logger.info(f"  Time: {time.strftime('%H:%M:%S', time.localtime(packet_info['timestamp']))}")
                    logger.info(f"  Summary: {packet_info['summary']}")
                    logger.info(f"  Source: {packet_info['src']}")
                    logger.info(f"  Destination: {packet_info['dst']}")
                    logger.info(f"  Protocol: {packet_info['protocol']}")
                    logger.info(f"  Length: {packet_info['length']} bytes")
                    logger.info("-" * 50)
                    
                except:
                    # Timeout occurred, continue if still running
                    if self.running:
                        continue
                    else:
                        break
                        
        except KeyboardInterrupt:
            logger.info("Packet processing interrupted")
        finally:
            logger.info(f"Total packets processed: {packet_counter}")

    def signal_handler(self, signum, frame):
        """
        Handle interrupt signals gracefully.
        """
        logger.info("Interrupt received, stopping packet capture...")
        self.running = False

    def start(self):
        """
        Start the packet sniffer with multiprocessing.
        """
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Start packet processing in a separate process
            processor = Process(target=self.process_packets)
            processor.start()
            
            # Start packet sniffing in main process
            self.sniff_packets()
            
            # Stop processing and wait for completion
            self.running = False
            processor.join(timeout=5)
            
            if processor.is_alive():
                logger.warning("Forcefully terminating packet processor")
                processor.terminate()
                processor.join()
                
        except Exception as e:
            logger.error(f"Error in packet sniffer: {e}")
        finally:
            logger.info("Packet sniffer shutdown complete")

def list_interfaces():
    """
    List available network interfaces.
    """
    try:
        interfaces = get_if_list()
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        return interfaces
    except Exception as e:
        print(f"Error listing interfaces: {e}")
        return []

def main():
    """
    Main function with CLI argument parsing.
    """
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer - Stage 1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer.py                          # Sniff on all interfaces
  python sniffer.py -i eth0                  # Sniff on specific interface
  python sniffer.py -c 100                   # Capture 100 packets
  python sniffer.py -i eth0 -c 50            # Capture 50 packets on eth0
  python sniffer.py --list-interfaces        # List available interfaces
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        type=str,
        help='Network interface to sniff on (default: all interfaces)'
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of packets to capture (0 for unlimited, default: 0)'
    )
    
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set log level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # List interfaces if requested
    if args.list_interfaces:
        list_interfaces()
        return
    
    # Validate packet count
    if args.count < 0:
        logger.error("Packet count must be non-negative")
        sys.exit(1)
    
    # Check if running as administrator (required for packet capture on Windows)
    try:
        import ctypes
        if sys.platform == "win32":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.warning("Administrator privileges may be required for packet capture on Windows")
    except:
        pass
    
    # Create and start packet sniffer
    logger.info("Initializing packet sniffer...")
    sniffer = PacketSniffer(interface=args.interface, packet_count=args.count)
    
    try:
        sniffer.start()
    except KeyboardInterrupt:
        logger.info("Packet sniffer interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
