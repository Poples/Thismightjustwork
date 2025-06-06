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
import os
from multiprocessing import Process, Queue, Pool, cpu_count
from queue import Full, Empty
from collections import defaultdict, deque
from datetime import datetime
import threading
from scapy.all import sniff, get_if_list
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.dates import DateFormatter
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def process_single_packet(packet_info):
    """
    Process a single packet. This function is used by the multiprocessing Pool.
    
    Args:
        packet_info: Dictionary containing packet information
        
    Returns:
        dict: Processed packet data with metrics and formatted string
    """
    try:
        # Extract metrics from packet
        metrics = {
            'timestamp': packet_info['timestamp'],
            'protocol': packet_info['protocol'],
            'length': packet_info['length'],
            'src': packet_info['src'],
            'dst': packet_info['dst']
        }
        
        # Create formatted string for logging
        result = []
        result.append(f"Time: {time.strftime('%H:%M:%S', time.localtime(packet_info['timestamp']))}")
        result.append(f"Summary: {packet_info['summary']}")
        result.append(f"Source: {packet_info['src']}")
        result.append(f"Destination: {packet_info['dst']}")        
        result.append(f"Protocol: {packet_info['protocol']}")
        result.append(f"Length: {packet_info['length']} bytes")
        
        return {
            'metrics': metrics,
            'formatted_string': "\n".join(result)
        }
    except Exception as e:
        return {
            'metrics': None,
            'formatted_string': f"Error processing packet: {e}"
        }

class PacketMetricsVisualizer:
    """
    Real-time packet metrics visualization using matplotlib.
    """
    def __init__(self, results_queue):
        self.results_queue = results_queue
        self.running = True
        
        # Data storage for metrics
        self.packet_count = 0
        self.protocol_counts = defaultdict(int)
        self.packet_sizes = deque(maxlen=100)  # Last 100 packet sizes
        self.timestamps = deque(maxlen=100)    # Last 100 timestamps
        self.packets_per_second = deque(maxlen=60)  # Last 60 seconds
        
        # Time tracking for packets per second
        self.last_second = int(time.time())
        self.current_second_count = 0
        
        # Setup matplotlib
        plt.style.use('dark_background')
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.suptitle('Real-time Packet Analysis', fontsize=16, color='white')
        
        # Initialize plots
        self.init_plots()
        
    def init_plots(self):
        """Initialize the matplotlib plots."""
        # Plot 1: Total packet count over time
        self.ax1.set_title('Total Packet Count', color='white')
        self.ax1.set_xlabel('Time (seconds ago)', color='white')
        self.ax1.set_ylabel('Cumulative Packets', color='white')
        self.line1, = self.ax1.plot([], [], 'cyan', linewidth=2)
        
        # Plot 2: Protocol distribution (pie chart)
        self.ax2.set_title('Protocol Distribution', color='white')
        
        # Plot 3: Packet size distribution
        self.ax3.set_title('Packet Size Distribution (Last 100)', color='white')
        self.ax3.set_xlabel('Packet Size (bytes)', color='white')
        self.ax3.set_ylabel('Frequency', color='white')
        
        # Plot 4: Packets per second
        self.ax4.set_title('Packets per Second', color='white')
        self.ax4.set_xlabel('Time (seconds ago)', color='white')
        self.ax4.set_ylabel('Packets/sec', color='white')
        self.line4, = self.ax4.plot([], [], 'lime', linewidth=2)
        
        plt.tight_layout()
        
    def process_metrics_data(self):
        """Process incoming metrics data from the queue."""
        try:
            while self.running:
                try:
                    # Get results from queue with timeout
                    results = self.results_queue.get(timeout=1)
                    
                    if results is None:  # Shutdown signal
                        break
                        
                    # Process each result in the batch
                    for result in results:
                        if result['metrics'] is not None:
                            self.update_metrics(result['metrics'])
                            
                except Empty:
                    continue
                except Exception as e:
                    logger.error(f"Error processing metrics data: {e}")
                    
        except KeyboardInterrupt:
            logger.info("Metrics processing interrupted")
        finally:
            logger.info("Metrics processor shutdown")
            
    def update_metrics(self, metrics):
        """Update metrics data with new packet information."""
        current_time = int(time.time())
        
        # Update packet count
        self.packet_count += 1
        
        # Update protocol counts
        self.protocol_counts[metrics['protocol']] += 1
        
        # Update packet sizes and timestamps
        self.packet_sizes.append(metrics['length'])
        self.timestamps.append(metrics['timestamp'])
        
        # Update packets per second tracking
        if current_time == self.last_second:
            self.current_second_count += 1
        else:
            # New second started
            self.packets_per_second.append(self.current_second_count)
            self.current_second_count = 1
            self.last_second = current_time
            
    def update_plots(self, frame):
        """Update all plots with current data."""
        try:
            # Clear all axes
            for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
                ax.clear()
                
            self.init_plots()
            
            if self.packet_count == 0:
                return
                
            # Plot 1: Total packet count over time
            if len(self.timestamps) > 1:
                current_time = time.time()
                time_offsets = [current_time - ts for ts in list(self.timestamps)]
                counts = list(range(self.packet_count - len(self.timestamps) + 1, self.packet_count + 1))
                
                self.ax1.plot(time_offsets[::-1], counts, 'cyan', linewidth=2)
                self.ax1.set_xlim(max(time_offsets) if time_offsets else 0, 0)
                
            # Plot 2: Protocol distribution
            if self.protocol_counts:
                protocols = list(self.protocol_counts.keys())
                counts = list(self.protocol_counts.values())
                colors = plt.cm.Set3(np.linspace(0, 1, len(protocols)))
                
                wedges, texts, autotexts = self.ax2.pie(counts, labels=protocols, autopct='%1.1f%%', 
                                                       colors=colors, textprops={'color': 'white'})
                
            # Plot 3: Packet size histogram
            if len(self.packet_sizes) > 0:
                self.ax3.hist(list(self.packet_sizes), bins=20, color='orange', alpha=0.7, edgecolor='white')
                
            # Plot 4: Packets per second
            if len(self.packets_per_second) > 1:
                time_range = list(range(len(self.packets_per_second)))
                self.ax4.plot(time_range, list(self.packets_per_second), 'lime', linewidth=2)
                self.ax4.set_xlim(0, max(time_range) if time_range else 1)
                
            # Update title with current stats
            self.fig.suptitle(f'Real-time Packet Analysis - Total: {self.packet_count} packets', 
                            fontsize=16, color='white')
                            
        except Exception as e:
            logger.error(f"Error updating plots: {e}")
            
    def start_visualization(self):
        """Start the visualization in a separate thread."""
        # Start the metrics processing in a thread
        metrics_thread = threading.Thread(target=self.process_metrics_data)
        metrics_thread.daemon = True
        metrics_thread.start()
        
        # Start the animation
        self.animation = animation.FuncAnimation(self.fig, self.update_plots, interval=1000, cache_frame_data=False)
        
        try:
            plt.show()
        except KeyboardInterrupt:
            logger.info("Visualization interrupted")
        finally:
            self.running = False

class PacketSniffer:
    def __init__(self, interface=None, packet_count=0, max_queue_size=1000, pool_size=2, enable_visualization=True):
        """
        Initialize the packet sniffer.
        
        Args:
            interface: Network interface to sniff on (None for all)
            packet_count: Number of packets to capture (0 for infinite)
            max_queue_size: Maximum size of packet queue (default: 1000)
            pool_size: Number of worker processes in pool (default: CPU count)
            enable_visualization: Whether to enable real-time visualization
        """      
        self.interface = interface
        self.packet_count = packet_count
        self.max_queue_size = max_queue_size
        self.pool_size = pool_size or cpu_count()
        self.enable_visualization = enable_visualization
        self.packet_queue = Queue(maxsize=max_queue_size)
        self.results_queue = Queue(maxsize=max_queue_size) if enable_visualization else None
        self.running = True
        self.pool = None
        self.dropped_packets = 0
        
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
            
            # Try to add packet to queue, drop if queue is full
            try:
                self.packet_queue.put(packet_info, block=False)
            except Full:
                self.dropped_packets += 1
                if self.dropped_packets % 100 == 0:  # Log every 100 dropped packets
                    logger.warning(f"Dropped {self.dropped_packets} packets due to full queue")
                    
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
        Process packets from the queue using a multiprocessing Pool.
        """
        packet_counter = 0
        batch_size = 5  # Process packets in batches for better efficiency
        packet_batch = []
        
        try:
            logger.info(f"Starting packet processor with {self.pool_size} workers")
            
            # Initialize the multiprocessing pool
            with Pool(processes=self.pool_size) as pool:
                self.pool = pool
                
                while self.running or not self.packet_queue.empty():
                    try:
                        # Get packet from queue with timeout
                        packet_info = self.packet_queue.get(timeout=1)
                        packet_batch.append(packet_info)                        
                        packet_counter += 1
                        
                        # Process batch when it reaches batch_size or queue is empty
                        if len(packet_batch) >= batch_size or (not self.running and self.packet_queue.empty()):
                            # Process packets in parallel
                            results = pool.map(process_single_packet, packet_batch)
                            
                            # Send results to visualization queue if enabled
                            if self.enable_visualization and self.results_queue:
                                try:
                                    self.results_queue.put(results, block=False)
                                except Full:
                                    logger.warning("Results queue full, dropping visualization data")
                            
                            # Log the results
                            for i, result in enumerate(results):
                                packet_num = packet_counter - len(packet_batch) + i + 1
                                logger.info(f"Packet #{packet_num}:")
                                for line in result['formatted_string'].split('\n'):
                                    logger.info(f"  {line}")
                                logger.info("-" * 50)
                            packet_batch = []  # Clear the batch
                            
                    except Empty:
                        # Process any remaining packets in the batch
                        if packet_batch:
                            results = pool.map(process_single_packet, packet_batch)
                            
                            # Send results to visualization queue if enabled
                            if self.enable_visualization and self.results_queue:
                                try:
                                    self.results_queue.put(results, block=False)
                                except Full:
                                    logger.warning("Results queue full, dropping visualization data")
                                    
                            for i, result in enumerate(results):
                                packet_num = packet_counter - len(packet_batch) + i + 1
                                logger.info(f"Packet #{packet_num}:")
                                for line in result['formatted_string'].split('\n'):
                                    logger.info(f"  {line}")
                                logger.info("-" * 50)
                            packet_batch = []
                        
                        # Timeout occurred, continue if still running
                        if self.running:
                            continue
                        else:
                            break
                            
        except KeyboardInterrupt:
            logger.info("Packet processing interrupted")        
        except Exception as e:
            logger.error(f"Error in packet processing: {e}")
        finally:
            self.pool = None
            if self.dropped_packets > 0:
                logger.warning(f"Total dropped packets due to full queue: {self.dropped_packets}")
            logger.info(f"Total packets processed: {packet_counter}")

    def signal_handler(self, signum, frame):
        """
        Handle interrupt signals gracefully.
        """
        logger.info("Interrupt received, stopping packet capture...")
        self.running = False

    def start(self):
        """
        Start the packet sniffer with multiprocessing and optional visualization.
        """
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            processes = []
            
            # Start visualization process if enabled
            if self.enable_visualization and self.results_queue:
                logger.info("Starting visualization process...")
                visualizer = PacketMetricsVisualizer(self.results_queue)
                viz_process = Process(target=visualizer.start_visualization)
                viz_process.start()
                processes.append(viz_process)
            
            # Start packet processing in a separate process
            processor = Process(target=self.process_packets)
            processor.start()
            processes.append(processor)
            
            # Start packet sniffing in main process
            self.sniff_packets()
            
            # Stop processing and wait for completion
            self.running = False
            
            # Send shutdown signal to visualization
            if self.enable_visualization and self.results_queue:
                try:
                    self.results_queue.put(None, timeout=1)  # Shutdown signal
                except Full:
                    pass
            
            # Wait for all processes to complete
            for process in processes:
                process.join(timeout=5)
                if process.is_alive():
                    logger.warning(f"Forcefully terminating process {process.name}")
                    process.terminate()
                    process.join()
                
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
        formatter_class=argparse.RawDescriptionHelpFormatter,        epilog="""
Examples:
  python sniffer.py                          # Sniff on all interfaces with visualization
  python sniffer.py -i eth0                  # Sniff on specific interface
  python sniffer.py -c 100                   # Capture 100 packets
  python sniffer.py -i eth0 -c 50            # Capture 50 packets on eth0
  python sniffer.py --queue-size 2000        # Set queue size to 2000
  python sniffer.py --pool-size 8            # Use 8 worker processes
  python sniffer.py --no-visualization       # Disable real-time visualization
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
    
    parser.add_argument(
        '--queue-size',
        type=int,
        default=1000,
        help='Maximum size of packet queue (default: 1000)'
    )
    
    parser.add_argument(
        '--pool-size',
        type=int,
        default=None,
        help='Number of worker processes in pool (default: CPU count)'
    )
    
    parser.add_argument(
        '--no-visualization',
        action='store_true',
        help='Disable real-time visualization'
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
    
    # Validate queue size
    if args.queue_size <= 0:
        logger.error("Queue size must be positive")
        sys.exit(1)
    
    # Validate pool size
    if args.pool_size is not None and args.pool_size <= 0:
        logger.error("Pool size must be positive")
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
    logger.info(f"Configuration: Queue size={args.queue_size}, Pool size={args.pool_size or cpu_count()}")
    logger.info(f"Visualization: {'Disabled' if args.no_visualization else 'Enabled'}")
    sniffer = PacketSniffer(
        interface=args.interface, 
        packet_count=args.count,
        max_queue_size=args.queue_size,
        pool_size=args.pool_size,
        enable_visualization=not args.no_visualization
    )
    
    try:
        sniffer.start()
    except KeyboardInterrupt:
        logger.info("Packet sniffer interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
