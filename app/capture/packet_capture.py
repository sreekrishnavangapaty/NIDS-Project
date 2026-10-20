import threading
import logging
import time

logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self, interface: str, count: int, duration: int, callback):
        self.interface = interface
        self.count = count
        self.duration = duration
        self.callback = callback
        self._is_running = False
        self.packets_captured = 0
        self._thread = None
        self._stop_event = threading.Event()

    def _capture_loop(self):
        try:
            from scapy.all import sniff
            
            logger.info(f"Starting packet capture on {self.interface}")
            
            def stop_filter(packet):
                return self._stop_event.is_set()

            def process_packet(packet):
                self.packets_captured += 1
                self.callback(packet)

            sniff(
                iface=self.interface,
                prn=process_packet,
                count=self.count,
                timeout=self.duration,
                stop_filter=stop_filter,
                store=False
            )
        except ImportError:
            logger.error("Scapy is not installed. Packet capture disabled.")
        except PermissionError:
            logger.error("Permission denied. Run with sufficient privileges (e.g., Administrator/root).")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            self._is_running = False
            logger.info(f"Packet capture stopped. Captured {self.packets_captured} packets.")

    def start(self):
        if self._is_running:
            return
        
        self._is_running = True
        self._stop_event.clear()
        self.packets_captured = 0
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        if self._is_running:
            self._stop_event.set()
            if self._thread:
                self._thread.join(timeout=2.0)
            self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running
