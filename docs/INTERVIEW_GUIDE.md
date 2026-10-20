# Interview Guide

1. **What is an NIDS?** A Network Intrusion Detection System monitors network traffic for suspicious activity and known threats. Code reference: `DetectionEngine`.
2. **Difference between IDS and IPS:** IDS only detects and alerts; IPS also prevents by blocking traffic.
3. **What is packet capture?** The process of intercepting and logging traffic passing over a network (e.g., using Scapy).
4. **What is Scapy?** A Python program/library that enables packet forging, sniffing, and parsing. Used in `PacketParser`.
5. **How are packets parsed?** `PacketParser` extracts IP, TCP, UDP, ICMP layers and maps them to `NetworkEvent` objects.
6. **What is feature extraction?** Getting relevant attributes (IPs, ports, flags) from raw packets.
7. **How is port scanning detected?** Using a time window to count distinct destination ports accessed by a source IP in `PortScanRule`.
8. **How are repeated connection attempts detected?** Counting connections to the same (IP, Port) within a time window in `RepeatedConnectionRule`.
9. **What is a detection threshold?** The limit above which an alert is generated (e.g., >10 ports).
10. **What is a time window?** The timeframe in which events are correlated (e.g., 10 seconds).
11. **How are alerts generated?** `DetectionEngine` returns `Alert` objects passed to `AlertManager`.
12. **Why SQLite?** It's lightweight, requires no setup, and is suitable for a prototype NIDS. Used in `DatabaseRepository`.
13. **Why FastAPI?** High performance, easy to build APIs, automatic OpenAPI docs.
14. **Why Streamlit?** Quick dashboard creation using pure Python.
15. **Why Matplotlib?** For creating traffic visualizations in the dashboard.
16. **How does Demo Mode work?** `generate_demo_traffic.py` creates synthetic `NetworkEvent`s to simulate attacks for demonstration.
17. **How are false positives handled?** Threshold tuning and alert deduplication in `AlertManager`.
18. **What are the limitations?** Scapy is slow for high-throughput networks; SQLite is not for concurrent heavy loads.
19. **How could machine learning be added?** By training anomaly detection models on the `network_events` data.
20. **How could this become a larger enterprise IDS?** Using DPDK/eBPF for capture, Kafka for ingestion, Elasticsearch for storage, and a distributed engine like Suricata.
