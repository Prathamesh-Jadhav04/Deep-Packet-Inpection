import sys
import os
import time
import joblib
import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from dpi_engine.pipeline import DPIEngine
from dpi_engine.classifiers import ETIClassifier, ETIFeatureExtractor
from dpi_engine.common import FiveTuple

def measure_eti_inference():
    print("Measuring ETI Classifier Inference Latency...")
    classifier = ETIClassifier()
    extractor = ETIFeatureExtractor(FiveTuple("192.168.1.100", "8.8.8.8", 12345, 443, 6))
    
    # Add fake packet sizes and times to extract features
    for i in range(100):
        # Create a mock packet
        from dpi_engine.common import Packet
        mock_packet = Packet(
            id=i,
            ts_sec=1700000000 + i,
            ts_usec=0,
            tuple=extractor.tuple,
            data=b"\x00" * 500,
            tcp_flags=0x10,
            payload_offset=14 + 20 + 20,
            payload_length=500 - (14 + 20 + 20)
        )
        extractor.add_packet(mock_packet)
        
    # Measure inference time
    start_time = time.perf_counter()
    iterations = 1000
    for _ in range(iterations):
        classifier.classify(extractor, 4) # AppType.TLS is 4
    end_time = time.perf_counter()
    
    avg_latency_ms = ((end_time - start_time) / iterations) * 1000.0
    print(f"ETI Inference Avg Latency: {avg_latency_ms:.4f} ms")
    return avg_latency_ms

def measure_throughput():
    pcap_file = "live_output.pcap"
    if not os.path.exists(pcap_file):
        # Try test_dpi.pcap if live_output is missing
        pcap_file = "test_dpi.pcap"
        if not os.path.exists(pcap_file):
            print("Error: No PCAP file found to benchmark. Generating one...")
            from dpi_engine.pipeline import generate_test_pcap
            generate_test_pcap("test_dpi.pcap")
            pcap_file = "test_dpi.pcap"
            
    print(f"Measuring Throughput with PCAP: {pcap_file}...")
    
    # We will process the PCAP multiple times in memory or do standard processing to get high-fidelity throughput metrics
    engine = DPIEngine(DPIEngine.Config(num_lbs=2, fps_per_lb=2))
    
    start_time = time.perf_counter()
    # We run it offline
    ok = engine.process(pcap_file, "benchmark_output.pcap")
    end_time = time.perf_counter()
    
    elapsed = end_time - start_time
    total_packets = engine.stats.total_packets
    
    # Clean up output
    if os.path.exists("benchmark_output.pcap"):
        os.remove("benchmark_output.pcap")
        
    if not ok or total_packets == 0:
        print("Replay processing failed during benchmark.")
        return 0, 0
        
    pps = total_packets / elapsed
    print(f"Processed {total_packets} packets in {elapsed:.4f} seconds.")
    print(f"Throughput: {pps:.2f} pps")
    return pps, total_packets

def main():
    print("=== DPI ENGINE REAL PERFORMANCE BENCHMARK ===")
    avg_latency = measure_eti_inference()
    pps, total_pkts = measure_throughput()
    
    # Write results to a temp JSON file for verification
    import json
    results = {
        "eti_inference_ms": round(avg_latency, 3),
        "throughput_pps": round(pps, 1),
        "total_packets": total_pkts
    }
    with open("scratch/benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("\nResults successfully saved to scratch/benchmark_results.json")

if __name__ == "__main__":
    main()
