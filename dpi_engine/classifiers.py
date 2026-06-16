from __future__ import annotations

import os
import math
from typing import Dict, List, Optional, Tuple, Any

from dpi_engine.common import FiveTuple, AppType, Packet


class ETIFeatureExtractor:
    def __init__(self, tuple_: FiveTuple) -> None:
        self.tuple = tuple_
        self.payload_sizes = []
        self.packet_times = []
        self.directions = []  # True for upload, False for download
        self.burst_count = 0
        self.burst_sizes = []
        self.last_direction = None
        self.current_burst_size = 0
        self.tls_record_lengths = []
        self.tls_record_count = 0

    def add_packet(self, packet: Packet) -> None:
        is_upload = (packet.tuple.src_ip == self.tuple.src_ip and 
                     packet.tuple.src_port == self.tuple.src_port)
        ts = packet.ts_sec + packet.ts_usec / 1000000.0
        self.packet_times.append(ts)
        self.payload_sizes.append(packet.payload_length)
        self.directions.append(is_upload)

        if self.last_direction is None:
            self.last_direction = is_upload
            self.current_burst_size = packet.payload_length
        elif self.last_direction == is_upload:
            self.current_burst_size += packet.payload_length
        else:
            if self.current_burst_size > 0:
                self.burst_sizes.append(self.current_burst_size)
                self.burst_count += 1
            self.last_direction = is_upload
            self.current_burst_size = packet.payload_length

        if packet.tuple.protocol == 6 and (packet.tuple.src_port == 443 or packet.tuple.dst_port == 443):
            if packet.payload_length > 0:
                payload = packet.data[packet.payload_offset : packet.payload_offset + packet.payload_length]
                self._extract_tls_records(payload)

    def _extract_tls_records(self, payload: bytes) -> None:
        offset = 0
        while offset + 5 <= len(payload):
            content_type = payload[offset]
            if content_type in (20, 21, 22, 23):
                rec_len = (payload[offset + 3] << 8) | payload[offset + 4]
                if rec_len > 16384 + 256:
                    break
                self.tls_record_lengths.append(rec_len)
                self.tls_record_count += 1
                offset += 5 + rec_len
            else:
                break

    def get_features(self) -> List[float]:
        hist = [0] * 10
        for sz in self.payload_sizes:
            if sz <= 100: hist[0] += 1
            elif sz <= 200: hist[1] += 1
            elif sz <= 400: hist[2] += 1
            elif sz <= 600: hist[3] += 1
            elif sz <= 800: hist[4] += 1
            elif sz <= 1000: hist[5] += 1
            elif sz <= 1200: hist[6] += 1
            elif sz <= 1400: hist[7] += 1
            elif sz <= 1600: hist[8] += 1
            else: hist[9] += 1

        total_packets = len(self.payload_sizes) or 1
        hist_norm = [count / total_packets for count in hist]

        mean_sz = sum(self.payload_sizes) / total_packets if self.payload_sizes else 0.0
        var_sz = sum((sz - mean_sz) ** 2 for sz in self.payload_sizes) / total_packets if self.payload_sizes else 0.0

        iats = []
        for i in range(1, len(self.packet_times)):
            iats.append((self.packet_times[i] - self.packet_times[i - 1]) * 1000.0)

        mean_iat = sum(iats) / len(iats) if iats else 0.0
        var_iat = sum((iat - mean_iat) ** 2 for iat in iats) / len(iats) if iats else 0.0

        std_iat = math.sqrt(var_iat)
        cv_iat = std_iat / mean_iat if mean_iat > 0 else 0.0

        bursts = list(self.burst_sizes)
        if self.current_burst_size > 0:
            bursts.append(self.current_burst_size)

        burst_count = len(bursts)
        avg_burst_sz = sum(bursts) / burst_count if burst_count > 0 else 0.0

        return hist_norm + [mean_sz, var_sz, mean_iat, var_iat, cv_iat, float(burst_count), avg_burst_sz]


class ETIClassifier:
    def __init__(self) -> None:
        self.model = None
        self.onnx_session = None
        self.model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "eti_rf_model.pkl"))
        self.onnx_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "eti_model.onnx"))
        
        # Try loading ONNX model first
        try:
            import onnxruntime
            if os.path.exists(self.onnx_path):
                # Suppress verbose warnings
                opts = onnxruntime.SessionOptions()
                opts.log_severity_level = 3
                self.onnx_session = onnxruntime.InferenceSession(self.onnx_path, sess_options=opts)
                print(f"[ETIClassifier] Loaded ONNX model from {self.onnx_path}")
            else:
                print(f"[ETIClassifier] ONNX model file not found at {self.onnx_path}")
        except Exception as exc:
            pass

        # Try loading standard RandomForest model
        try:
            import joblib
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                print(f"[ETIClassifier] Loaded RandomForest from {self.model_path}")
            else:
                print(f"[ETIClassifier] Model file not found at {self.model_path}. Using heuristics.")
        except Exception as exc:
            print(f"[ETIClassifier] Loading error: {exc}. Using heuristics.")

    def classify(self, extractor: ETIFeatureExtractor, app_type: AppType) -> Tuple[str, float]:
        features = extractor.get_features()
        
        # 1. ONNX Runtime Inference
        if self.onnx_session is not None:
            try:
                import numpy as np
                x_input = np.array([features], dtype=np.float32)
                input_name = self.onnx_session.get_inputs()[0].name
                outputs = self.onnx_session.run(None, {input_name: x_input})
                if outputs and len(outputs) >= 2:
                    pred_label = str(outputs[0][0])
                    prob_dict = outputs[1][0]
                    prob = float(prob_dict.get(pred_label, 1.0))
                    return pred_label, prob
            except Exception:
                pass

        # 2. Fallback: Joblib RandomForest Inference
        if self.model is not None:
            try:
                import numpy as np
                probs = self.model.predict_proba([features])[0]
                classes = self.model.classes_
                pred_idx = np.argmax(probs)
                return classes[pred_idx], float(probs[pred_idx])
            except Exception:
                pass

        total_packets = len(extractor.payload_sizes)
        if total_packets < 5:
            return "BENIGN", 1.0

        cv_iat = features[14]
        mean_sz = features[10]
        var_sz = features[11]

        client_bytes = 0
        server_bytes = 0
        for sz, is_up in zip(extractor.payload_sizes, extractor.directions):
            if is_up:
                client_bytes += sz
            else:
                server_bytes += sz
        byte_ratio = client_bytes / (client_bytes + server_bytes + 1)

        if cv_iat < 0.15 and total_packets >= 10:
            return "SUSPICIOUS", 0.85

        if byte_ratio > 0.85 and client_bytes > 5000000:
            return "SUSPICIOUS", 0.80

        if app_type == AppType.DNS and mean_sz < 80 and var_sz < 20 and total_packets >= 10:
            return "MALICIOUS", 0.90

        return "BENIGN", 1.0


eti_classifier = ETIClassifier()
