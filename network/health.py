"""
Network Health module.
Provides non-destructive operational readiness checks for the Network Engine.
"""

from typing import Dict, Any, List

def check_network_module_imports() -> bool:
    """Verifies that core network modules are importable."""
    try:
        import network.metadata
        import network.parser
        import network.synthetic
        import network.flow
        import network.features
        import network.constants
        return True
    except ImportError:
        return False

def check_scapy_availability() -> bool:
    """Verifies if Scapy is installed and available."""
    try:
        from network.adapters.scapy_adapter import is_scapy_available
        return is_scapy_available()
    except ImportError:
        return False

def check_capture_backend_readiness() -> bool:
    """
    Checks if the capture backend functions are accessible.
    Does NOT execute a live sniff or require Administrator privileges.
    """
    try:
        from network.adapters.scapy_adapter import capture_packets
        # If the function exists and Scapy is available, the backend is 'ready' for attempts.
        # We don't guarantee Npcap presence here as that requires live sniffing to test definitively on Windows.
        return check_scapy_availability()
    except ImportError:
        return False

def check_parser_readiness() -> bool:
    """Verifies the parser can process a basic synthetic packet."""
    try:
        from network.parser import parse_packet
        from network.synthetic import create_tcp_packet
        packet_dict = create_tcp_packet(source_ip="10.0.0.1")
        meta = parse_packet(packet_dict)
        return meta is not None and meta.source_ip == "10.0.0.1"
    except Exception:
        return False

def check_flow_engine_readiness() -> bool:
    """Verifies the flow aggregator can group packets."""
    try:
        from network.flow import FlowAggregator
        from network.parser import parse_packet
        from network.synthetic import create_tcp_packet
        
        agg = FlowAggregator()
        pkt1 = parse_packet(create_tcp_packet())
        pkt2 = parse_packet(create_tcp_packet())
        agg.add_packet(pkt1)
        agg.add_packet(pkt2)
        
        flows = agg.get_all_flows()
        return len(flows) > 0 and flows[0].packet_count == 2
    except Exception:
        return False

def check_feature_extractor_readiness() -> bool:
    """Verifies feature extraction translates metadata to numerical structures."""
    try:
        from network.features import extract_packet_features
        from network.parser import parse_packet
        from network.synthetic import create_tcp_packet
        
        pkt = parse_packet(create_tcp_packet())
        features = extract_packet_features(pkt)
        return isinstance(features, dict) and "protocol_enc" in features
    except Exception:
        return False

def run_core_pipeline_self_test() -> Dict[str, Any]:
    """
    Performs a full, completely in-memory self-test of the pipeline:
    Synthetic Metadata -> Parser -> PacketMetadata -> FlowAggregator -> Feature Extraction.
    Uses safe documentation IPs and never retains payloads.
    """
    status = {
        "success": False,
        "error": None
    }
    try:
        from network.synthetic import create_tcp_packet
        from network.parser import parse_packet
        from network.flow import FlowAggregator
        from network.features import extract_packet_features, extract_flow_features
        
        # 1. Create one safe synthetic packet
        raw_dict = create_tcp_packet(
            source_ip="192.168.0.100", 
            destination_ip="10.0.0.50",
            source_port=12345,
            destination_port=80,
            packet_size=120
        )
        
        # 2. Parse it into PacketMetadata
        packet_meta = parse_packet(raw_dict)
        if not packet_meta:
            raise ValueError("Parser failed to return metadata.")
            
        # 3. Add to temporary FlowAggregator
        agg = FlowAggregator()
        flow_meta = agg.add_packet(packet_meta)
        
        # 4. Extract features
        pkt_features = extract_packet_features(packet_meta)
        flow_features = extract_flow_features(flow_meta)
        
        # 5. Verify structure validity
        if "payload" in raw_dict or "payload" in pkt_features:
            raise ValueError("Payload leakage detected in pipeline.")
            
        if not pkt_features or not flow_features:
            raise ValueError("Feature extraction failed.")
            
        status["success"] = True
    except Exception as e:
        status["error"] = str(e)
        
    return status

def get_network_status_report() -> Dict[str, Any]:
    """
    Generates a full health report for the Network Engine.
    Status can be 'success', 'warning', or 'failed'.
    """
    report = {
        "status": "failed",
        "modules_importable": check_network_module_imports(),
        "scapy_available": check_scapy_availability(),
        "capture_backend_ready": check_capture_backend_readiness(),
        "parser_ready": check_parser_readiness(),
        "flow_engine_ready": check_flow_engine_readiness(),
        "feature_extractor_ready": check_feature_extractor_readiness(),
        "pipeline_self_test": run_core_pipeline_self_test()
    }
    
    # Determine overall status
    core_ready = (
        report["modules_importable"] and 
        report["parser_ready"] and 
        report["flow_engine_ready"] and 
        report["feature_extractor_ready"] and
        report["pipeline_self_test"]["success"]
    )
    
    if not core_ready:
        report["status"] = "failed"
    elif not report["scapy_available"] or not report["capture_backend_ready"]:
        report["status"] = "warning"
        report["warning_message"] = "Live capture prerequisites unavailable. Synthetic/offline processing only."
    else:
        report["status"] = "success"
        
    return report
