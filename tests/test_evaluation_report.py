import pytest
from backend.services.simulation_evaluation_report_service import SimulationEvaluationReportService
from backend.schemas.monitoring import SimulationHistoryRecord
from backend.services.monitoring_service import MonitoringStateService
from utils.time_utils import get_current_utc_time
import csv
import io
import json

@pytest.fixture
def monitoring_service():
    return MonitoringStateService(simulation_history_limit=10)

@pytest.fixture
def report_service(monitoring_service):
    return SimulationEvaluationReportService(monitoring_state_service=monitoring_service)

def test_csv_neutralization(report_service):
    assert report_service._neutralize_csv_value("=1+1") == "'=1+1"
    assert report_service._neutralize_csv_value("+SUM(A1:A2)") == "'+SUM(A1:A2)"
    assert report_service._neutralize_csv_value("-malware") == "'-malware"
    assert report_service._neutralize_csv_value("@command") == "'@command"
    assert report_service._neutralize_csv_value("\ttext") == "'\ttext"
    assert report_service._neutralize_csv_value("\rtext") == "'\rtext"
    
    # Numeric values should stay numeric/unquoted where possible
    assert report_service._neutralize_csv_value(5) == "5"
    assert report_service._neutralize_csv_value(3.14) == "3.14"
    assert report_service._neutralize_csv_value("-10.5") == "-10.5" # legitimate numeric negative

def test_empty_history_metrics(report_service):
    metrics = report_service.get_summary_metrics([])
    assert metrics["total_retained_cycles"] == 0
    assert metrics["successful_inference_cycles"] == 0
    assert metrics["recommendation_rate"] == 0.0
    assert metrics["average_cycle_duration_ms"] == 0.0
    assert metrics["oldest_retained_at"] is None

def test_summary_metrics(report_service):
    t = get_current_utc_time().isoformat()
    history = [
        SimulationHistoryRecord(
            cycle_id="1", state="simulation_complete", source_category="simulated",
            started_at=t, completed_at=t, duration_ms=10.0,
            inference_status="success", predicted_canonical_label="benign",
            policy_status="success", alert_recommended=False
        ),
        SimulationHistoryRecord(
            cycle_id="2", state="simulation_complete", source_category="simulated",
            started_at=t, completed_at=t, duration_ms=20.0,
            inference_status="success", predicted_canonical_label="malware",
            policy_status="success", alert_recommended=True, proposed_severity="high"
        ),
        SimulationHistoryRecord(
            cycle_id="3", state="error", source_category="simulated",
            started_at=t, completed_at=t, duration_ms=30.0,
            inference_status="error", policy_status="unavailable", alert_recommended=False
        )
    ]
    
    metrics = report_service.get_summary_metrics(history)
    assert metrics["total_retained_cycles"] == 3
    assert metrics["successful_inference_cycles"] == 2
    assert metrics["failed_inference_cycles"] == 1
    assert metrics["successful_policy_evaluations"] == 2
    assert metrics["failed_policy_evaluations"] == 0
    assert metrics["recommendation_count"] == 1
    assert metrics["recommendation_rate"] == 0.5 # 1/2 successful policies
    assert metrics["average_cycle_duration_ms"] == 20.0
    assert metrics["predicted_label_counts"]["benign"] == 1
    assert metrics["predicted_label_counts"]["malware"] == 1
    assert metrics["proposed_severity_counts"]["high"] == 1

def test_json_export(report_service, monitoring_service):
    t = get_current_utc_time().isoformat()
    record = SimulationHistoryRecord(
        cycle_id="1", state="simulation_complete", source_category="simulated",
        started_at=t, completed_at=t, duration_ms=10.0
    )
    monitoring_service._history.append(record)
    
    report = report_service.generate_json_report()
    assert report["report_schema_version"] == "simulation-report-v1"
    assert report["retained_record_count"] == 1
    assert len(report["cycles"]) == 1
    assert report["cycles"][0]["cycle_id"] == "1"
    assert report["summary_metrics"]["total_retained_cycles"] == 1

def test_csv_export(report_service, monitoring_service):
    t = get_current_utc_time().isoformat()
    record = SimulationHistoryRecord(
        cycle_id="1", state="simulation_complete", source_category="simulated",
        started_at=t, completed_at=t, duration_ms=10.0,
        predicted_canonical_label="-malware"
    )
    monitoring_service._history.append(record)
    
    csv_str = report_service.generate_csv_report()
    reader = csv.reader(io.StringIO(csv_str))
    rows = list(reader)
    
    assert len(rows) == 2 # Header + 1 row
    assert rows[0][0] == "Cycle ID"
    assert rows[1][0] == "1"
    
    # Check neutralized value (-malware -> '-malware)
    assert rows[1][7] == "'-malware"
