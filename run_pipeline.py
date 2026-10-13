import argparse
import json
from pathlib import Path

import pandas as pd

from src.data_engineering.process_logs import load_cloudtrail, normalize_events, build_activity_features
from src.security.detection_rules import detect_rule_findings
from src.ai_engineering.anomaly_detection import score_anomalies


def main():
    parser = argparse.ArgumentParser(description="Analyze CloudTrail-style JSON locally.")
    parser.add_argument("--input", required=True, help="Path to CloudTrail JSON file")
    parser.add_argument("--output-dir", default="outputs", help="Directory for output files")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    records = load_cloudtrail(args.input)
    events = normalize_events(records)
    features = build_activity_features(events)
    findings = detect_rule_findings(events)
    scored = score_anomalies(features)

    events.to_csv(output_dir / "normalized_events.csv", index=False)
    features.to_csv(output_dir / "activity_features.csv", index=False)
    scored.to_csv(output_dir / "anomaly_results.csv", index=False)
    with (output_dir / "rule_findings.json").open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"Input records: {len(records)}")
    print(f"Normalized events: {len(events)}")
    print(f"Activity feature rows: {len(features)}")
    print(f"Rule findings: {len(findings)}")
    print(f"Outputs written to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
