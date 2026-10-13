# Implementation and evidence checklist

## Local prototype evidence
- [ ] Run the pipeline successfully.
- [ ] Run the unit tests successfully.
- [ ] Review normalized_events.csv.
- [ ] Review activity_features.csv.
- [ ] Review rule_findings.json.
- [ ] Review anomaly_results.csv.
- [ ] Record Python version and package versions.

## AWS deployment evidence (not performed by the local prototype)
- [ ] Account secured with MFA and billing alert/budget.
- [ ] CloudTrail trail configured and delivering logs to a private S3 bucket.
- [ ] S3 encryption and Block Public Access verified.
- [ ] GuardDuty enabled after pricing review.
- [ ] EventBridge rule and Lambda target tested with a supported sample event.
- [ ] SNS email subscription confirmed and test message received.
- [ ] IAM permissions reviewed for least privilege.
- [ ] Actual screenshots captured and sensitive identifiers redacted.

## Limitations
- The sample data is synthetic.
- The example repeated-login rule counts failures in the supplied input file; it is not a streaming, per-IP sliding-window detector.
- The demonstration Isolation Forest is fitted to the available feature rows. For meaningful evaluation, train on a baseline dataset and score a separate test set.
- A model anomaly is not proof of malicious activity.
