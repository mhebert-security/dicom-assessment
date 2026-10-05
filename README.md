# dicom-assessment

Companion to "DICOM Is Unauthenticated and Full of PHI: A Practical Security Analysis"
From Bedside to Substation — Module 5, Article 11
https://mhebert.dev/ot-learning/module-5-medical-devices/

A structured security assessment of a default-configured Orthanc DICOM server in a
simulated clinical environment. Eight findings across critical, high, and medium
severity, each with the command used to reproduce it, the evidence the server
returned, and the exact configuration change that addresses it.

The target is fictional. "Lakeside General Hospital" does not exist. The assessment
address is a private RFC 1918 address. All patient data used during testing came from
publicly available de-identified DICOM datasets. Nothing here targets a real system,
and no real patient information was accessed or retained.

## Layout

```
report.md                the full assessment report: findings, evidence, remediation
orthanc-hardened.json    a baseline hardened Orthanc configuration to start from
```

## Why this matters

A default Orthanc install ships with authentication disabled, remote access allowed,
the DICOMweb plugin active, and no transport encryption. Any host with network access
can enumerate the archive, retrieve images, and push files without credentials. The
findings in `report.md` reproduce on any Orthanc server installed with default
settings, which is the point: the default is the vulnerability, not the misconfiguration.

## Disclaimer

This repository is educational. The findings are real in the sense that they
reproduce on default software, but the target organization and network are fictional,
and no vulnerability disclosure against a real deployment is implied or intended.
