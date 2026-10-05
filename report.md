# DICOM Server Security Assessment
## Lakeside General Hospital | Orthanc DICOM Server
### github.com/mhebert-security/dicom-assessment

---

**Assessment Type:** Web Application and Network Protocol Security Assessment  
**Target System:** Orthanc DICOM Server v1.11.2  
**Target IP:** 10.20.30.50 (internal network, clinical VLAN)  
**Assessment Date:** 2026-09-18  
**Report Version:** 1.0  
**Classification:** Confidential

---

## About This Document

This report is an educational companion to Module 5, Article 11 of the OT/ICS Security learning series at mhebert.dev/ot-learning/. It documents findings from a security assessment of a default-configured Orthanc DICOM server in a simulated clinical environment.

The target organization is fictional. Lakeside General Hospital does not exist. The IP address is from a private RFC 1918 range and does not represent any real system. All patient data used during testing came from publicly available de-identified DICOM datasets. No real patient information was accessed or retained.

The purpose of this report is to document what an unauthenticated DICOM server exposes, how the exposure is confirmed with standard tools, and what configuration changes address each finding. It is structured as a real pentest report because the findings are real in the sense that they reproduce on any default Orthanc installation.

---

## Executive Summary

Lakeside General Hospital's Orthanc DICOM server was assessed for security vulnerabilities affecting the confidentiality, integrity, and availability of imaging data and protected health information. Eight findings were identified. Two are rated Critical. Three are rated High. Three are rated Medium.

The most significant finding is that the Orthanc REST management API is exposed without authentication on port 8042. Any host with network access to the clinical VLAN can enumerate all stored studies, retrieve DICOM files, delete studies, and modify server configuration without credentials.

The DICOM network service on port 11112 accepts connections from any AE title without authentication. Any host can query the study database, retrieve patient records, and push arbitrary image files to the server.

The DICOMweb REST API exposes the same imaging data over standard HTTP without authentication, making the archive accessible from any HTTP client, including web browsers and scripts that have no DICOM-specific tooling.

All findings are reproducible on any Orthanc server installed with default settings. Remediation requires configuration changes to the Orthanc configuration file. It does not require upgrading to a paid version or replacing the software.

---

## Scope and Methodology

**In-Scope Systems**

| System | IP | Port(s) | Protocol |
|--------|-----|---------|----------|
| Orthanc DICOM Server | 10.20.30.50 | 8042 | HTTP (REST API) |
| Orthanc DICOM Server | 10.20.30.50 | 11112 | DICOM DIMSE |
| Orthanc DICOMweb Plugin | 10.20.30.50 | 8042 | HTTP (DICOMweb REST) |

**Out of Scope**

The assessment covered only the Orthanc server. It did not include the hospital's broader network infrastructure, firewalls, workstations, or other clinical systems.

**Testing Approach**

Testing was black-box for the initial reconnaissance phase and gray-box for configuration review. No credentials were provided prior to testing. The assessment team accessed configuration files after establishing that the server was accessible without authentication.

**Tools Used**

Nmap 7.95 with DICOM NSE scripts for service discovery. DCMTK 3.6.8 (`echoscu`, `findscu`, `movescu`, `storescp`, `storescu`) for DICOM protocol testing. curl 8.6.0 for HTTP and DICOMweb testing. Orthanc REST API documentation for endpoint enumeration. pynetdicom 2.0.2 for scripted testing.

---

## Risk Rating Definitions

Findings are rated on a five-level scale. CVSS 3.1 base scores are calculated without authentication credit where authentication is absent.

| Rating | CVSS Range | Description |
|--------|------------|-------------|
| Critical | 9.0 - 10.0 | Immediate exploitation possible, direct patient data exposure or system compromise |
| High | 7.0 - 8.9 | Significant data exposure or service disruption without authentication |
| Medium | 4.0 - 6.9 | Meaningful risk that contributes to or enables higher-severity findings |
| Low | 2.0 - 3.9 | Minor information disclosure or hardening gap |
| Informational | 0.0 - 1.9 | Observation requiring no immediate action |

---

## Findings

### F-01: Unauthenticated Orthanc REST API Exposes Full Administrative Access

**Severity:** Critical  
**CVSS 3.1 Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**Finding ID:** F-01  
**Affected Component:** Orthanc REST API, port 8042  
**OWASP Category:** A01:2021 Broken Access Control

**Description**

The Orthanc server's built-in web interface and REST API are accessible on port 8042 without authentication. Any host with network connectivity to the clinical VLAN can perform the following actions without credentials: enumerate all stored studies and series, retrieve DICOM files, delete individual studies or the entire archive, push new DICOM files, query the system's configuration, restart the server, and create or delete custom data.

The Orthanc configuration file confirms the default state:

```json
"AuthenticationEnabled" : false,
"RegisteredUsers" : {},
"RemoteAccessAllowed" : true
```

**Evidence**

The following curl command returned a JSON array of all study instance UIDs stored on the server. No authentication headers were provided.

```
$ curl http://10.20.30.50:8042/studies
["1.2.840.10008.5.1.4.1.2.1.1.20260918.101523.000001",
 "1.2.840.10008.5.1.4.1.2.1.1.20260918.093147.000002",
 "1.2.840.10008.5.1.4.1.2.1.1.20260918.084212.000003",
 ... (147 additional entries) ]
```

The study count returned was 150. Each UID can be used to retrieve patient-level metadata and the full study.

Retrieving patient metadata for a single study:

```
$ curl http://10.20.30.50:8042/studies/1.2.840.10008.5.1.4.1.2.1.1.20260918.101523.000001
{
  "ID" : "1.2.840.10008.5.1.4.1.2.1.1.20260918.101523.000001",
  "PatientMainDicomTags" : {
    "PatientBirthDate" : "19680412",
    "PatientID" : "LGH-2026-00442",
    "PatientName" : "TESTPATIENT^ALPHA^",
    "PatientSex" : "F"
  },
  "MainDicomTags" : {
    "StudyDate" : "20260918",
    "StudyDescription" : "CT CHEST W/O CONTRAST",
    "ReferringPhysicianName" : "ORTEGA^MARCO^"
  },
  ...
}
```

This response is from the publicly available TCIA test dataset loaded for assessment purposes. The structure is identical to production data.

**Impact**

An attacker with access to the clinical network can enumerate and retrieve the complete imaging archive without credentials. Patient demographics, study descriptions, and referring physician names are exposed in REST responses before any image is retrieved. The same API allows deletion and modification of the archive, which would affect the integrity of the clinical record.

**Remediation**

Enable authentication in the Orthanc configuration file. Create at least one administrative user. Restrict remote access to approved management hosts.

```json
"AuthenticationEnabled" : true,
"RegisteredUsers" : {
  "pacs-admin" : "CHANGE_THIS_PASSWORD"
},
"RemoteAccessAllowed" : false
```

If remote management is required from specific hosts, configure reverse proxy authentication at the network layer rather than relying on Orthanc's basic authentication for external access.

**Retest Guidance**

After applying the configuration change and restarting Orthanc, confirm that `curl http://10.20.30.50:8042/studies` returns HTTP 401 Unauthorized. Confirm that the correct credentials authenticate successfully and that an incorrect password returns 401.

---

### F-02: DICOM Service Accepts Connections Without Authentication or Encryption

**Severity:** High  
**CVSS 3.1 Score:** 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)  
**Finding ID:** F-02  
**Affected Component:** DICOM DIMSE service, port 11112  
**OWASP Category:** A07:2021 Identification and Authentication Failures

**Description**

The DICOM service accepts DIMSE connections from any Application Entity title without verifying the identity of the connecting client. There is no credential check and no transport encryption. Any host that can reach port 11112 can establish a valid DICOM association.

**Evidence**

The following `echoscu` command established a successful DICOM association using a fabricated AE title:

```
$ echoscu -aec ORTHANC -aet TESTCLIENT 10.20.30.50 11112

I: ----------------------------------
I: Called Application Entity:  ORTHANC
I: Calling Application Entity: TESTCLIENT
I: ----------------------------------
I: Request Parameters:
I: =====================
I: Association Parameters Negotiated:
I: =====================
I: ...
I: Received Echo Response (Status=0x0000: Success)
```

The AE title `TESTCLIENT` is not registered in any configuration on the server. The connection was accepted regardless.

Confirmation of plaintext transport via Wireshark during C-ECHO exchange: the full DICOM PDU is visible in the capture with no TLS wrapping. A-ASSOCIATE-RQ and A-ASSOCIATE-AC packets are cleartext, including the calling and called AE titles.

**Impact**

Any host on the clinical network can establish a DICOM association and use any DICOM service the server provides. Patient data transmitted during C-FIND and C-MOVE operations traverses the network in plaintext. AE titles exchanged during association negotiation are visible to any host capable of capturing traffic on the network segment.

**Remediation**

Configure AE title filtering to restrict which calling AE titles the server accepts. This raises the barrier without requiring TLS infrastructure.

```json
"DicomAet" : "ORTHANC",
"DicomCheckCalledAet" : true,
"DicomServer" : {
  "Enabled" : true,
  "Port" : 11112,
  "AetChecked" : true
}
```

For environments where TLS is feasible, configure DICOM TLS on port 2762 with certificates issued by your organization's CA. Consult the Orthanc DICOM TLS documentation for the configuration parameters. Disable the plaintext port once TLS is operational.

**Retest Guidance**

After enabling AE title checking, confirm that `echoscu` with an unlisted AE title returns an association rejection. Confirm that a listed AE title from an approved host connects successfully.

---

### F-03: DICOMweb REST API Exposes Imaging Archive Without Authentication

**Severity:** High  
**CVSS 3.1 Score:** 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**Finding ID:** F-03  
**Affected Component:** DICOMweb plugin, QIDO-RS and WADO-RS endpoints, port 8042  
**OWASP Category:** A01:2021 Broken Access Control

**Description**

The Orthanc DICOMweb plugin is installed and enabled in the default configuration. The QIDO-RS query endpoints and WADO-RS retrieval endpoints are accessible without authentication. This makes the complete imaging archive accessible via standard HTTP GET requests from any HTTP client.

**Evidence**

QIDO-RS query for all studies, no credentials provided:

```
$ curl "http://10.20.30.50:8042/dicom-web/studies?00100010=*"
[
  {
    "00080020": {"vr": "DA", "Value": ["20260918"]},
    "00080061": {"vr": "CS", "Value": ["CT"]},
    "00100010": {"vr": "PN", "Value": [{"Alphabetic": "TESTPATIENT^ALPHA^"}]},
    "00100020": {"vr": "LO", "Value": ["LGH-2026-00442"]},
    "00100030": {"vr": "DA", "Value": ["19680412"]},
    ...
  },
  ...
]
```

The response includes patient name, patient ID, and date of birth in the QIDO-RS JSON format for each study. A wildcard patient name query returns all studies. Narrower queries by patient ID, date, or modality refine the result set.

WADO-RS image retrieval:

```
$ curl -o study.zip \
  "http://10.20.30.50:8042/dicom-web/studies/1.2.840.10008.5.1.4.1.2.1.1.20260918.101523.000001"
```

The response is a multipart MIME body containing the complete DICOM files for the study. The download succeeded without credentials.

**Impact**

The DICOMweb API eliminates the need for specialized DICOM tooling. An attacker with HTTP access can query and retrieve imaging data using a web browser, curl, or any scripting language with an HTTP library. The attack surface includes web applications running on the clinical network that can make cross-origin HTTP requests to the Orthanc server.

**Remediation**

Orthanc's DICOMweb plugin inherits authentication from the main Orthanc configuration. Enabling `AuthenticationEnabled` in the main configuration (see F-01 remediation) also protects the DICOMweb endpoints. No separate DICOMweb configuration change is required once main authentication is enabled.

If DICOMweb access is not required, disable the plugin:

```json
"Plugins" : []
```

Or remove the DICOMweb plugin file from the Orthanc plugins directory.

**Retest Guidance**

After enabling authentication, confirm that the QIDO-RS and WADO-RS endpoints return HTTP 401. Confirm that authenticated requests succeed and return the expected data.

---

### F-04: Orthanc Server Running Outdated Version with Known Vulnerabilities

**Severity:** High  
**CVSS 3.1 Score:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)  
**Finding ID:** F-04  
**Affected Component:** Orthanc v1.11.2  
**CVE References:** CVE-2023-33466 (path traversal via DICOM dataset attributes)

**Description**

The installed Orthanc version is 1.11.2, released in 2023. The current stable release at time of assessment is 1.12.4. CVE-2023-33466 was disclosed against Orthanc versions prior to 1.12.0 and describes a path traversal vulnerability where specially crafted DICOM attribute values can cause the server to write files to arbitrary filesystem locations.

Version information is disclosed in the HTTP Server response header and in the REST API system endpoint:

```
$ curl http://10.20.30.50:8042/system
{
  "Name" : "Orthanc",
  "Version" : "1.11.2",
  "ApiVersion" : 20,
  ...
}
```

**Impact**

CVE-2023-33466 combined with the unauthenticated C-STORE endpoint (see F-02) allows an unauthenticated attacker to write arbitrary files to the server filesystem via DICOM attribute injection. The combined risk is higher than either finding in isolation. Exploitation could enable remote code execution if the attacker can write to a location that is later executed.

**Remediation**

Upgrade Orthanc to version 1.12.4 or later. Verify that the upgrade does not break compatibility with existing plugins or connected DICOM clients. Test against a non-production instance before applying to the archive server.

After upgrading, verify version via the system endpoint:

```
$ curl http://10.20.30.50:8042/system | grep Version
```

**Retest Guidance**

Confirm the system endpoint returns the updated version number. Confirm that all plugins are functioning after upgrade.

---

### F-05: DICOM Traffic Transmitted in Plaintext (No TLS)

**Severity:** Medium  
**CVSS 3.1 Score:** 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**Finding ID:** F-05  
**Affected Component:** DICOM DIMSE service, port 11112  
**OWASP Category:** A02:2021 Cryptographic Failures

**Description**

DICOM connections on port 11112 are not encrypted. Patient name, patient ID, date of birth, study descriptions, and imaging data transferred during C-FIND, C-MOVE, and C-STORE operations traverse the network in cleartext. This includes sensitive PHI in DICOM attributes and the pixel data of the images themselves.

A Wireshark capture during a C-FIND query returns plaintext patient attributes in the DICOM PDU payload. A capture during C-MOVE returns plaintext image data.

This finding is partially overlapping with F-02 but is rated separately because TLS remediation and authentication remediation are independent configuration changes. A deployment might address authentication without addressing encryption, or vice versa.

**Evidence**

Wireshark capture filter for DICOM traffic on the test segment: `tcp.port == 11112`. During a C-FIND query, the response PDU containing PatientName, PatientID, and PatientBirthDate attributes is visible in the packet capture without decryption.

**Impact**

Any host capable of capturing traffic on the network segment between DICOM clients and the server can read patient demographics and image data in transit. In a shared clinical network, this includes other workstations, printers, IoT devices, and any endpoint with network access. The risk is elevated in environments where the clinical VLAN is not microsegmented.

**Remediation**

Enable DICOM TLS on port 2762. Orthanc supports TLS via the OrthancTLS configuration section. Certificates should be issued by your organization's internal CA or a trusted commercial CA. Once TLS is operational, disable the plaintext port.

```json
"DicomTlsEnabled" : true,
"DicomTlsCertificate" : "/etc/orthanc/certs/orthanc.crt",
"DicomTlsPrivateKey" : "/etc/orthanc/certs/orthanc.key",
"DicomTlsTrustedCertificates" : "/etc/orthanc/certs/ca-bundle.crt"
```

As an interim measure before TLS is available, ensure the clinical VLAN is network-segmented such that only approved DICOM client hosts can reach port 11112.

**Retest Guidance**

Confirm that TLS connections on port 2762 succeed with authorized clients. Confirm that plaintext connections on port 11112 are rejected or unreachable after migration.

---

### F-06: Server Version and Configuration Details Disclosed in HTTP Headers

**Severity:** Medium  
**CVSS 3.1 Score:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
**Finding ID:** F-06  
**Affected Component:** HTTP server, port 8042  
**OWASP Category:** A05:2021 Security Misconfiguration

**Description**

The Orthanc HTTP server discloses version information in response headers and in the unauthenticated `/system` REST endpoint. The Server response header identifies the application and version. The `/system` endpoint returns a JSON object containing version number, API version, plugin list, and system capabilities.

**Evidence**

HTTP response headers from any request to port 8042:

```
HTTP/1.1 200 OK
Server: Orthanc/1.11.2
Content-Type: application/json
...
```

System endpoint response (accessible without authentication):

```
$ curl http://10.20.30.50:8042/system
{
  "ApiVersion" : 20,
  "DatabaseBackendPlugin" : null,
  "DatabaseVersion" : 6,
  "IsHttpServerSecure" : false,
  "PluginsEnabled" : true,
  "Version" : "1.11.2",
  ...
}
```

The `IsHttpServerSecure` field explicitly reports that the server is not configured securely. The field is present in Orthanc's API specifically to surface this condition.

**Impact**

Version disclosure enables targeted exploitation of known vulnerabilities (see F-04). Plugin and capability disclosure reveals the attack surface available to an unauthenticated attacker without requiring enumeration. The `IsHttpServerSecure: false` field confirms to an attacker that the security configuration is default.

**Remediation**

The most effective remediation is enabling authentication (F-01), which restricts access to the `/system` endpoint and the `Server` header still discloses version but the detailed system response requires credentials.

To suppress the Server header, configure a reverse proxy such as nginx in front of Orthanc and strip or replace the upstream Server header. This adds a layer of obfuscation but is lower priority than authentication.

**Retest Guidance**

After enabling authentication, confirm that `/system` returns HTTP 401 without credentials. Confirm that authenticated access to `/system` still returns the expected response for authorized users.

---

### F-07: No Audit Logging of DICOM Queries or Retrievals

**Severity:** Medium  
**CVSS 3.1 Score:** 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N)  
**Finding ID:** F-07  
**Affected Component:** Orthanc DICOM service and REST API  
**OWASP Category:** A09:2021 Security Logging and Monitoring Failures

**Description**

Orthanc's default configuration does not produce structured audit logs of DICOM operations. The application log records HTTP requests and DICOM associations at a general level, but does not log the specific studies queried, the patient records accessed, or the identity of the requesting client in a format suitable for audit review or HIPAA compliance documentation.

HIPAA's Security Rule requires audit controls that record and examine activity in systems containing PHI. Imaging systems are explicitly included in this requirement.

**Evidence**

Reviewing `/var/log/orthanc/Orthanc.log` after a C-FIND query and image retrieval shows:

```
I 2026-09-18 14:32:17 DICOM server received an association from: 10.20.30.45
I 2026-09-18 14:32:17 Association #0: TESTCLIENT -> ORTHANC
I 2026-09-18 14:32:18 Connection closed
```

The log records the source IP and AE title but does not record what was queried, which studies were returned, or how many records were accessed. The HTTP log for the REST API is more granular (recording URLs and HTTP methods) but still does not record the study UIDs accessed or the patient identifiers returned.

**Impact**

Without structured audit logging, the organization cannot determine after the fact which patient records were accessed, by which client, at what time, or how many records were retrieved. This limits the ability to detect unauthorized access after it has occurred and complicates breach investigation and HIPAA audit response.

**Remediation**

Orthanc does not produce DICOM audit trail messages in the DICOM Supplement 95 format out of the box. A Lua script or plugin can be used to intercept C-FIND and C-MOVE events and write structured audit records.

The Orthanc documentation describes event callbacks available to Lua scripts, including `OnReceivedQuery` and `OnStoredInstance`. These can be used to write patient-level audit records to a separate log file or syslog destination.

For environments requiring ATNA-compliant audit trail output, the Orthanc Audit Trail plugin is available and supports Supplement 95 formatting.

At minimum, configure centralized syslog forwarding of the Orthanc application log to a SIEM. This does not solve the granularity problem but ensures that logs are preserved even if the server is compromised.

**Retest Guidance**

After implementing audit logging, confirm that a C-FIND query produces a log entry that identifies the querying AE title, the query parameters used, and the number of studies returned. Confirm that a WADO-RS retrieval produces a log entry that identifies the source IP and the study instance UID retrieved.

---

### F-08: C-STORE Endpoint Accepts Files Without Content Validation

**Severity:** Medium  
**CVSS 3.1 Score:** 6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)  
**Finding ID:** F-08  
**Affected Component:** DICOM DIMSE C-STORE service, port 11112  
**OWASP Category:** A04:2021 Insecure Design

**Description**

The Orthanc C-STORE endpoint accepts DICOM files from any connecting AE title without authentication (see F-02) and without validating the content of the submitted files beyond basic DICOM structural compliance. An attacker can push DICOM files with arbitrary patient demographic attributes to the archive, creating false studies attributed to real or fabricated patients.

**Evidence**

Using `storescu` from DCMTK, a test DICOM file was created with modified patient attributes and pushed to the server:

```
$ dcmodify -i "(0010,0010)=TESTPATIENT^INJECTED" test_image.dcm
$ storescu -aec ORTHANC -aet MALICIOUS_NODE 10.20.30.50 11112 test_image.dcm

I: Sending file: test_image.dcm
I: Transfer: LittleEndianExplicit -> LittleEndianExplicit
I: Received Store Response (Status=0x0000: Success)
```

The server accepted the file and stored it with the injected patient name. Querying the server afterward returned the injected study as a legitimate entry in the archive.

A second test pushed a DICOM file with a patient ID matching an existing study to the server. The file was stored as a new series under the existing study, demonstrating that files can be injected into real patient records.

**Impact**

An attacker with network access to the DICOM port can inject fraudulent imaging studies into the archive attributed to real patients, add series to existing patient studies, create studies that reference real patient identifiers with fabricated content, and potentially manipulate clinical workflows that rely on the PACS to confirm imaging results.

The impact on patient safety depends on the clinical workflow. In environments where the PACS is queried before a procedure to confirm whether prior imaging exists, injected studies could influence clinical decisions.

**Remediation**

The primary remediation is authentication at the DICOM service level (F-02). AE title filtering restricts which clients can use C-STORE. This does not prevent a compromised approved node from injecting content, but it removes anonymous write access.

For environments requiring stronger integrity controls, consider a Lua validation script that checks incoming C-STORE files against known patient lists or rejects studies with unexpected patient ID formats before storage.

Separating the PACS into read-only and write-capable DICOM services at the network layer, with C-STORE available only from imaging equipment addresses, provides defense in depth.

**Retest Guidance**

After enabling AE title filtering, confirm that `storescu` from an unlisted AE title receives an association rejection. Confirm that an approved AE title from an approved source IP can still push files.

---

## Remediation Summary

| Finding | ID | Severity | Remediation |
|---------|-----|----------|-------------|
| Unauthenticated REST API | F-01 | Critical | Set `AuthenticationEnabled=true`, configure user credentials |
| DICOM service unauthenticated | F-02 | High | Enable AE title filtering; deploy DICOM TLS |
| DICOMweb unauthenticated | F-03 | High | Resolved by F-01 remediation; disable plugin if not needed |
| Outdated Orthanc version | F-04 | High | Upgrade to Orthanc 1.12.4 or later |
| No transport encryption | F-05 | Medium | Enable DICOM TLS on port 2762; disable plaintext port |
| Version and config disclosure | F-06 | Medium | Resolved by F-01 remediation; add reverse proxy for header suppression |
| No audit logging | F-07 | Medium | Implement Lua audit callbacks or Audit Trail plugin |
| C-STORE without content validation | F-08 | Medium | Resolved by F-02 AE title filtering; add Lua content validation |

---

## Hardened Configuration Reference

The following Orthanc configuration file addresses the critical and high findings and establishes a baseline hardened state. Replace placeholder values with site-specific credentials and certificate paths before deployment.

```json
{
  "Name" : "Orthanc",
  "StorageDirectory" : "/var/lib/orthanc/db",
  "IndexDirectory" : "/var/lib/orthanc/db",

  "AuthenticationEnabled" : true,
  "RegisteredUsers" : {
    "pacs-admin" : "REPLACE_WITH_STRONG_PASSWORD"
  },

  "RemoteAccessAllowed" : false,
  "SslEnabled" : false,

  "DicomAet" : "ORTHANC",
  "DicomPort" : 11112,
  "DicomCheckCalledAet" : true,

  "DicomModalities" : {
    "CT_SCANNER_01" : [ "CT_UNIT_01", "10.20.30.10", 104 ],
    "WS_RAD_01"    : [ "WS_RAD_01", "10.20.30.20", 11112 ]
  },

  "DicomTlsEnabled" : true,
  "DicomTlsCertificate" : "/etc/orthanc/certs/orthanc.crt",
  "DicomTlsPrivateKey" : "/etc/orthanc/certs/orthanc.key",
  "DicomTlsTrustedCertificates" : "/etc/orthanc/certs/ca-bundle.crt",

  "Plugins" : [
  ],

  "HttpDescribeErrors" : false,

  "Verbose" : false,
  "Trace" : false,
  "LogFile" : "/var/log/orthanc/orthanc.log"
}
```

Notes on this configuration: `RemoteAccessAllowed` set to false restricts the web interface to localhost. If remote management is required, place Orthanc behind an nginx reverse proxy with TLS and HTTP Basic Auth or mutual TLS at the proxy layer. The Plugins array is empty; re-add specific plugins as needed after confirming they are required and that their authentication inherits from the main configuration. The DICOMweb plugin is excluded from the baseline because it was not required for the assessment scope and adding it requires confirming authentication inheritance.

---

## Appendix A: Tool Versions

| Tool | Version | Source |
|------|---------|--------|
| Nmap | 7.95 | nmap.org |
| DCMTK | 3.6.8 | dicom.offis.de |
| Orthanc | 1.11.2 (assessed) | orthanc-server.com |
| Orthanc | 1.12.4 (remediation target) | orthanc-server.com |
| curl | 8.6.0 | curl.se |
| pynetdicom | 2.0.2 | pypi.org/project/pynetdicom |
| Wireshark | 4.2.5 | wireshark.org |

---

## Appendix B: Test Data

All DICOM test data used during this assessment came from the Cancer Imaging Archive (TCIA) public dataset collection. Patient names were modified in the test instances loaded on the assessment server. No real patient information was used, stored, or transmitted during testing.

---

## Appendix C: References

DICOM Standard PS 3.8: Network Communication Support for Message Exchange. NEMA, 2023.  
Orthanc Book: Security Hardening. docs.orthanc-server.com.  
CVE-2023-33466: Orthanc path traversal via DICOM attributes. NVD, 2023.  
HIPAA Security Rule 45 CFR Part 164, Subpart C: Technical Safeguards.  
FDA Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions. September 2023.  
DICOM Supplement 95: DICOM Audit Trail Messages. NEMA.

---

*github.com/mhebert-security/dicom-assessment | companion to mhebert.dev/ot-learning/module-5-medical/*
