# Incident Summary: Phishing Email Detected Post-Delivery

## Incident ID
INC-001

## Incident Type
Phishing / Deceptive Email

## Detection Source
SIEM – Email Security Monitoring

## Alert Overview
A SIEM alert was triggered after an email was marked as phishing post-delivery. Automated analysis identified multiple indicators consistent with phishing, including spoofing behavior, authentication failures, and a suspicious compressed attachment.

## Affected User
- **Recipient:** Eddie Huffman (IT Manager)
- **Email Address:** e.huffman@tryhackme.thm

## Timeline
- **Email Delivered:** March 27, 2025
- **Alert Generated:** March 27, 2025 at 19:25
- **Severity:** Medium
- **Verdict:** True Positive

## Email Details
- **Subject:** Important Update: Microsoft Teams Pricing Increase
- **Sender Display Name:** Microsoft Support
- **Sender Address:** support@microsoft.com (spoofed)
- **Attachment:** REPORT.rar

## Indicators of Compromise (IOCs)
- Spoofed sender impersonating Microsoft
- SPF: Fail
- DKIM: Fail
- Urgent language indicating social engineering
- Suspicious compressed attachment (.rar)

## Investigation Steps
- Reviewed SIEM alert metadata and email headers
- Analyzed sender authentication results (SPF/DKIM)
- Evaluated attachment type and delivery method
- Assessed language and context for social engineering indicators

## Findings
- Sender failed email authentication checks
- Attachment type commonly used to deliver malware
- Message used urgency and impersonation tactics
- No evidence of legitimate business purpose

## MITRE ATT&CK Mapping
- **T1566.001 – Phishing: Spearphishing Attachment**
- **TA0001 – Initial Access**

## Severity Assessment
**Medium**  
The email posed a credible phishing risk but no evidence of execution or user interaction was observed.

## Response Actions
- Classified alert as a True Positive
- Documented findings in the SIEM
- Recommended blocking sender and attachment hash
- Advised user awareness and monitoring

## Outcome
The phishing email was successfully identified, investigated, and documented according to SOC procedures. No further malicious activity was observed.

## Lessons Learned
- Email authentication failures are strong phishing indicators
- Post-delivery detection remains critical
- Clear documentation improves SOC response consistency
