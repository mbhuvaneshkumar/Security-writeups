# Security Write-ups

Welcome to my cybersecurity portfolio. This repository contains hands-on projects and technical write-ups covering Security Operations Center (SOC) monitoring, vulnerability assessment and penetration testing (VAPT), and API security testing.

My goal is to strengthen my practical cybersecurity skills by building lab environments, investigating security events, testing vulnerabilities in intentionally vulnerable applications, and documenting findings with remediation recommendations.

## Projects

### 1. Splunk SOC Home Lab

**Focus:** SIEM monitoring, log analysis, threat detection, and incident investigation.

**Project overview**

Built a SOC home lab using Splunk Enterprise, Splunk Universal Forwarder, and Sysmon to collect and analyze endpoint security telemetry. Used the lab to simulate attack scenarios and practice detecting suspicious activities through log analysis and custom SPL queries.

**What I worked on**
- Configured a Splunk environment for security event collection and analysis.
- Ingested  security events for investigation and monitoring.
- Simulated attack scenarios, including brute-force attempts, RDP lateral movement, and privilege escalation.
- Created four custom SPL detection alerts to identify suspicious activity.
- Practiced investigating security events and understanding how attack activity can be detected through logs.

**Tools:** Splunk Enterprise, Splunk Universal Forwarder, Sysmon, SPL, Windows event logs.

**Project:** [View Splunk SOC Home Lab](SOC-Labs/Splunk-SOC-Home-Lab)

---

### 2. Metasploitable 2 – Vulnerability Assessment and Penetration Testing

**Focus:** Network reconnaissance, service enumeration, vulnerability identification, and exploitation.

**Project overview**

Performed a hands-on VAPT assessment against Metasploitable 2, an intentionally vulnerable Linux environment designed for security testing. The assessment involved identifying exposed services, examining potential vulnerabilities, validating security weaknesses, and documenting their impact.

**Assessment activities**
- Performed network scanning and service enumeration.
- Investigated vulnerable services and potential attack paths.
- Practiced exploitation techniques in a controlled lab environment.
- Reviewed the security impact of identified weaknesses.
- Documented findings and remediation recommendations.

**Tools:** Nmap, Metasploit Framework.

**Project:** [View Metasploitable 2 Assessment](VAPT/Metasploitable-2)

---

### 3. Metasploitable 3 – Vulnerability Assessment and Penetration Testing

**Focus:** Vulnerability discovery, service analysis, exploitation, and security assessment.

**Project overview**

Conducted practical security testing in the Metasploitable 3 lab environment to explore vulnerable services and understand how weaknesses can be identified and validated during a penetration test.

**Assessment activities**
- Conducted reconnaissance and service enumeration.
- Investigated potential vulnerabilities in the target environment.
- Used penetration testing tools to validate security weaknesses.
- Examined the possible impact of successful exploitation.
- Documented assessment observations and relevant security improvements.

**Tools:** Nmap, Metasploit Framework.

**Project:** [View Metasploitable 3 Assessment](VAPT/Metasploitable-3)

---

### 4. API Security Assessment – OWASP Juice Shop

**Focus:** API security testing, authentication, authorization, and sensitive data protection.

**Project overview**

Performed a black-box API security assessment against OWASP Juice Shop, a deliberately vulnerable application used for security testing and training. The assessment focused on identifying API security weaknesses and understanding how they could affect application data and access controls.

**Assessment activities**
- Examined API endpoints and application responses.
- Tested authentication and authorization controls.
- Investigated Broken Object Level Authorization (BOLA).
- Examined broken authentication and sensitive data exposure risks.
- Documented security findings, potential impact, and remediation recommendations.

**Tools:** Burp Suite, browser developer tools, and API testing techniques.

**Project:** [View API Security Assessment](VAPT/API-Security-Assessment)

---

## Skills and Technologies

- **SOC and SIEM:** Splunk Enterprise, SPL, Wazuh, Sysmon, log analysis, alert triage.
- **Vulnerability Assessment and Penetration Testing:** Nmap, Metasploit Framework, Burp Suite, vulnerability validation.
- **Security Analysis:** Windows/Linux logs, network traffic analysis, incident investigation, MITRE ATT&CK.
- **API Security:** Authentication and authorization testing, BOLA, sensitive data exposure.
- **Reporting:** Vulnerability documentation, risk assessment, CVSS scoring, and remediation recommendations.

## What I Have Learned

Through these projects, I have developed practical experience in setting up security testing environments, analyzing logs, investigating suspicious activities, identifying vulnerabilities, validating security findings, and documenting remediation steps. These projects also help me understand both defensive security monitoring and offensive security testing.

## About Me

I am a B.Tech graduate in Computer Science and Engineering with a specialization in Cybersecurity. I am interested in SOC operations, security analysis, vulnerability assessment, and penetration testing, and I continue to build my skills through practical labs and security research.

**Certifications**
- Certified Ethical Hacker (CEH v13)
- CompTIA Security+
- Microsoft Security, Compliance, and Identity Fundamentals (SC-900)

**Connect with me**
- LinkedIn https://www.linkedin.com/in/mummadi-bhuvanesh-kumar/
  

*Disclaimer: All security testing documented in this repository is intended for educational purposes and authorized lab environments. Testing should only be performed on systems for which permission has been granted.*
