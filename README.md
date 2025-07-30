# Cloud Incident Response Automation

This project automates threat detection and response in AWS using GuardDuty, EventBridge, Lambda, and custom threat intelligence. When a potential security incident is detected, the system isolates the affected EC2 instance, tags it as compromised, and sends real-time alerts via SNS. A separate Lambda function can restore the instance to a healthy state. 

---

## Table of Contents
1. Project Overview & Objectives

2. Architecture Diagram & Data Flow

3. Tools & AWS Services Used

4. Build Steps (Terraform / Console)

5. Lambda Code & Logic Explained

6. Custom Threat Intelligence (S3)

7. Attack Simulation & Results

8. Lessons Learned & Future Roadmap

9. Appendix
