# Cloud Incident Response Automation

This project automates threat detection and response in AWS using GuardDuty, EventBridge, Lambda, and custom threat intelligence. When a potential security incident is detected, the system isolates the affected EC2 instance, tags it as compromised, and sends real-time alerts via SNS. A separate Lambda function can restore the instance to a healthy state. 



## Table of Contents
1. Project Overview & Objectives

2. Architecture Diagram & Data Flow

3. Tools & AWS Services Used

4. Build Steps (Terraform / Console) (s3 in here as well, include code snapshot in step that have it and explain it briefly in this part as well)

5. Attack Simulation & Results

6. Appendix



## 1. Project Overview & Objectives
When managing infrastructure on AWS, detecting and responding to security incidents quickly is essential. Manual incident response processes such as identifying compromised EC2 instances, isolating them, and notifying the security team can take significant time and effort. During this delay, attackers may continue exfiltrating sensitive data, causing increased security risks and potential damage to the business.

To solve these challenges, I built a fully automated incident response pipeline. This pipeline instantly detects malicious activity, isolates compromised instances, tags affected resources clearly, and alerts the security team through real-time notifications.

## 2. Architecture Diagram & Data Flow
<img width="1820" height="1253" alt="image" src="https://github.com/user-attachments/assets/6e1312fc-dd6d-46ac-86d8-4c11a8072242" />


## 3. Tools & AWS Services Used
1. Amazon EC2
2. Amazon S3
3. Amazon SNS
4. Amazon EventBridge
5. Amazon GuardDuty
6. Amazon VPC
7. Amazon CloudWatch
8. AWS IAM
9. AWS Lambda
