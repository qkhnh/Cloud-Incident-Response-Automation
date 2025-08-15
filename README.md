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


## 4. Build Steps

### 4.1 Create a custom Threat-IP list (S3) 
1. Open Notepad, VS Code, or any plain text editor then type the attacker's IP address (no headers or quotes)
2. Save the file and note it down for later
3. AWS Console → S3 → Create bucket
4. Enter a bucket name (e.g., GD-Threat-List) → leave defaults → Create bucket
5. Open the bucket → Upload → Add files → choose the file you created just now → Upload
6. Copy the Object URL (you’ll paste it into GuardDuty in Step 4.3)

### 4.2 Create an SNS topic for alerts
1. Console → SNS → Topics → Create topic
2. Type: Standard | Name: GD-incident-alerts (e.g., IncidentAlerts, incident-alerts) → Create topic
3. Inside the topic → Create subscription
    - Protocol: Email | Endpoint: your email
4. Click Create subscription → open the confirmation e-mail and click Confirm subscription
5. Copy the Topic ARN (needed for Lambda env var)

### 4.3 Enable GuardDuty & enter your Threat-IP list
1. Console → GuardDuty → Get started / Enable (if not already on)
2. Left nav → Lists ▸ Add a threat ip list 
    - Name: Threat-ip-list (e.g., CustomThreatIPs, ipthreatlist) | Format: Plaintext
    - Location: paste S3 object URL from Step 4.1
    - Add list
3. Get the Detector ID:
    - Left nav → Settings → "Detector" section.
    - Note down the Detector ID.
  
### 4.4 Turn on VPC Flow Logs (to CloudWatch)
1. Console → VPC → Your VPCs → select default VPC
2. Tabs → Flow Logs → Create flow log
    - Filter All
    - Destination Send to CloudWatch Logs
    - Create new log group (e.g, vpc-flow-logs, Flow-logs)
    - IAM role Create new (vpc-flow-logs-role)
    - Create flow log

### 4.5 Network and Security Groups
1. Create quarantine SG
- Console → EC2 → Security Groups → Create
    - Name: sg_deny_all (e.g., sg_deny_all, sg_block_everything)
    - VPC: default
    - Inbound : Remove all → empty
    - Outbound : Remove all → empty → Create security group

2. Create SG for "Target"
    - Name: sg_target (e.g., TARGET, target_sg)
    - Inbound → Add rule SSH 22 | Source: 0.0.0.0/0
    - Inbound → Add rule HTTP 80 | Source: 0.0.0.0/0
    - Outbound → default → Create
  
3. Create SG for "Attacker"
    - Name: sg_attacker (e.g., ATTACKER, attacker_sg)
    - Inbound → Add rule SSH 22 | Source: My IP
    - Outbound = default → Create
   
### 4.6 Launch EC2 instances
1. Launch Target instance
- Console → EC2 → Launch instances
- Name: target-instance (e.g., Target, TARGET-EC2)
- AMI: Amazon Linux 2 (free tier eligible)
- Instance type: t2.micro
- Key pair: create or select existing key (download .pem file if new)
- Network settings:
    - VPC: default
    - Subnet: default
    - Auto-assign public IP: Enable
    - Security group: Select sg_target from Step 4.5
- Storage: leave default (8 GB gp2)
- Launch instance

2. Launch Attacker instance 
- Console → EC2 → Launch instances
    - Name: attacker-instance (e.g., Attacker, Attacker-EC2)
    - AMI: Kali Linux
    - Instance type: t2.micro
    - Key pair: create or select existing key (download .pem file if new)
    - Network settings:
        - VPC: default
        - Subnet: default
        - Auto-assign public IP: Enable
        - Security group: Select sg_attacker from Step 4.5
    - Storage: leave default (8 GB gp2)
    - Launch instance
 
 ### 4.7 Create Incident Response Lambda (Quarantine)
1. Console → Lambda → Create function
    - Name: GuardDutyIncidentResponder
    - Runtime: Python 3.x
    - Permissions: Create a new role with basic Lambda permissions → Create function
  
2. Add environment variables (Configuration → Environment variables → Edit → Add):
    - BLOCKING_SG_ID = sg_deny_all ID (from 4.5)
    - SNS_TOPIC_ARN_NEW = SNS Topic ARN (from 4.2)
    - APPROVAL_BASE_URL = temporary placeholder (e.g., https://example.com/placeholder). You’ll set the real Function URL in 4.12
    - APPROVAL_SECRET_PARAM = SSM param name you’ll create in 4.9 (e.g., /guardduty/approval/secret)
    - INCIDENT_TOKENS_TABLE = IncidentTokens (you’ll create in 4.8)
    - EXPIRE_MINUTES = 60 (or a custom number that you want)
    - INSTANCE_TAG_KEY = IncidentStatus
    - QUARANTINED_VALUE = Quarantined
      
3. Paste code into the function editor → Deploy.
- Code should:
    - Describe instance → loop each ENI → replace SGs with deny-all.
    - Tag instance: OriginalSGs=<csv> and IncidentStatus=Quarantined.
    - Generate token = uuid4().hex, expires_at = now + EXPIRE_MINUTES*60.
    - Sign instanceId|findingId|token with HMAC-SHA256 (secret from SSM).
    - Build approval URL with token + sig (+ findingTitle) and publish to SNS.
      
4. Attach minimal IAM to the role (Configuration → Permissions → Role name → Add inline policy):
    - EC2: DescribeInstances, ModifyNetworkInterfaceAttribute, CreateTags
    - DynamoDB (table: IncidentTokens): PutItem
    - SNS: Publish on your topic ARN
    - SSM: GetParameter (with decryption) on your secret
    - Logs: CloudWatch Logs permissions
      
### 4.8 Create DynamoDB Table for Approval Tokens
1. Console → DynamoDB → Create table
2. Table name: IncidentTokens
3. Partition key: token (String) → Create table
4. Enable TTL (Table → Additional settings → TTL):
    - Attribute name: expires_at → Enable
5. Item shape (what Lambdas will store/read):
    - token (PK), instanceId, findingId, findingTitle, created_at (int), expires_at (int), used (bool)
      
### 4.9 Create SSM Parameter (HMAC Secret)
1. Console → Systems Manager → Parameter Store → Create parameter
2. Name: /guardduty/approval/secret (or your chosen path)
3. Type: SecureString
4. Value: a long random string (≥32 chars) → Create parameter
5. You’ll reference this name in both Lambdas via APPROVAL_SECRET_PARAM.

### 4.10 Create Restore Lambda (Reapply Original SGs)
1. Console → Lambda → Create function
    - Name: RestoreGuardDutyInstance
    - Runtime: Python 3.x → Create function
2. Behavior (paste code → Deploy):
    - Read instanceId from event.
    - Read OriginalSGs tag from instance, split to list.
    - For each ENI, call ModifyNetworkInterfaceAttribute(Groups=<original list>).
    - Tag IncidentStatus=Healthy.
3. IAM for Restore role:
- EC2:
    - DescribeInstances
    - ModifyNetworkInterfaceAttribute,
    - CreateTags
    - DeleteTags
Logs for this function
