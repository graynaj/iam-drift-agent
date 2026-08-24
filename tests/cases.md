# Risk assessment — test runs

Model: gemini-3.7-flash (Vertex AI), temperature=0.1
Date: 2026-08-24

## Run 1
[Direct use of automatic function calling (AFC) in Models.generate_content is not recommended. Instead, we recommend to use AFC in Chat.send_message. Similarly, direct use of AFC in Models.generate_content_stream is not recommended. Instead, we recommend to use AFC in Chat.send_message_stream.

=== owner_to_service_account ===
CRITICAL | intentional: True
Granting the primitive roles/owner role to a service account provides unrestricted administrative control across the entire project, violating least privilege principles. This presents a severe security risk as any compromise of the service account results in full project takeover.
→ Revoke roles/owner and assign fine-grained, least-privilege roles required specifically for the CI/CD pipeline's tasks.

=== public_bucket ===
CRITICAL | intentional: False
Granting any role to allUsers exposes the resource publicly to the entire internet, representing an immediate critical security risk. The target bucket customer-exports likely contains sensitive customer information and was modified directly by an intern account rather than an automated CI/CD pipeline.
→ Immediately remove the allUsers binding from the bucket IAM policy and enable Cloud Storage public access prevention on the bucket.

=== routine_viewer ===
LOW | intentional: True
The granted role roles/logging.viewer is a standard read-only role assigned to an internal corporate user. This conforms to least-privilege principles for an analyst requiring visibility into project logs without modification rights.
→ Confirm that the analyst requires access to these specific logs and ensure log data does not expose sensitive credentials or PII.

=== night_escalation ===
CRITICAL | intentional: False
Granting the Service Account Token Creator role at the project level to an external contractor allows full impersonation of any service account within the project. Occurring during off-hours at 03:47 UTC, this broad privilege escalation presents an immediate and severe security risk.
→ Revoke roles/iam.serviceAccountTokenCreator from contractor@external.com at the project level immediately and grant access only to specific service accounts if required.

=== permission_removal ===
LOW | intentional: True
This change revokes the broad primitive Editor role from an offboarded user, which reduces the attack surface and follows least privilege principles. Because this is a standard permission removal by an administrator during business hours, the overall risk is low.
→ Verify that former-employee@example.com has been fully deprovisioned across all other cloud resources and Google Workspace.]

## Run 2 (identical input, identical prompt)
[Direct use of automatic function calling (AFC) in Models.generate_content is not recommended. Instead, we recommend to use AFC in Chat.send_message. Similarly, direct use of AFC in Models.generate_content_stream is not recommended. Instead, we recommend to use AFC in Chat.send_message_stream.

=== owner_to_service_account ===
CRITICAL | intentional: True
Granting the primitive roles/owner role provides complete, unrestricted administrative access and control over all project resources and IAM policies. This violates the principle of least privilege and introduces severe security risk, even when granted to a CI service account.
→ Revoke roles/owner and grant specific, least-privilege predefined or custom roles tailored to the CI pipeline's exact functional needs.

=== public_bucket ===
CRITICAL | intentional: False
Granting any permissions to allUsers exposes the bucket to the entire public internet, posing an immediate data leakage risk. Because this policy change grants read access on customer-exports and was performed by an individual intern account, it constitutes a critical security incident.
→ Immediately remove the roles/storage.objectViewer binding for allUsers and enable Public Access Prevention on the bucket.

=== routine_viewer ===
LOW | intentional: True
The granted role roles/logging.viewer confers read-only access to view logs across the project to an internal user. This aligns with least-privilege principles for an analyst role and does not allow modifying resources or permissions.
→ Verify that the analyst requires project-level log access and confirm that application logs do not expose sensitive data or credentials.

=== night_escalation ===
HIGH | intentional: False
Granting the Service Account Token Creator role at the project level to an external identity allows impersonation of all service accounts within the project. The change occurred outside standard business hours and introduces significant privilege escalation risk.
→ Revoke roles/iam.serviceAccountTokenCreator from contractor@external.com and scope any necessary impersonation permissions to specific service accounts rather than the entire project.

=== permission_removal ===
LOW | intentional: True
This change revokes a high-privilege primitive role (roles/editor) from an offboarded user account, which reduces overall risk. It aligns with least privilege principles and standard account offboarding procedures.
→ Verify that all other project, folder, and organization-level IAM bindings and active credentials for former-employee@example.com have been fully revoked.

=== ambiguous_ci ===
HIGH | intentional: True
The change grants the primitive roles/editor role to a service account, giving broad modification permissions across almost all project resources. While applied via an authorized Terraform service account, primitive role assignments represent a significant security risk.
→ Replace the primitive roles/editor role with specific, fine-grained predefined roles tailored to the deployment service account's exact requirements.

=== self_grant ===
HIGH | intentional: False
Granting the roles/iam.securityAdmin role to an individual developer provides broad permissions to modify all IAM policies within the project. This presents a high risk of privilege escalation, especially since the developer account is granting this powerful administrative role to itself.
→ Revoke roles/iam.securityAdmin from dev@example.com and enforce principle of least privilege using predefined or custom roles with scoped permissions.]

## Finding: non-deterministic severity
`night_escalation` scored CRITICAL in run 1 and HIGH in run 2 with the same
input and temperature=0.1. All other cases were stable across runs.

This matters because alert routing depends on the severity threshold — the same
event would page an on-call engineer in one run and not the other. Open question
for day 2: enforce deterministic severity via explicit rules and let the model
supply only reasoning, or keep model-assigned severity and store confidence.