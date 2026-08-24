CASES = {
    "owner_to_service_account": """
principal: dev@example.com
method: SetIamPolicy
resource: projects/iam-drift-agent
change: granted roles/owner to svc-ci@example.iam.gserviceaccount.com
time: 2026-08-24T14:22:00Z
""",

    "public_bucket": """
principal: intern@example.com
method: storage.setIamPermissions
resource: buckets/customer-exports
change: granted roles/storage.objectViewer to allUsers
time: 2026-08-24T16:05:00Z
""",

    "routine_viewer": """
principal: admin@example.com
method: SetIamPolicy
resource: projects/iam-drift-agent
change: granted roles/logging.viewer to analyst@example.com
time: 2026-08-24T10:15:00Z
""",

    "night_escalation": """
principal: contractor@external.com
method: SetIamPolicy
resource: projects/iam-drift-agent
change: granted roles/iam.serviceAccountTokenCreator to contractor@external.com
time: 2026-08-24T03:47:00Z
""",

    "permission_removal": """
principal: admin@example.com
method: SetIamPolicy
resource: projects/iam-drift-agent
change: removed roles/editor from former-employee@example.com
time: 2026-08-24T09:00:00Z
""",

    "ambiguous_ci": """
principal: svc-terraform@example.iam.gserviceaccount.com
method: SetIamPolicy
resource: projects/iam-drift-agent
change: granted roles/editor to svc-deploy@example.iam.gserviceaccount.com
time: 2026-08-24T11:30:00Z
""",

    "self_grant": """
principal: dev@example.com
method: SetIamPolicy
resource: projects/iam-drift-agent
change: granted roles/iam.securityAdmin to dev@example.com
time: 2026-08-24T15:12:00Z
""",
}