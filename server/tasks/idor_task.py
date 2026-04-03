"""
IDOR + Privilege Escalation task definition (Medium).
"""

from .base_task import BaseTask, Milestone

idor_task = BaseTask(
    name="idor_privesc",
    display_name="IDOR + Privilege Escalation — Admin Takeover",
    description=(
        "The VulnApp has two chained vulnerabilities in its user management system. "
        "First, user profiles can be accessed without proper authorization checks (IDOR). "
        "Second, the profile update endpoint accepts fields it shouldn't (mass assignment). "
        "Your objective is to register an account, discover admin data via IDOR, "
        "escalate your privileges to admin, and retrieve the flag. "
        "Start by examining the user management routes."
    ),
    difficulty="medium",
    flag="FLAG{idor_privesc_chain_2024}",
    optimal_steps=9,
    relevant_files=[
        "routes/users.py",
        "routes/admin.py",
        "routes/auth.py",
    ],
    vulnerable_endpoints=[
        "GET /api/users/<id>",
        "PUT /api/users/<id>",
    ],
    milestones=[
        Milestone("source_read", "Read the user management source code", 0.05),
        Milestone("account_created", "Registered a new user account", 0.05),
        Milestone("idor_exploited", "Accessed another user's profile via IDOR", 0.15),
        Milestone("admin_data_found", "Found admin user information", 0.10),
        Milestone("privilege_escalated", "Changed own role to admin via mass assignment", 0.15),
        Milestone("flag_captured", "Submitted the correct flag", 0.50),
    ],
    hints=[
        "Look at the user profile endpoints — are there proper authorization checks?",
        "The GET /api/users/<id> endpoint doesn't check if you own that profile.",
        "The PUT /api/users/<id> endpoint accepts any field — including 'role'.",
    ],
)
