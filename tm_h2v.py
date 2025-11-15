#!/usr/bin/env python3

from pytm import (
 TM,
 Actor,
 Boundary,
 Classification,
 Data,
 Dataflow,
 Datastore,
 Server,
 DatastoreType,
 Assumption,
)

# Initialize threat model
tm = TM("How2validate - API Secret Validation Tool")
tm.description = """How2validate is an open-source command-line tool and backend service designed to help 
developers, security engineers, and organizations validate API keys, secrets, and credentials across 
multiple third-party providers. Its primary purpose is to detect misconfigured, inactive, or compromised 
API tokens before they are used in production.

The system provides secret validation via provider APIs, automated GitHub/Firebase-based user onboarding, 
API token generation with rate limits, scheduled cleanup of inactive data, and optional email notifications."""

tm.isOrdered = True
tm.mergeResponses = True
tm.assumptions = [
 "All communication takes place over HTTPS/TLS",
 "Secrets are never logged or stored beyond validation output",
 "MongoDB Atlas provides encryption at rest and VPC isolation",
 "Firebase handles secure authentication and token management",
 "GitHub Actions runners are trusted for CI/CD automation",
 "IP allowlists and firewall rules restrict unauthorized access",
 "Sensitive data is encrypted and deleted after 90-day inactivity window",
]

# ============================================================================
# SECURITY BOUNDARIES
# ============================================================================

internet = Boundary("Public Internet")
internet.levels = [1]

github_cloud = Boundary("GitHub Cloud")
github_cloud.levels = [1]

firebase_cloud = Boundary("Firebase Cloud (Google Cloud)")
firebase_cloud.levels = [1]

mongodb_cloud = Boundary("MongoDB Atlas Cloud")
mongodb_cloud.levels = [2]

local_environment = Boundary("Local Developer Environment")
local_environment.levels = [1]

api_backend = Boundary("API Backend (Cloud Infrastructure)")
api_backend.levels = [2]

provider_apis = Boundary("Third-Party Provider APIs")
provider_apis.levels = [1]

# ============================================================================
# ACTORS (Users & External Entities)
# ============================================================================

developer_user = Actor("Developer/User")
developer_user.inBoundary = local_environment
developer_user.levels = [1]

security_engineer = Actor("Security Engineer")
security_engineer.inBoundary = local_environment
security_engineer.levels = [1]

github_runner = Actor("GitHub Actions Runner")
github_runner.inBoundary = github_cloud
github_runner.levels = [1]

attacker_external = Actor("External Attacker")
attacker_external.inBoundary = internet
attacker_external.levels = [1]

# ============================================================================
# SERVERS & SERVICES
# ============================================================================

cli_tool = Server("How2validate CLI")
cli_tool.inBoundary = local_environment
cli_tool.OS = "Multi-platform (Node.js)"
cli_tool.controls.sanitizesInput = True
cli_tool.controls.encodesOutput = True
cli_tool.controls.isHardened = True
cli_tool.levels = [1]

api_gateway = Server("API Gateway")
api_gateway.inBoundary = api_backend
api_gateway.OS = "Node.js/Express"
api_gateway.controls.isHardened = True
api_gateway.controls.sanitizesInput = True
api_gateway.controls.encodesOutput = True
api_gateway.controls.authorizesSource = True
api_gateway.levels = [2]

auth_service = Server("Authentication Service (Firebase Auth)")
auth_service.inBoundary = firebase_cloud
auth_service.OS = "Managed Service"
auth_service.controls.isHardened = True
auth_service.controls.authorizesSource = True
auth_service.levels = [2]

validation_service = Server("Secret Validation Service")
validation_service.inBoundary = api_backend
validation_service.OS = "Node.js/Express"
validation_service.controls.isHardened = True
validation_service.controls.sanitizesInput = True
validation_service.levels = [2]

token_service = Server("API Token Management Service")
token_service.inBoundary = api_backend
token_service.OS = "Node.js/Express"
token_service.controls.isHardened = True
token_service.controls.authorizesSource = True
token_service.levels = [2]

cleanup_service = Server("Automated Cleanup Service")
cleanup_service.inBoundary = api_backend
cleanup_service.OS = "Node.js/Scheduled Job"
cleanup_service.controls.isHardened = True
cleanup_service.levels = [2]

notification_service = Server("Email Notification Service (ZeptoMail)")
notification_service.inBoundary = internet
notification_service.OS = "Managed Service"
notification_service.controls.isHardened = True
notification_service.levels = [1]

provider_validators = Server("Third-Party Provider APIs")
provider_validators.inBoundary = provider_apis
provider_validators.OS = "External APIs (AWS, GCP, GitHub, OpenAI, DigitalOcean)"
provider_validators.controls.isHardened = True
provider_validators.levels = [1]

# ============================================================================
# DATASTORES
# ============================================================================

user_db = Datastore("User Account Database")
user_db.OS = "MongoDB Atlas"
user_db.type = DatastoreType.SQL
user_db.inBoundary = mongodb_cloud
user_db.controls.isHardened = True
user_db.inScope = True
user_db.maxClassification = Classification.TOP_SECRET
user_db.storesPII = True
user_db.levels = [2]

api_token_db = Datastore("API Token Store")
api_token_db.OS = "MongoDB Atlas"
api_token_db.type = DatastoreType.SQL
api_token_db.inBoundary = mongodb_cloud
api_token_db.controls.isHardened = True
api_token_db.inScope = True
api_token_db.maxClassification = Classification.RESTRICTED
api_token_db.levels = [2]

validation_log_db = Datastore("Validation Results Log")
validation_log_db.OS = "MongoDB Atlas"
validation_log_db.type = DatastoreType.SQL
validation_log_db.inBoundary = mongodb_cloud
validation_log_db.inScope = True
validation_log_db.maxClassification = Classification.TOP_SECRET
validation_log_db.levels = [2]

usage_metrics_db = Datastore("Usage Metrics & Analytics")
usage_metrics_db.OS = "MongoDB Atlas"
usage_metrics_db.type = DatastoreType.SQL
usage_metrics_db.inBoundary = mongodb_cloud
usage_metrics_db.controls.isHardened = True
usage_metrics_db.inScope = True
usage_metrics_db.maxClassification = Classification.RESTRICTED
usage_metrics_db.levels = [2]

# ============================================================================
# DATA DEFINITIONS
# ============================================================================

github_oauth_token = Data(
 "GitHub OAuth Token & User Identity",
 description="GitHub username, email, avatar, OAuth access token",
 classification=Classification.TOP_SECRET
)

api_key_input = Data(
 "API Keys for Validation",
 description="Secrets submitted for validation (AWS keys, GCP tokens, GitHub tokens, OpenAI keys, etc.)",
 classification=Classification.RESTRICTED
)

validation_request = Data(
 "Validation Request",
 description="API request containing secret to validate and provider type",
 classification=Classification.RESTRICTED
)

validation_result = Data(
 "Validation Result",
 description="Provider response indicating if secret is valid, active, or compromised",
 classification=Classification.TOP_SECRET
)

user_id_token = Data(
 "Firebase ID Token",
 description="JWT token for user authentication and authorization",
 classification=Classification.TOP_SECRET
)

api_token = Data(
 "Generated API Token",
 description="Hashed API token issued to user for accessing How2validate backend",
 classification=Classification.RESTRICTED
)

user_profile = Data(
 "User Profile Data",
 description="GitHub username, email, avatar, account metadata",
 classification=Classification.TOP_SECRET
)

rate_limit_metadata = Data(
 "Rate Limit & Usage Metadata",
 description="Request counts, rate limit status, usage analytics",
 classification=Classification.RESTRICTED
)

cleanup_signal = Data(
 "Cleanup Trigger Signal",
 description="Scheduled job signal to delete inactive records after 90 days",
 classification=Classification.RESTRICTED
)

email_notification = Data(
 "Email Notification",
 description="Optional email sent to user about validation results",
 classification=Classification.TOP_SECRET
)

# ============================================================================
# DATAFLOWS - USER AUTHENTICATION & ONBOARDING
# ============================================================================

# Developer initiates GitHub OAuth login
dev_to_github_oauth = Dataflow(developer_user, github_runner, "GitHub OAuth Login")
dev_to_github_oauth.protocol = "HTTPS"
dev_to_github_oauth.dstPort = 443
dev_to_github_oauth.data = github_oauth_token
dev_to_github_oauth.note = "Developer authenticates via GitHub"
dev_to_github_oauth.levels = [1]

# GitHub OAuth callback to Firebase
github_to_firebase = Dataflow(github_runner, auth_service, "GitHub OAuth Callback")
github_to_firebase.protocol = "HTTPS"
github_to_firebase.dstPort = 443
github_to_firebase.data = github_oauth_token
github_to_firebase.note = "GitHub forwards OAuth token to Firebase"
github_to_firebase.levels = [1]

# Firebase issues ID token
firebase_to_api = Dataflow(auth_service, api_gateway, "Firebase ID Token Issued")
firebase_to_api.protocol = "HTTPS"
firebase_to_api.dstPort = 443
firebase_to_api.data = user_id_token
firebase_to_api.note = "Firebase authentication service issues JWT"
firebase_to_api.levels = [2]

# API stores user profile in MongoDB
api_to_user_db = Dataflow(api_gateway, user_db, "Store User Profile")
api_to_user_db.protocol = "MongoDB/TLS"
api_to_user_db.dstPort = 27017
api_to_user_db.data = user_profile
api_to_user_db.note = "User profile stored with encryption at rest"
api_to_user_db.levels = [2]

# ============================================================================
# DATAFLOWS - API TOKEN GENERATION
# ============================================================================

# API issues new token to user
api_to_cli_token = Dataflow(api_gateway, cli_tool, "Issue API Token")
api_to_cli_token.protocol = "HTTPS"
api_to_cli_token.dstPort = 443
api_to_cli_token.data = api_token
api_to_cli_token.note = "Hashed API token issued with rate limit enforcement"
api_to_cli_token.levels = [1, 2]

# API stores hashed token in database
api_to_token_db = Dataflow(token_service, api_token_db, "Store Hashed API Token")
api_to_token_db.protocol = "MongoDB/TLS"
api_to_token_db.dstPort = 27017
api_to_token_db.data = api_token
api_to_token_db.note = "Only hashed tokens stored, never plaintext secrets"
api_to_token_db.levels = [2]

# ============================================================================
# DATAFLOWS - SECRET VALIDATION FLOW
# ============================================================================

# Developer uses CLI to validate secret
dev_to_cli = Dataflow(developer_user, cli_tool, "Submit Secret for Validation")
dev_to_cli.protocol = "Local Command"
dev_to_cli.data = api_key_input
dev_to_cli.note = "Developer invokes CLI with secret to validate"
dev_to_cli.levels = [1]

# CLI sends validation request to API gateway
cli_to_api_gateway = Dataflow(cli_tool, api_gateway, "Validation Request")
cli_to_api_gateway.protocol = "HTTPS"
cli_to_api_gateway.dstPort = 443
cli_to_api_gateway.data = validation_request
cli_to_api_gateway.note = "CLI authenticates with API token, sends secret for validation"
cli_to_api_gateway.levels = [1, 2]

# API gateway routes to validation service
api_to_validation = Dataflow(api_gateway, validation_service, "Route Validation Request")
api_to_validation.protocol = "Internal gRPC/HTTPS"
api_to_validation.data = validation_request
api_to_validation.note = "Internal service routing with input sanitization"
api_to_validation.levels = [2]

# Validation service calls third-party provider API
validation_to_provider = Dataflow(validation_service, provider_validators, "Call Provider API")
validation_to_provider.protocol = "HTTPS"
validation_to_provider.dstPort = 443
validation_to_provider.data = api_key_input
validation_to_provider.note = "Sends secret only to respective provider for validation"
validation_to_provider.levels = [1, 2]

# Provider returns validation result
provider_to_validation = Dataflow(provider_validators, validation_service, "Validation Response")
provider_to_validation.protocol = "HTTPS"
provider_to_validation.dstPort = 443
provider_to_validation.data = validation_result
provider_to_validation.note = "Provider confirms if secret is valid, active, or compromised"
provider_to_validation.responseTo = validation_to_provider
provider_to_validation.levels = [1, 2]

# Validation service stores result in database
validation_to_db = Dataflow(validation_service, validation_log_db, "Store Validation Result")
validation_to_db.protocol = "MongoDB/TLS"
validation_to_db.dstPort = 27017
validation_to_db.data = validation_result
validation_to_db.note = "Result stored without storing the original secret"
validation_to_db.levels = [2]

# Validation result returned to API gateway
validation_to_api = Dataflow(validation_service, api_gateway, "Return Result")
validation_to_api.protocol = "Internal gRPC/HTTPS"
validation_to_api.data = validation_result
validation_to_api.note = "Encoded response returned to API"
validation_to_api.levels = [2]

# API returns result to CLI
api_to_cli_result = Dataflow(api_gateway, cli_tool, "Validation Result")
api_to_cli_result.protocol = "HTTPS"
api_to_cli_result.dstPort = 443
api_to_cli_result.data = validation_result
api_to_cli_result.note = "CLI receives structured validation result"
api_to_cli_result.responseTo = cli_to_api_gateway
api_to_cli_result.levels = [1, 2]

# CLI displays result to developer
cli_to_dev_result = Dataflow(cli_tool, developer_user, "Display Validation Result")
cli_to_dev_result.protocol = "Console Output"
cli_to_dev_result.data = validation_result
cli_to_dev_result.note = "User sees validation outcome"
cli_to_dev_result.responseTo = dev_to_cli
cli_to_dev_result.levels = [1]

# ============================================================================
# DATAFLOWS - USAGE TRACKING
# ============================================================================

# API tracks usage metrics
api_to_metrics_db = Dataflow(api_gateway, usage_metrics_db, "Log Usage Metrics")
api_to_metrics_db.protocol = "MongoDB/TLS"
api_to_metrics_db.dstPort = 27017
api_to_metrics_db.data = rate_limit_metadata
api_to_metrics_db.note = "Request count, rate limits, user analytics tracked"
api_to_metrics_db.levels = [2]

# ============================================================================
# DATAFLOWS - OPTIONAL EMAIL NOTIFICATIONS
# ============================================================================

# Validation service sends notification request
validation_to_notification = Dataflow(validation_service, notification_service, "Send Notification Email")
validation_to_notification.protocol = "HTTPS/SMTP"
validation_to_notification.dstPort = 443
validation_to_notification.data = email_notification
validation_to_notification.note = "Optional email sent via ZeptoMail"
validation_to_notification.levels = [1, 2]

# Email service sends notification to user
notification_to_dev = Dataflow(notification_service, developer_user, "Email Notification")
notification_to_dev.protocol = "SMTP"
notification_to_dev.dstPort = 25
notification_to_dev.data = email_notification
notification_to_dev.note = "Email received by developer with validation summary"
notification_to_dev.levels = [1]

# ============================================================================
# DATAFLOWS - AUTOMATED CLEANUP (90-day inactivity)
# ============================================================================

# Scheduled cleanup job triggers
cleanup_trigger = Dataflow(cleanup_service, api_token_db, "Delete Inactive Tokens")
cleanup_trigger.protocol = "MongoDB/TLS"
cleanup_trigger.dstPort = 27017
cleanup_trigger.data = cleanup_signal
cleanup_trigger.note = "Scheduled job deletes records inactive for 90+ days"
cleanup_trigger.levels = [2]

# Cleanup job deletes validation logs
cleanup_logs = Dataflow(cleanup_service, validation_log_db, "Purge Old Validation Logs")
cleanup_logs.protocol = "MongoDB/TLS"
cleanup_logs.dstPort = 27017
cleanup_logs.data = cleanup_signal
cleanup_logs.note = "Automated deletion of aged validation records"
cleanup_logs.levels = [2]

# ============================================================================
# DATA TRAVERSAL & PROCESSING
# ============================================================================

# API key data traverses through multiple flows
api_key_traversal = Data(
 name="API Key Validation Data Flow",
 description="Complete journey of API key from user through validation pipeline",
 classification=Classification.RESTRICTED,
 traverses=[dev_to_cli, cli_to_api_gateway, api_to_validation, validation_to_provider, 
 provider_to_validation, validation_to_api, api_to_cli_result, cli_to_dev_result],
 processedBy=[cli_tool, api_gateway, validation_service, provider_validators]
)

# Sensitive user authentication flow
auth_flow = Data(
 name="User Authentication & Token Flow",
 description="GitHub OAuth through Firebase authentication to API token generation",
 classification=Classification.TOP_SECRET,
 traverses=[dev_to_github_oauth, github_to_firebase, firebase_to_api, api_to_cli_token],
 processedBy=[auth_service, api_gateway, token_service]
)

if __name__ == "__main__":
 tm.process()