import boto3
import subprocess
import configparser
import os
import json

"""
AWS SSO Credential Manager
--------------------------------
This script automates logging into AWS SSO, retrieving temporary credentials for multiple accounts and roles, 
and updating the ~/.aws/credentials file.

### Prerequisites:
1. Install AWS CLI:
   - https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html

2. Configure AWS SSO:
   Run the following command and follow the prompts:
   "aws configure sso"
   enter your AWS SSO start url (found in AWS SSO settings, its the page you use to login)
   Choose the region you're SSO is setup in
   When it says SSO registration scopes, press enter. It will launch a web page to auth with AWS
   Select any of the accounts listed
   When asked for a profile name, give your profile and easy to remember name

   Set the AWS_SSO_PROFILE to the name you specified above.
   Run the python script and follow the prompts

This script prevents duplicate credentials and updates existing ones.
"""


AWS_SSO_PROFILE = "clearer"  # Update with your actual AWS SSO profile name
CREDENTIALS_FILE = os.path.expanduser("~/.aws/credentials")

# Step 1: Log into AWS SSO (if not already authenticated)
def aws_sso_login(profile):
    print(f"Logging into AWS SSO for profile: {profile}...")
    subprocess.run(["aws", "sso", "login", "--profile", profile], check=True)

# Step 2: Retrieve SSO access token from AWS cache
def get_sso_access_token(profile):
    token_cache_path = os.path.expanduser("~/.aws/sso/cache/")
    for file in os.listdir(token_cache_path):
        if file.endswith(".json"):
            with open(os.path.join(token_cache_path, file), "r") as f:
                token_data = json.load(f)
                return token_data.get("accessToken")
    raise RuntimeError("SSO token not found. Ensure you are logged in.")

# Step 3: List available AWS accounts
def get_sso_accounts(sso_client, access_token):
    return sso_client.list_accounts(accessToken=access_token)["accountList"]

# Step 4: Let the user select accounts and roles
def select_accounts_and_roles(sso_client, access_token, accounts):
    selected_roles = []
    
    print("\nAvailable AWS Accounts and Roles:")
    for i, account in enumerate(accounts):
        print(f"  [{i}] {account['accountId']} - {account['accountName']}")
    
    selected_indexes = input("\nEnter the indexes of the accounts you want to use (comma-separated, or press Enter to select all): ").strip()

    if not selected_indexes:
        selected_indexes = list(range(len(accounts)))  # Select all accounts
    else:
        selected_indexes = [int(idx.strip()) for idx in selected_indexes.split(",")]

    for idx in selected_indexes:
        account = accounts[idx]
        account_id = account["accountId"]
        account_name = account["accountName"]
        roles = sso_client.list_account_roles(accessToken=access_token, accountId=account_id)["roleList"]

        print(f"\nRoles for {account_id} ({account_name}):")
        for j, role in enumerate(roles):
            print(f"  [{j}] {role['roleName']}")

        role_index = int(input(f"Select a role index for {account_id}: "))
        selected_roles.append((account_id, account_name, roles[role_index]["roleName"]))
    
    return selected_roles

# Step 5: Fetch and update AWS credentials
def update_aws_credentials(sso_client, access_token, selected_roles):
    config = configparser.ConfigParser()
    
    # Read existing credentials file if it exists
    if os.path.exists(CREDENTIALS_FILE):
        config.read(CREDENTIALS_FILE)

    updated_profiles = set()

    for account_id, account_name, role_name in selected_roles:
        credentials = sso_client.get_role_credentials(
            accessToken=access_token,
            accountId=account_id,
            roleName=role_name
        )["roleCredentials"]

        profile_name = f"{account_id}-{role_name}"
        updated_profiles.add(profile_name)

        # Update or add credentials
        config[profile_name] = {
            "# AWS Account": account_name,  # Store account name in a comment
            "aws_access_key_id": credentials["accessKeyId"],
            "aws_secret_access_key": credentials["secretAccessKey"],
            "aws_session_token": credentials["sessionToken"]
        }

        print(f"✅ Credentials updated for profile: {profile_name} ({account_name})")

    # Write back updated credentials
    with open(CREDENTIALS_FILE, "w") as configfile:
        config.write(configfile, space_around_delimiters=False)  # Preserve formatting

    print("\n✅ AWS credentials file updated successfully.")

# Main execution
aws_sso_login(AWS_SSO_PROFILE)
session = boto3.Session(profile_name=AWS_SSO_PROFILE)
sso_client = session.client("sso")

access_token = get_sso_access_token(AWS_SSO_PROFILE)
accounts = get_sso_accounts(sso_client, access_token)
selected_roles = select_accounts_and_roles(sso_client, access_token, accounts)
update_aws_credentials(sso_client, access_token, selected_roles)
