"""
AWS IAM User Auditor

This script audits IAM users across all configured AWS profiles to identify security risks and compliance issues.

Purpose:
- Scan all AWS profiles for IAM users and their security configurations
- Identify users with security issues based on configurable criteria
- Generate comprehensive reports of findings with severity ratings

Key Features:
- Multi-profile support - scans all AWS profiles configured on the system
- Configurable security thresholds
- Detects common IAM security issues:
  - Console access without MFA
  - Admin privileges without proper safeguards
  - Inactive user accounts
  - Old or unused access keys
  - Recently created accounts that need review

Requirements:
- Python 3.6+
- boto3 library
- Valid AWS credentials configured (~/.aws/credentials or ~/.aws/config)
- Appropriate IAM permissions to list and inspect users

Usage:
1. Run the script: python aws_iam_auditor.py
2. Configure security thresholds when prompted (or accept defaults)
3. Review the generated CSV reports:
   - Main report: One line per user with key details
   - Summary report: Only flagged users, sorted by severity
   - Detailed report (optional): Expanded access key information

The script will automatically use AWS profiles configured on your system.
You will need IAM read permissions in each account you wish to audit.

Author: [Andy Davenport]
Version: 1.0
Date: [04-04-25]
"""


import boto3
import csv
import os
import configparser
from datetime import datetime, timedelta, timezone
import json

# Configuration for review criteria - these will be configurable
DEFAULT_CONFIG = {
    'inactive_days_threshold': 90,           # Flag users with no activity for this many days
    'access_key_age_threshold': 90,          # Flag access keys older than this many days
    'unused_key_days_threshold': 90,         # Flag keys not used for this many days
    'check_mfa': True,                       # Check if users with console access have MFA enabled
    'check_admin_privileges': True,          # Check if users have administrator privileges
    'new_user_days_threshold': 7             # Flag newly created users within this many days
}

def list_iam_users(profile_name=None, config=None):
    """Get detailed information about IAM users in the specified AWS profile"""
    # Use default config if none provided
    if config is None:
        config = DEFAULT_CONFIG
    
    # Create IAM client with specific profile if provided
    if profile_name:
        session = boto3.Session(profile_name=profile_name)
        iam = session.client('iam')
    else:
        iam = boto3.client('iam')
    
    # Get current time for age calculations
    current_time = datetime.now(timezone.utc)
    
    # Get list of users
    users = iam.list_users()
    
    user_details = []
    for user in users['Users']:
        username = user['UserName']
        user_id = user['UserId']
        arn = user['Arn']
        create_date = user['CreateDate']
        
        # Get console access and last login date
        login_profile = None
        last_login = 'Never'
        try:
            login_profile = iam.get_login_profile(UserName=username)
            last_login = user.get('PasswordLastUsed', 'Never')
        except iam.exceptions.NoSuchEntityException:
            pass
        
        # Get MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=username)
        has_mfa = 'Yes' if mfa_devices['MFADevices'] else 'No'
        
        # Get access keys and their last used time
        access_keys = iam.list_access_keys(UserName=username)
        has_access_keys = 'Yes' if access_keys['AccessKeyMetadata'] else 'No'
        
        key_details = []
        key_summary = {
            'count': len(access_keys['AccessKeyMetadata']),
            'active_count': 0,
            'inactive_count': 0,
            'oldest_key_age': 0,
            'newest_key_age': 0,
            'days_since_last_use': 'Never'
        }
        
        for key in access_keys['AccessKeyMetadata']:
            key_id = key['AccessKeyId']
            key_status = key['Status']
            key_create_date = key['CreateDate']
            
            # Track active/inactive keys
            if key_status == 'Active':
                key_summary['active_count'] += 1
            else:
                key_summary['inactive_count'] += 1
            
            # Calculate key age
            key_age_days = (current_time - key_create_date.replace(tzinfo=timezone.utc)).days
            key_summary['oldest_key_age'] = max(key_summary['oldest_key_age'], key_age_days)
            if key_summary['newest_key_age'] == 0:
                key_summary['newest_key_age'] = key_age_days
            else:
                key_summary['newest_key_age'] = min(key_summary['newest_key_age'], key_age_days)
            
            # Get last used information for each key
            try:
                key_last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used_date = key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate', 'Never')
                service_name = key_last_used.get('AccessKeyLastUsed', {}).get('ServiceName', 'N/A')
                region = key_last_used.get('AccessKeyLastUsed', {}).get('Region', 'N/A')
                
                # Track most recent use across all keys
                if last_used_date != 'Never':
                    days_since_use = (current_time - last_used_date.replace(tzinfo=timezone.utc)).days
                    if key_summary['days_since_last_use'] == 'Never':
                        key_summary['days_since_last_use'] = days_since_use
                    else:
                        key_summary['days_since_last_use'] = min(key_summary['days_since_last_use'], days_since_use)
                
                key_details.append({
                    'id': key_id,
                    'status': key_status,
                    'create_date': key_create_date,
                    'last_used': last_used_date,
                    'service': service_name,
                    'region': region
                })
            except Exception as e:
                key_details.append({
                    'id': key_id,
                    'status': key_status,
                    'create_date': key_create_date,
                    'last_used': f"Error: {str(e)}",
                    'service': 'Error',
                    'region': 'Error'
                })
        
        # Check if user has admin privileges
        has_admin_privileges = check_admin_privileges(iam, username)
        
        # Add user with current profile name
        user_details.append({
            'profile': profile_name or 'default',
            'username': username,
            'user_id': user_id,
            'arn': arn,
            'create_date': create_date,
            'last_login': last_login,
            'console_access': 'Yes' if login_profile else 'No',
            'has_mfa': has_mfa,
            'has_admin_privileges': has_admin_privileges,
            'has_access_keys': has_access_keys,
            'access_keys': key_details,
            'key_summary': key_summary,
            # Initialize review fields
            'needs_review': 'No',
            'review_reasons': '',
            'review_severity': ''
        })
    
    # Flag users for review based on criteria
    for user in user_details:
        flag_user_for_review(user, current_time, config)
    
    return user_details

def check_admin_privileges(iam, username):
    """Check if a user has administrator privileges"""
    try:
        # Get all policies attached to the user
        attached_policies = iam.list_attached_user_policies(UserName=username)
        
        # Check for admin policy or wildcard permissions
        for policy in attached_policies['AttachedPolicies']:
            if policy['PolicyName'] == 'AdministratorAccess':
                return 'Yes'
            
            # Get policy details
            policy_arn = policy['PolicyArn']
            policy_version = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_document = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_version
            )['PolicyVersion']['Document']
            
            # Check for "*" permissions
            for statement in policy_document.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    action = statement.get('Action', [])
                    if action == '*' or (isinstance(action, list) and '*' in action):
                        if statement.get('Resource') == '*':
                            return 'Yes'
        
        # Check group memberships for admin privileges
        groups = iam.list_groups_for_user(UserName=username)
        for group in groups['Groups']:
            group_name = group['GroupName']
            
            # Check group policies
            attached_group_policies = iam.list_attached_group_policies(GroupName=group_name)
            for policy in attached_group_policies['AttachedPolicies']:
                if policy['PolicyName'] == 'AdministratorAccess':
                    return 'Yes (via group)'
                
                # Could add detailed policy inspection here too
        
        return 'No'
    except Exception as e:
        return f'Error checking: {str(e)}'

def flag_user_for_review(user, current_time, config):
    """Flag user accounts for review based on configurable criteria"""
    review_reasons = []
    severity = 'Low'
    
    # Check if new user account
    if isinstance(user['create_date'], datetime):
        user_age_days = (current_time - user['create_date'].replace(tzinfo=timezone.utc)).days
        if user_age_days <= config['new_user_days_threshold']:
            review_reasons.append(f"Recent creation ({user_age_days} days ago)")
            severity = max(severity, 'Low')
    
    # Check for inactive console users
    if user['console_access'] == 'Yes':
        if user['last_login'] == 'Never':
            review_reasons.append("Console access enabled but never used")
            severity = max(severity, 'Medium')
        elif isinstance(user['last_login'], datetime):
            days_since_login = (current_time - user['last_login'].replace(tzinfo=timezone.utc)).days
            if days_since_login > config['inactive_days_threshold']:
                review_reasons.append(f"Inactive console ({days_since_login} days)")
                severity = max(severity, 'Medium')
        
        # Check MFA
        if config['check_mfa'] and user['has_mfa'] == 'No':
            review_reasons.append("Console access without MFA")
            severity = max(severity, 'High')
    
    # Check admin privileges
    if config['check_admin_privileges'] and 'Yes' in user['has_admin_privileges']:
        review_reasons.append("Has admin privileges")
        if user['has_mfa'] == 'No' and user['console_access'] == 'Yes':
            review_reasons.append("Admin without MFA")
            severity = 'High'
        else:
            severity = max(severity, 'Medium')
    
    # Check access keys
    if user['has_access_keys'] == 'Yes':
        # Old keys
        if user['key_summary']['oldest_key_age'] > config['access_key_age_threshold']:
            review_reasons.append(f"Old access key ({user['key_summary']['oldest_key_age']} days)")
            severity = max(severity, 'Medium')
        
        # Unused keys
        if user['key_summary']['active_count'] > 0:
            if user['key_summary']['days_since_last_use'] == 'Never':
                review_reasons.append("Active key(s) never used")
                severity = max(severity, 'Medium')
            elif isinstance(user['key_summary']['days_since_last_use'], int) and user['key_summary']['days_since_last_use'] > config['unused_key_days_threshold']:
                review_reasons.append(f"Unused key(s) ({user['key_summary']['days_since_last_use']} days)")
                severity = max(severity, 'Medium')
    
    # Set review flags if any reasons found
    if review_reasons:
        user['needs_review'] = 'Yes'
        user['review_reasons'] = '; '.join(review_reasons)
        user['review_severity'] = severity

def get_aws_profiles():
    """Find all available AWS profiles from config files"""
    profiles = ['default']
    
    # Look for AWS credentials file
    credentials_path = os.path.expanduser("~/.aws/credentials")
    config_path = os.path.expanduser("~/.aws/config")
    
    if os.path.exists(credentials_path):
        config = configparser.ConfigParser()
        config.read(credentials_path)
        profiles.extend([s.replace("profile ", "") for s in config.sections() if s != "default"])
    
    if os.path.exists(config_path):
        config = configparser.ConfigParser()
        config.read(config_path)
        profiles.extend([s.replace("profile ", "") for s in config.sections() if s not in profiles and s != "default"])
    
    return list(set(profiles))  # Remove duplicates

def get_user_config():
    """Get user configuration for review thresholds"""
    print("\n--- Review Criteria Configuration ---")
    print("Press Enter to accept default values or enter new values.\n")
    
    config = {}
    config['inactive_days_threshold'] = int(input(f"Days threshold for inactive users [default: {DEFAULT_CONFIG['inactive_days_threshold']}]: ") or DEFAULT_CONFIG['inactive_days_threshold'])
    config['access_key_age_threshold'] = int(input(f"Days threshold for old access keys [default: {DEFAULT_CONFIG['access_key_age_threshold']}]: ") or DEFAULT_CONFIG['access_key_age_threshold'])
    config['unused_key_days_threshold'] = int(input(f"Days threshold for unused access keys [default: {DEFAULT_CONFIG['unused_key_days_threshold']}]: ") or DEFAULT_CONFIG['unused_key_days_threshold'])
    
    check_mfa_input = input(f"Check for MFA on console users [Y/n, default: {'Y' if DEFAULT_CONFIG['check_mfa'] else 'N'}]: ").lower()
    config['check_mfa'] = True if not check_mfa_input or check_mfa_input == 'y' else False
    
    check_admin_input = input(f"Check for admin privileges [Y/n, default: {'Y' if DEFAULT_CONFIG['check_admin_privileges'] else 'N'}]: ").lower()
    config['check_admin_privileges'] = True if not check_admin_input or check_admin_input == 'y' else False
    
    config['new_user_days_threshold'] = int(input(f"Days threshold for flagging new users [default: {DEFAULT_CONFIG['new_user_days_threshold']}]: ") or DEFAULT_CONFIG['new_user_days_threshold'])
    
    print("\nConfiguration saved. Processing users...\n")
    return config

def save_to_csv(all_users):
    """Save user details to CSV file with one line per user"""
    # Ask user for filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"iam_users_{timestamp}.csv"
    filename = input(f"Enter the filename to save IAM users (default: {default_filename}): ") or default_filename
    
    # Define CSV file headers
    headers = [
        'Profile', 'UserName', 'UserId', 'Arn', 'CreateDate', 'LastLogin', 
        'ConsoleAccess', 'HasMFA', 'HasAdminPrivileges', 
        'AccessKeyCount', 'ActiveKeyCount', 'OldestKeyAge', 'DaysSinceLastKeyUse',
        'KeyDetails',  # JSON string with detailed key info
        'NeedsReview', 'ReviewSeverity', 'ReviewReasons'
    ]
    
    # Write to CSV file
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        
        for user in all_users:
            # Format key details as JSON for compact storage
            key_details_json = json.dumps([{
                'id': k['id'],
                'status': k['status'],
                'created': k['create_date'].isoformat() if isinstance(k['create_date'], datetime) else str(k['create_date']),
                'last_used': k['last_used'].isoformat() if isinstance(k['last_used'], datetime) else str(k['last_used']),
                'service': k['service'],
                'region': k['region']
            } for k in user['access_keys']])
            
            row = [
                user['profile'],
                user['username'],
                user['user_id'],
                user['arn'],
                user['create_date'].isoformat() if isinstance(user['create_date'], datetime) else user['create_date'],
                user['last_login'].isoformat() if isinstance(user['last_login'], datetime) else user['last_login'],
                user['console_access'],
                user['has_mfa'],
                user['has_admin_privileges'],
                user['key_summary']['count'],
                user['key_summary']['active_count'],
                user['key_summary']['oldest_key_age'],
                user['key_summary']['days_since_last_use'],
                key_details_json,
                user['needs_review'],
                user['review_severity'],
                user['review_reasons']
            ]
            writer.writerow(row)
    
    print(f"IAM user details saved to {filename}")
    
    # Print summary of flagged users
    flagged_users = [user for user in all_users if user['needs_review'] == 'Yes']
    high_severity = len([u for u in flagged_users if u['review_severity'] == 'High'])
    medium_severity = len([u for u in flagged_users if u['review_severity'] == 'Medium'])
    low_severity = len([u for u in flagged_users if u['review_severity'] == 'Low'])
    
    print(f"\nAudit Summary:")
    print(f"- Total users: {len(all_users)}")
    print(f"- Flagged for review: {len(flagged_users)}")
    print(f"  - High severity: {high_severity}")
    print(f"  - Medium severity: {medium_severity}")
    print(f"  - Low severity: {low_severity}")
    
    return filename

def save_summary_report(all_users, filename_base):
    """Create a separate summary report file with flagged users"""
    summary_filename = f"{filename_base}_summary.csv"
    
    # Filter only flagged users and sort by severity
    flagged_users = [user for user in all_users if user['needs_review'] == 'Yes']
    
    # Define severity order for sorting
    severity_order = {'High': 0, 'Medium': 1, 'Low': 2}
    flagged_users.sort(key=lambda x: severity_order.get(x['review_severity'], 3))
    
    headers = [
        'Profile', 'UserName', 'ConsoleAccess', 'HasMFA', 'HasAdminPrivileges', 
        'AccessKeyCount', 'ActiveKeyCount', 'ReviewSeverity', 'ReviewReasons'
    ]
    
    with open(summary_filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        
        for user in flagged_users:
            row = [
                user['profile'],
                user['username'],
                user['console_access'],
                user['has_mfa'],
                user['has_admin_privileges'],
                user['key_summary']['count'],
                user['key_summary']['active_count'],
                user['review_severity'],
                user['review_reasons']
            ]
            writer.writerow(row)
    
    print(f"Summary report of flagged users saved to {summary_filename}")

def save_detailed_report(all_users, filename_base):
    """Create a detailed report with expanded access key information"""
    detailed_filename = f"{filename_base}_detailed.csv"
    
    headers = [
        'Profile', 'UserName', 'UserId', 'Arn', 'CreateDate', 'LastLogin', 
        'ConsoleAccess', 'HasMFA', 'HasAdminPrivileges', 
        'AccessKeyId', 'KeyStatus', 'KeyCreateDate', 'KeyLastUsed', 'LastUsedService', 'LastUsedRegion',
        'NeedsReview', 'ReviewSeverity', 'ReviewReasons'
    ]
    
    with open(detailed_filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        
        for user in all_users:
            profile = user['profile']
            username = user['username']
            user_id = user['user_id']
            arn = user['arn']
            create_date = user['create_date'].isoformat() if isinstance(user['create_date'], datetime) else user['create_date']
            last_login = user['last_login'].isoformat() if isinstance(user['last_login'], datetime) else user['last_login']
            console_access = user['console_access']
            has_mfa = user['has_mfa']
            has_admin = user['has_admin_privileges']
            needs_review = user['needs_review']
            review_severity = user['review_severity']
            review_reasons = user['review_reasons']
            
            if user['access_keys']:
                for key in user['access_keys']:
                    row = [
                        profile,
                        username,
                        user_id,
                        arn,
                        create_date,
                        last_login,
                        console_access,
                        has_mfa,
                        has_admin,
                        key['id'],
                        key['status'],
                        key['create_date'].isoformat() if isinstance(key['create_date'], datetime) else key['create_date'],
                        key['last_used'].isoformat() if isinstance(key['last_used'], datetime) else key['last_used'],
                        key['service'],
                        key['region'],
                        needs_review,
                        review_severity,
                        review_reasons
                    ]
                    writer.writerow(row)
            else:
                # If no keys, still add user with empty key fields
                row = [
                    profile,
                    username,
                    user_id,
                    arn,
                    create_date, 
                    last_login,
                    console_access,
                    has_mfa,
                    has_admin,
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                    needs_review,
                    review_severity,
                    review_reasons
                ]
                writer.writerow(row)
    
    print(f"Detailed report with expanded access key information saved to {detailed_filename}")

if __name__ == "__main__":
    all_user_details = []
    profiles = get_aws_profiles()
    
    print(f"Found {len(profiles)} AWS profiles: {', '.join(profiles)}")
    
    # Get user configuration
    user_config = get_user_config()
    
    for profile in profiles:
        print(f"Processing profile: {profile}")
        try:
            users = list_iam_users(profile, user_config)
            print(f"Found {len(users)} users in profile {profile}")
            all_user_details.extend(users)
        except Exception as e:
            print(f"Error processing profile {profile}: {str(e)}")
    
    if all_user_details:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"iam_users_{timestamp}"
        filename_base = input(f"Enter base filename for reports (default: {default_filename}): ") or default_filename
        
        # Save main report with one line per user
        save_to_csv(all_user_details)
        
        # Save summary report with just flagged users
        save_summary_report(all_user_details, filename_base)
        
        # Ask if user wants detailed report with expanded access key info
        detailed_report = input("\nDo you want to generate a detailed report with one line per access key? (y/N): ").lower()
        if detailed_report == 'y':
            save_detailed_report(all_user_details, filename_base)
    else:
        print("No IAM users found in any profiles.")
        
