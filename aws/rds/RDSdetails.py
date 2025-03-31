'''
AWS RDS Inventory Script

This script retrieves details of RDS instances across multiple AWS accounts and regions.
It reads AWS profiles from the local credentials file, extracts associated account names
from comments, and queries each account for available RDS instances. The collected data
(account name, profile, region, instance ID, engine type, and version) is saved in a CSV file.

Dependencies:
- boto3
- botocore
- csv

Output:
- Generates 'rds_instances.csv' with RDS instance details.
'''

import boto3
import botocore
import csv
import os
import configparser

def get_aws_profiles_with_names():
    credentials_file = os.path.expanduser("~/.aws/credentials")
    profiles_with_names = {}
    
    if os.path.exists(credentials_file):
        with open(credentials_file, "r") as f:
            lines = f.readlines()
        
        profile_name = None
        account_name = None
        
        for line in lines:
            line = line.strip()
            if line.startswith("#"):  # Comment line with account name
                account_name = line.lstrip("#").strip()
            elif line.startswith("[") and "]" in line:  # Profile section
                profile_name = line.strip("[]").strip()
                if profile_name and account_name:
                    profiles_with_names[profile_name] = account_name
                account_name = None  # Reset for next profile
    
    return profiles_with_names

def get_regions(session):
    try:
        ec2_client = session.client('ec2')
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except botocore.exceptions.BotoCoreError as e:
        print(f"Error retrieving regions: {e}")
        return []

def get_rds_instances(session, region, profile, account_name, csv_writer):
    rds_client = session.client('rds', region_name=region)
    
    try:
        response = rds_client.describe_db_instances()
        instances = response.get('DBInstances', [])
        
        if not instances:
            print(f"No RDS instances found in region {region}.")
            return
        
        print(f"RDS Instances in {region} for profile {profile} ({account_name}):")
        for instance in instances:
            db_instance_id = instance.get('DBInstanceIdentifier', 'N/A')
            engine = instance.get('Engine', 'N/A')
            engine_version = instance.get('EngineVersion', 'N/A')
            
            print(f"Instance ID: {db_instance_id}")
            print(f"Engine: {engine}")
            print(f"Engine Version: {engine_version}")
            print("-------------------------")
            
            csv_writer.writerow([account_name, profile, region, db_instance_id, engine, engine_version])
    
    except Exception as e:
        print(f"Error retrieving RDS instances in region {region}: {e}")

if __name__ == "__main__":
    profiles_with_names = get_aws_profiles_with_names()
    
    with open("rds_instances.csv", mode="w", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow(["Account Name", "Profile", "Region", "Instance ID", "Engine", "Engine Version"])
        
        for profile, account_name in profiles_with_names.items():
            print(f"Switching to AWS profile: {profile} ({account_name})")
            
            try:
                session = boto3.Session(profile_name=profile)
                regions = get_regions(session)
                
                if not regions:
                    print(f"No regions found for profile {profile}, using default region us-east-1.")
                    regions = ["us-east-1"]
                
                for region in regions:
                    get_rds_instances(session, region, profile, account_name, csv_writer)
            except botocore.exceptions.BotoCoreError as e:
                print(f"Error accessing AWS account with profile {profile}: {e}")
