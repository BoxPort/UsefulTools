"""
AWS Parameter Store Security Manager
==================================

This script manages AWS Systems Manager Parameter Store parameters with a focus on security.
It identifies non-secure parameters and provides options to convert them to secure parameters.

Key Features:
------------
1. AWS Profile Support:
   - Lists and validates available AWS profiles
   - Supports multiple AWS accounts via profile selection
   - Validates AWS credentials before operations

2. Parameter Store Operations:
   - Identifies all non-secure (String type) parameters in a region
   - Exports parameter names and values to Excel for review
   - Optional conversion of non-secure parameters to SecureString type

3. Security Features:
   - Credential validation before operations
   - Confirmation prompts before sensitive actions
   - Logging of all operations and errors
   - Support for AWS KMS encryption via SecureString conversion

Usage:
------
1. Run the script
2. Select AWS profile (or use default credentials)
3. Specify AWS region (defaults to eu-west-1)
4. Choose whether to convert parameters to secure
5. Review generated Excel file with parameter details

Requirements:
------------
- Python 3.6+
- boto3
- pandas
- openpyxl (for Excel support)

AWS Permissions Required:
-----------------------
- ssm:DescribeParameters
- ssm:GetParameter
- ssm:PutParameter
- sts:GetCallerIdentity (for credential validation)
"""


import boto3
import pandas as pd
import logging
from typing import List, Tuple, Optional
from botocore.exceptions import ClientError, ProfileNotFound, InvalidConfigError
from botocore.session import Session
from boto3.session import Session as Boto3Session

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AWSCredentialValidator:
    @staticmethod
    def validate_credentials(profile_name: Optional[str] = None) -> Boto3Session:
        """
        Validate AWS credentials and return a boto3 session if valid.
        Raises exception if credentials are invalid.
        """
        try:
            session = boto3.Session(profile_name=profile_name)
            # Test credentials by making a simple API call
            sts = session.client('sts')
            sts.get_caller_identity()
            logger.info(f"Successfully validated credentials{f' for profile {profile_name}' if profile_name else ''}")
            return session
        except ProfileNotFound:
            logger.error(f"AWS profile '{profile_name}' not found")
            raise
        except ClientError as e:
            logger.error(f"Invalid AWS credentials: {e}")
            raise
        except Exception as e:
            logger.error(f"Error validating AWS credentials: {e}")
            raise

    @staticmethod
    def list_available_profiles() -> List[str]:
        """List all available AWS profiles."""
        try:
            session = Session()
            return session.available_profiles
        except Exception as e:
            logger.error(f"Error listing AWS profiles: {e}")
            return []

class ParameterStoreManager:
    def __init__(self, region_name: str = 'eu-west-1', profile_name: Optional[str] = None):
        """
        Initialize Parameter Store Manager with optional profile name.
        """
        self.session = AWSCredentialValidator.validate_credentials(profile_name)
        self.ssm = self.session.client('ssm', region_name=region_name)
        self.paginator = self.ssm.get_paginator('describe_parameters')
        self.region_name = region_name
        self.profile_name = profile_name

    def get_non_secure_parameters(self) -> List[Tuple[str, str]]:
        """Retrieve all non-secure parameters from Parameter Store."""
        non_secure_parameters = []
        try:
            for page in self.paginator.paginate():
                for param in page['Parameters']:
                    if param['Type'] == 'String':
                        try:
                            value = self.ssm.get_parameter(
                                Name=param['Name'], 
                                WithDecryption=False
                            )
                            non_secure_parameters.append(
                                (param['Name'], value['Parameter']['Value'])
                            )
                        except ClientError as e:
                            logger.error(f"Error getting parameter {param['Name']}: {e}")
        except ClientError as e:
            logger.error(f"Error accessing Parameter Store: {e}")
            raise

        return non_secure_parameters

    def convert_to_secure_parameters(self, parameters: List[Tuple[str, str]]) -> None:
        """Convert specified parameters to SecureString type."""
        for name, value in parameters:
            try:
                self.ssm.put_parameter(
                    Name=name,
                    Value=value,
                    Type='SecureString',
                    Overwrite=True
                )
                logger.info(f"Successfully converted {name} to SecureString")
            except ClientError as e:
                logger.error(f"Error converting parameter {name}: {e}")

def save_to_excel(parameters: List[Tuple[str, str]], filename: str) -> None:
    """Save parameters to Excel file."""
    try:
        df = pd.DataFrame(parameters, columns=['Parameter', 'Value'])
        df.to_excel(filename, index=False)
        logger.info(f"Parameters saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving to Excel: {e}")
        raise

def select_aws_profile() -> Optional[str]:
    """Interactive profile selection."""
    available_profiles = AWSCredentialValidator.list_available_profiles()
    
    if not available_profiles:
        logger.info("No AWS profiles found. Using default credentials.")
        return None

    print("\nAvailable AWS profiles:")
    for i, profile in enumerate(available_profiles, 1):
        print(f"{i}. {profile}")
    print(f"{len(available_profiles) + 1}. Use default credentials")

    while True:
        try:
            choice = int(input("\nSelect profile number: "))
            if 1 <= choice <= len(available_profiles):
                return available_profiles[choice - 1]
            elif choice == len(available_profiles) + 1:
                return None
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")

def main():
    try:
        # Select AWS profile
        profile_name = select_aws_profile()

        # Select region
        region = input("Enter AWS region (press Enter for eu-west-1): ").strip() or 'eu-west-1'

        # Initialize manager with selected profile
        manager = ParameterStoreManager(region_name=region, profile_name=profile_name)
        
        # Get confirmation from user
        while True:
            makesecure = input('Change values to secure (Y/N)? ').lower()
            if makesecure in ['y', 'n']:
                break
            print("Please enter 'Y' or 'N'")

        # Get parameters
        parameters = manager.get_non_secure_parameters()

        if not parameters:
            logger.info("No non-secure parameters found")
            return

        print("\nNon-secure parameters:")
        for name, value in parameters:
            print(f"{name}: {value}")
        # Save to Excel
        save_to_excel(parameters, 'non_secure_parameters.xlsx')

        # Convert to secure if requested
        if makesecure == 'y':
            confirm = input('This action will convert all listed parameters to SecureString. Continue? (Y/N) ').lower()
            if confirm == 'y':
                manager.convert_to_secure_parameters(parameters)
            else:
                logger.info("Conversion cancelled")

    except Exception as e:
        logger.error(f"Script failed: {e}")

if __name__ == "__main__":
    main()
