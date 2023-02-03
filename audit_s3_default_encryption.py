# Import modules.
import sys
import boto3
from botocore.exceptions import ClientError
import time
import os
import csv
import json
from re import search




regions_str = 'us-east-1,us-east-2,us-west-1,us-west-2,af-south-1,ap-east-1,ap-south-1,ap-south-2,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ca-central-1,eu-central-1,eu-central-2,eu-west-1,eu-west-2,eu-west-3,eu-south-1,eu-south-2,eu-north-1,me-south-1,me-central-1,sa-east-1'
regions = regions_str.split(",")


# Define the report output location
bucketEncryptionReport = (
    'C:/users/neilmeht/Desktop/bucketEncryptionReport_'+time.strftime("%Y%m%d-%H%M%S")+'.csv'
)

#Create empty output files to store report.
open(bucketEncryptionReport, "a").close()


# Create function to handle client errors (4xx errors).
def is_client_error(code):
    e = sys.exc_info()[1]
    if isinstance(e, ClientError) and e.response["Error"]["Code"] == code:
        return ClientError
    return type("NeverEverRaisedException", (Exception,), {})

###################################################################################################################
#### This Functions will print the data. ####
###################################################################################################################
def report_info(file_name, details):
    print(
        details,
        file=open(file_name, "a"),
    )


###################################################################################################################
#### Print buckets that are configured with SSE-KMS (AWS Managed & Customer Managed) encryption keys.. ####
###################################################################################################################


def sse_kms_bucket_logger():

    # Initialize S3 client.
    s3 = boto3.client("s3")
    # List all buckets in the account.
    response = s3.list_buckets()
    # Get the bucket name from the response
    buckets = response.get("Buckets")
    # Create a for loop to peform an action on all the buckets in the account.
    report_dict = []
    for bucket in buckets:
        myBuckets = bucket.get("Name")
        #sets s3 client region depending on the bucket
        response = s3.get_bucket_location(Bucket=myBuckets)
        location=response['LocationConstraint']
        s3 = boto3.client('s3', region_name=location)
        endpointUrl = s3.meta.endpoint_url
        s3 = boto3.client('s3', endpoint_url=endpointUrl, region_name=location)

        # Print buckets that are configured with SSE-KMS (AWS Managed & Customer Managed) encryption keys.

        try:
            resp = s3.get_bucket_encryption(Bucket=myBuckets)
            kms_key = resp["ServerSideEncryptionConfiguration"]["Rules"][0][
                "ApplyServerSideEncryptionByDefault"
            ]["KMSMasterKeyID"]
            bucketKey = str(
                resp["ServerSideEncryptionConfiguration"]["Rules"][0][
                    "BucketKeyEnabled"
                ]
            )
            for region in regions:
                # Create variables for regional KMS Key ARNs:
                key_region_arn = "arn:aws:kms:{0}".format(region)
                if kms_key.startswith(key_region_arn):
                    data = {
                        "region": region,
                        "bucket": myBuckets,
                        "kmsKey": kms_key,
                        "bucketStatus": bucketKey,
                    }
                    report_dict.append(data)
        except KeyError as b:
            # Print buckets that are configured with SSE-S3 (AES256) encryption keys.
            sse_type = resp["ServerSideEncryptionConfiguration"]["Rules"][0][
                "ApplyServerSideEncryptionByDefault"
            ]["SSEAlgorithm"]
            report_info(
                bucketEncryptionReport,
                "{0}, {1}, {2}".format(myBuckets, sse_type, "N/A"),
            )
        except is_client_error("AccessDenied"):
            # Print buckets that threw a HTTP 403 AccessDenied error when making the GetBucketEncryption API call.
            report_info(
                bucketEncryptionReport,
                "{0}, {1}, {2}".format(myBuckets, "AccessDenied", "Unknown"),
            )
        except is_client_error("ServerSideEncryptionConfigurationNotFoundError"):
            # Print buckets where no Default Encryption Configurations were found.
            report_info(
                bucketEncryptionReport,
                "{0}, {1}, {2}".format(myBuckets, "SSEConfigNotFound", "N/A"),
            )
        except is_client_error("IllegalLocationConstraintException"):
            # Print buckets that threw an IllegalLocationConstraint error when making the GetBucketEncryptionAPI call.
            report_info(
                bucketEncryptionReport,
                "{0}, {1}, {2}".format(
                    myBuckets, "IllegalLocationConstraintException", "N/A"
                ),
            )

    return report_dict


###################################################################################################################
#### This Functions will check to see if the KMS Key is an AWS Managed KMS Key or a Customer Managed KMS Key. ####
###################################################################################################################


def key_type_check(reported_data, kms,region):
    for item in reported_data:
        # Provide a title for each row.
        if region == item["region"]:
            bucket = item["bucket"]
            KMS_Key = item["kmsKey"]
            bucketKeyStatus = item["bucketStatus"]

            try:
                response = kms.describe_key(KeyId=KMS_Key)
                key_type = response["KeyMetadata"]["KeyManager"]
                # print(bucket+', '+KMS_Key+', '+key_type+', '+bucketKeyStatus)
                report_info(
                    bucketEncryptionReport,
                    "{0}, {1}, {2}, {3}".format(bucket, KMS_Key, key_type, bucketKeyStatus),
                )
            except is_client_error("AccessDeniedException"):
                # print(bucket+', AccessDenied, AccessDenied, '+bucketKeyStatus)
                report_info(
                    bucketEncryptionReport,
                    "{0}, {1}, {2}, {3}".format(
                        bucket, KMS_Key, "AccessDenied", bucketKeyStatus
                    ),
                )
            except is_client_error("NotFoundException"):
                # print(bucket+', '+KMS_Key+', '+bucketKeyStatus)
                report_info(
                    bucketEncryptionReport,
                    "{0}, {1}, {2}, {3}".format(
                        bucket, KMS_Key, "keyNotFound", bucketKeyStatus
                    ),
                )


def report_executor():
    # Looping through all the regions
    reported_data = sse_kms_bucket_logger()
    for region in regions:
        # Initialize KMS client on a per region basis.
        url = "https://kms.{0}.amazonaws.com".format(region)
        kms = boto3.client("kms", region_name=region, endpoint_url=(url))
        key_type_check(reported_data, kms,region)

if __name__ == '__main__' :
    report_executor()
