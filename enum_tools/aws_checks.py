"""
AWS-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import sys
from enum_tools import utils
import concurrent.futures
import boto3
import botocore

BANNER = '''
++++++++++++++++++++++++++
      amazon checks
++++++++++++++++++++++++++
'''

# Known S3 domain names
S3_URL = 's3.amazonaws.com'
APPS_URL = 'awsapps.com'
global S3_AUTH_STATUS
S3_AUTH_STATUS = 0

# Known AWS region names. This global will be used unless the user passes
# in a specific region name. (NOT YET IMPLEMENTED)
AWS_REGIONS = ['amazonaws.com',
               'ap-east-1.amazonaws.com',
               'us-east-2.amazonaws.com',
               'us-west-1.amazonaws.com',
               'us-west-2.amazonaws.com',
               'ap-south-1.amazonaws.com',
               'ap-northeast-1.amazonaws.com',
               'ap-northeast-2.amazonaws.com',
               'ap-northeast-3.amazonaws.com',
               'ap-southeast-1.amazonaws.com',
               'ap-southeast-2.amazonaws.com',
               'ca-central-1.amazonaws.com',
               'cn-north-1.amazonaws.com.cn',
               'cn-northwest-1.amazonaws.com.cn',
               'eu-central-1.amazonaws.com',
               'eu-west-1.amazonaws.com',
               'eu-west-2.amazonaws.com',
               'eu-west-3.amazonaws.com',
               'eu-north-1.amazonaws.com',
               'sa-east-1.amazonaws.com']


class S3Response:
    def __init__(self, bucket_name: str, status_code: int):
        self.bucket_name = str(bucket_name)
        self.status_code = int(status_code)
        self.url = f'https://{bucket_name}.s3.amazonaws.com/'
        self.reason = ''

def print_s3_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif 'Bad Request' in reply.reason:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN S3 BUCKET'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        #utils.list_bucket_contents(reply.url)
    elif reply.status_code == 403:
        data['msg'] = 'Protected S3 Bucket'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        sys.stdout.flush()
        return 'breakout'
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              f"       {reply.status_code}: {reply.reason}")
        sys.stdout.flush()

    return None


def check_s3_buckets(names, threads, args):
    """
    Checks for open and restricted Amazon S3 buckets
    """
    print("[+] Checking for S3 buckets")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

 # Authenticated checks
    if args.profile or args.access_key:
        # Set AWS credentials
        if args.profile:
            boto3.setup_default_session(profile_name=args.profile)
        elif args.access_key and args.access_key and not args.session_token:
            boto3.setup_default_session(aws_access_key_id=args.access_key,
                                        aws_secret_access_key=args.secret_key)
        elif args.session_token:
            boto3.setup_default_session(aws_access_key_id=args.access_key,
                                        aws_secret_access_key=args.secret_key,
                                        aws_session_token=args.session_token)
        # Print identity
        print(f'[+] AWS: Making API calls as {str(sts_get_caller_identity())}')

        # Run checks
        print("[+] Checking for S3 buckets")
        for name in names:
            candidates.append(name)
        check_s3_authenticated_multithread(candidates)

    # Unauthenticated checks
    else:
        print("[+] Checking for S3 buckets")
        for name in names:
            candidates.append(f'{name}.{S3_URL}')
        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=False,
                            callback=print_s3_response,
                            threads=threads)

    # Stop the time
    utils.stop_timer(start_time)

def sts_get_caller_identity():
    client_sts = boto3.client('sts')
    identity = client_sts.get_caller_identity()
    calling_principal = str(identity['Arn'])
    return calling_principal


def check_s3_authenticated_multithread(bucket_names):
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(check_s3_authenticated, bucket_name, len(bucket_names)): bucket_name for bucket_name in bucket_names}
        for future in concurrent.futures.as_completed(futures):
            file_dict = futures[future]
            try:
                future.result()
            except Exception as error:
                print(f'Uncaught exception: {error}')
                sys.exit()


def check_s3_authenticated(bucket_name, total_buckets):
    global S3_AUTH_STATUS
    S3_AUTH_STATUS += 1
    try:
        s3_client = boto3.client('s3')
        head_bucket = s3_client.head_bucket(Bucket=bucket_name)
        # No error, bucket exists
        is_listable = is_bucket_listable(bucket_name)
        if is_listable:
            bucket = S3Response(bucket_name, 200)
            print_s3_response(bucket)
        else:
            bucket = S3Response(bucket_name, 403)
            print_s3_response(bucket)
    except botocore.exceptions.ClientError as error:
        # Get the error code and HTTP status code
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        http_status = error.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
        # Bucket doesn't exist
        if error_code == 'NoSuchBucket':
            bucket = S3Response(bucket_name, 404)
            print_s3_response(bucket)
        elif error_code in ('404', 'NotFound', 'Not Found') or http_status == 404:
            bucket = S3Response(bucket_name, 404)
            print_s3_response(bucket)
        elif http_status == 403:
            bucket = S3Response(bucket_name, 403)
            print_s3_response(bucket)
        # Unknown error
        else:
            print('AWS API Error: ' + str(error))
            bucket = S3Response(bucket_name, 404)
            print_s3_response(bucket)
    # Catch all other exceptions
    except Exception as error:
        print(f'Uncaught exception: {error}')
        sys.exit()


def is_bucket_listable(bucket_name):
    """List objects in an S3 bucket"""
    try:
        s3_client = boto3.client('s3')
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        return True
    except botocore.exceptions.ClientError as error:
        print(f'Error: {error}')
        return False
    except Exception as error:
        print(f'Uncaught exception: {error}')
        return False

def check_awsapps(names, threads, nameserver, nameserverfile=False):
    """
    Checks for existence of AWS Apps
    (ie. WorkDocs, WorkMail, Connect, etc.)
    """
    data = {'platform': 'aws', 'msg': 'AWS App Found:', 'target': '', 'access': ''}

    print("[+] Checking for AWS Apps")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    for name in names:
        candidates.append(f'{name}.{APPS_URL}')

    # AWS Apps use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads)

    for name in valid_names:
        data['target'] = f'https://{name}'
        data['access'] = 'protected'
        utils.fmt_output(data)

    # Stop the timer
    utils.stop_timer(start_time)


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)
    sys.stdout.flush()

    # Print a guaranteed output line for debugging
    print("[+] AWS checks starting with keyword: " + ', '.join(args.keyword))
    sys.stdout.flush()

    # Use user-supplied AWS region if provided
    # if not regions:
    #    regions = AWS_REGIONS
    check_s3_buckets(names, args.threads, args)
    sys.stdout.flush()
    
    check_awsapps(names, args.threads, args.nameserver, args.nameserverfile)
    sys.stdout.flush()
    
    # Print an ending line
    print("[+] AWS checks completed")
    sys.stdout.flush()
