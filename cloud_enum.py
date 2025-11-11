#!/usr/bin/env python3

"""
cloud_enum by initstring (github.com/initstring)

Multi-cloud OSINT tool designed to enumerate storage and services in AWS,
Azure, and GCP.

Enjoy!
"""

import os
import sys
import argparse
import re
from enum_tools import aws_checks
from enum_tools import azure_checks
from enum_tools import gcp_checks
from enum_tools import utils

BANNER = '''
##########################
        cloud_enum
   github.com/initstring
##########################

'''


def parse_arguments():
    """
    Handles user-passed parameters
    """
    desc = "Multi-cloud enumeration utility. All hail OSINT!"
    parser = argparse.ArgumentParser(description=desc)

    # Grab the current dir of the script, for setting some defaults below
    script_path = os.path.split(os.path.abspath(sys.argv[0]))[0]

    kw_group = parser.add_mutually_exclusive_group(required=True)

    # Keyword can given multiple times
    kw_group.add_argument('-k', '--keyword', type=str, action='append',
                          help='Keyword. Can use argument multiple times.')

    # OR, a keyword file can be used
    kw_group.add_argument('-kf', '--keyfile', type=str, action='store',
                          help='Input file with a single keyword per line.')

    # Use included mutations file by default, or let the user provide one
    core_group = parser.add_argument_group('Runtime Options')
    core_group.add_argument('-m', '--mutations', type=str, action='store',
                            default=script_path + '/enum_tools/fuzz.txt',
                            help='Mutations. Default: enum_tools/fuzz.txt')

   # Use include container brute-force or let the user provide one
    core_group.add_argument('-b', '--brute', type=str, action='store',
                           default=script_path + '/enum_tools/fuzz.txt',
                           help='List to brute-force Azure container names.'
                                 '  Default: enum_tools/fuzz.txt')

    core_group.add_argument('-t', '--threads', type=int, action='store',
                            default=5, help='Threads for HTTP brute-force.'
                                            ' Default = 5')

    core_group.add_argument('-ns', '--nameserver', type=str, action='store',
                            default='1.1.1.1',
                            help='DNS server to use in brute-force.')
    core_group.add_argument('-nsf', '--nameserverfile', type=str,
                            help='Path to the file containing nameserver IPs')
    core_group.add_argument('-l', '--logfile', type=str, action='store',
                            help='Appends found items to specified file.')
    core_group.add_argument('-f', '--format', type=str, action='store',
                            default='text',
                            help='Format for log file (text,json,csv)'
                                 ' - default: text')

    core_group.add_argument('--disable-aws', action='store_true',
                            help='Disable Amazon checks.')

    core_group.add_argument('--disable-azure', action='store_true',
                            help='Disable Azure checks.')

    core_group.add_argument('--disable-gcp', action='store_true',
                            help='Disable Google checks.')

    core_group.add_argument('-qs', '--quickscan', action='store_true',
                            help='Disable all mutations and second-level scans')

    auth_options = parser.add_argument_group('AWS Authentication Options')
    auth_options.add_argument('--profile',
                              help='AWS named profile to use. Profile should be present in ~/.aws/credentials',
                              type=str)
    auth_options.add_argument('--access-key',
                              help='AWS access key to use. Also provide the secret key with --secret-key.',
                              type=str)
    auth_options.add_argument('--secret-key',
                              help='AWS secret key to use. Also provide the access key with --access-key.',
                              type=str)
    auth_options.add_argument('--session-token',
                              help='AWS session-token. Also provide the access key with --access-key and the secret '
                                   'key with --secret-key',
                              type=str)


    args = parser.parse_args()

    # Ensure mutations file is readable
    if not os.access(args.mutations, os.R_OK):
        print(f"[!] Cannot access mutations file: {args.mutations}")
        sys.exit()

    # Ensure brute file is readable
    if not os.access(args.brute, os.R_OK):
        print("[!] Cannot access brute-force file, exiting")
        sys.exit()

    # Ensure keywords file is readable
    if args.keyfile:
        if not os.access(args.keyfile, os.R_OK):
            print("[!] Cannot access keyword file, exiting")
            sys.exit()

        # Parse keywords from input file
        with open(args.keyfile, encoding='utf-8') as infile:
            args.keyword = [keyword.strip() for keyword in infile]

    # Ensure log file is writeable
    if args.logfile:
        if os.path.isdir(args.logfile):
            print("[!] Can't specify a directory as the logfile, exiting.")
            sys.exit()
        if os.path.isfile(args.logfile):
            target = args.logfile
        else:
            target = os.path.dirname(args.logfile)
            if target == '':
                target = '.'

        if not os.access(target, os.W_OK):
            print("[!] Cannot write to log file, exiting")
            sys.exit()

        # Set up logging format
        if args.format not in ('text', 'json', 'csv'):
            print("[!] Sorry! Allowed log formats: 'text', 'json', or 'csv'")
            sys.exit()
        # Set the global in the utils file, where logging needs to happen
        utils.init_logfile(args.logfile, args.format)

    # Validate that access key and secret key are provided
    if (args.access_key and not args.secret_key) or (not args.access_key and args.secret_key):
        parser.error('--access-key and --secret-key arguments must both be provided')

    # Validate session token
    if args.session_token and not args.access_key and not args.secret_key:
        parser.error('--session-token requires --access-key and --secret-key arguments')

    # Validate that access keys and profile isn't provided together
    if (args.access_key and args.secret_key) and args.profile:
        parser.error('Cannot use --access-key/--secret-key and --profile at the same time')

    return args


def print_status(args):
    """
    Print a short pre-run status message
    """
    print(f"Keywords:    {', '.join(args.keyword)}")
    if args.quickscan:
        print("Mutations:   NONE! (Using quickscan)")
    else:
        print(f"Mutations:   {args.mutations}")
    print(f"Brute-list:  {args.brute}")
    print("")


def check_windows():
    """
    No need to handle color printing since we're removing ANSI codes
    """
    pass


def read_mutations(mutations_file):
    """
    Read mutations file into memory for processing.
    """
    with open(mutations_file, encoding="utf8", errors="ignore") as infile:
        mutations = infile.read().splitlines()

    print(f"[+] Mutations list imported: {len(mutations)} items")
    return mutations


def clean_text(text):
    """
    Clean text to be RFC compliant for hostnames / DNS
    """
    banned_chars = re.compile('[^a-z0-9.-]')
    text_lower = text.lower()
    text_clean = banned_chars.sub('', text_lower)

    return text_clean


def append_name(name, names_list):
    """
    Ensure strings stick to DNS label limit of 63 characters
    """
    if len(name) <= 63:
        names_list.append(name)


def build_names(base_list, mutations):
    """
    Combine base and mutations for processing by individual modules.
    """
    names = []

    for base in base_list:
        # Clean base
        base = clean_text(base)

        # First, include with no mutations
        append_name(base, names)

        for mutation in mutations:
            # Clean mutation
            mutation = clean_text(mutation)

            # Then, do appends
            append_name(f"{base}{mutation}", names)
            append_name(f"{base}.{mutation}", names)
            append_name(f"{base}-{mutation}", names)

            # Then, do prepends
            append_name(f"{mutation}{base}", names)
            append_name(f"{mutation}.{base}", names)
            append_name(f"{mutation}-{base}", names)

    # Removed the output of mutation results count
    # Just return the names list
    return names

def read_nameservers(file_path):
    try:
        with open(file_path, 'r') as file:
            nameservers = [line.strip() for line in file if line.strip()]
        if not nameservers:
            raise ValueError("Nameserver file is empty")
        return nameservers
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        exit(1)
    except ValueError as e:
        print(e)
        exit(1)

def main():
    """
    Main program function.
    """
    args = parse_arguments()
    print(BANNER)
    sys.stdout.flush()

    # Generate a basic status on targets and parameters
    print_status(args)
    sys.stdout.flush()

    # First, build a sorted base list of target names
    if args.quickscan:
        mutations = []
    else:
        mutations = read_mutations(args.mutations)
        sys.stdout.flush()
    
    names = build_names(args.keyword, mutations)
    
    # Print total number of names for debugging
    print(f"[+] Total mutation results: {len(names)} items")
    sys.stdout.flush()

    # All the work is done in the individual modules
    try:
        if not args.disable_aws:
            print("[+] Running AWS checks...")
            sys.stdout.flush()
            aws_checks.run_all(names, args)
            sys.stdout.flush()
        if not args.disable_azure:
            print("[+] Running Azure checks...")
            sys.stdout.flush()
            azure_checks.run_all(names, args)
            sys.stdout.flush()
        if not args.disable_gcp:
            print("[+] Running GCP checks...")
            sys.stdout.flush()
            gcp_checks.run_all(names, args)
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("Thanks for playing!")
        sys.stdout.flush()
        sys.exit()
    except Exception as e:
        print(f"[!] Error during execution: {str(e)}")
        sys.stdout.flush()
        sys.exit(1)

    # Best of luck to you!
    print("\n[+] All done, happy hacking!\n")
    sys.stdout.flush()
    sys.exit(0)


if __name__ == '__main__':
    main()
