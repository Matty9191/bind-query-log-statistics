#!/usr/bin/env python
# Program: bind-query-log-statistics.py
# Author: Matty < matty91 at gmail dot com >
# Current Version: 1.0
# Last Updated: 11-11-2016
# Version history:
#   1.0 Initial Release
# Purpose: Analyzes Bind query logs and produces a variety of query statistics.
# License: 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.


import sys
import argparse
import re
import time
import socket
from collections import Counter
from collections import defaultdict

# Counters
COUNT = 0
TOTAL_QUERIES = 0

# Timestsmp helpers
FIRST_QUERY = time.strftime("%d-%b-%Y %H:%M:%S.000")
LAST_QUERY = ""

# Dictionaries to store query data
DOMAINS = []
LOGFILES = []
NETS_TO_EXCLUDE = []
IPS_TO_EXCLUDE = []
DNS_QUERIES = defaultdict(int)
DNS_CLIENTS = defaultdict(int)
DNS_QUERY_TYPES = defaultdict(int)
DNS_RESOLUTION_MATRIX = defaultdict(lambda: defaultdict(int))

# Don't print a resolution matrix by default
ENABLE_RESOLUTION_MATRIX = ""
ENABLE_HISTOGRAMS = ""

# Place to store query time period breakdown
HISTOGRAM_HOUR = defaultdict(int)
HISTOGRAM_MINUTE = defaultdict(int)


def process_time(timestamp):
    """
        Log the first and last query times so we can
        display them on the final report
    """
    global FIRST_QUERY, LAST_QUERY

    if timestamp < FIRST_QUERY:
        FIRST_QUERY = timestamp
    elif timestamp > LAST_QUERY:
        LAST_QUERY = timestamp


def generate_statistics(dns_question, rr_type, client_ip):
    """ Increment statistics for the dns_question """
    global TOTAL_QUERIES

    # If/Else added to avoid using the regex module unless absolutely necessary
    if DOMAINS != ".":
        if any(re.search(d, dns_question) for d in DOMAINS):
            TOTAL_QUERIES += 1
            DNS_QUERIES[dns_question] += 1
            DNS_QUERY_TYPES[rr_type] += 1
            DNS_CLIENTS[client_ip] += 1
            client_net = '.'.join(client_ip.split('.', 3)[:3])
    else:
        TOTAL_QUERIES += 1
        DNS_QUERIES[dns_question] += 1
        DNS_QUERY_TYPES[rr_type] += 1
        DNS_CLIENTS[client_ip] += 1

    if ENABLE_RESOLUTION_MATRIX:
        if (not (client_ip in IPS_TO_EXCLUDE or
                 any(re.search(client_net, net) for net in NETS_TO_EXCLUDE))):
            DNS_RESOLUTION_MATRIX[dns_question][client_ip] += 1


def print_top_dns_requests(num_print):
    """ Print the top DNS questions that were asked """
    print "\nTop ", num_print, " DNS names requested:"
    for query, _ in Counter(DNS_QUERIES).most_common(num_print):
        print "  " + query + " : " + str(DNS_QUERIES[query])


def print_top_dns_clients(num_print):
    """ Print the top DNS_CLIENTS who asked the most questions """
    print "\nTop ", num_print, " DNS clients:"
    for client_ip, num_queries  in Counter(DNS_CLIENTS).most_common(num_print):
        try:
            client_name = socket.gethostbyaddr(client_ip)[0]
        except socket.herror:
            client_name = client_ip
        print "  " + client_name + " : ", num_queries


def print_dns_resolution_matrix():
    """ Print a list of DNS requests and the
        DNS_CLIENTS who asked those questions
    """
    print "\nDomain to client resolution matrix:"
    for domain in DNS_RESOLUTION_MATRIX:
        print "\n  " + domain
        for client_ip in DNS_RESOLUTION_MATRIX[domain]:
            try:
                client_name = socket.gethostbyaddr(client_ip)[0]
            except socket.herror:
                client_name = client_ip
            print "  |-- " + client_name + " ", DNS_RESOLUTION_MATRIX[domain][client_ip]

def print_dns_summary():
    """ Print a number of summary statistics """
    print "\nSummary for %s - %s\n" % (FIRST_QUERY, LAST_QUERY)
    print "%-25s : %d" % ("Total DNS_QUERIES processed", TOTAL_QUERIES)

    for rr_type, query_count in sorted(DNS_QUERY_TYPES.items(), key=lambda a: a[1], reverse=True):
        print "  %-6s records requested : %d" % (rr_type, query_count)


def process_query(query):
    """ Takes a Bind query log entry and splits it to see how many
        entries it contains. The query log format can change between
        releases and can grow or shrink if views are used.

        Known query log formats:

        Bind 9.3 query log format:
        20-Sep-2016 11:26:15.510 query: info: client 1.2.3.4#60010: \
        view standard: query: blip.prefetch.net IN AAAA +

        Bind 9.9 query log format:
        20-Sep-2016 11:24:30.025 query: info: client 1.2.3.4#61687 \
        (blip.prefetch.net): view standard: query: blip.prefetch.net
        IN A + (10.1.1.1)

        # Bind 9.3 w/o views
        08-Nov-2016 14:05:59.996 query: info: client 1.2.3.4#7619: \
        query: 10.10.10.10.in-addr.arpa IN PTR -E
    """
    chopped = query.split()

    if len(chopped) < 11:
        print "Unknown query log format"
        print "Offending line -> %s" % query

    # Bind 9.3 query w/o views
    if len(chopped) == 11:
        timestamp = chopped[0] + " " + chopped[1]
        client_ip = chopped[5].split("#")[0]
        rr_type = chopped[9]
        dns_question = chopped[7]

    # Bind 9.3 query w/ views
    elif len(chopped) == 13:
        timestamp = chopped[0] + " " + chopped[1]
        client_ip = chopped[5].split("#")[0]
        rr_type = chopped[11]
        dns_question = chopped[9]

    # Bind 9.9 query w/ views
    elif len(chopped) == 15:
        timestamp = chopped[0] + " " + chopped[1]
        client_ip = chopped[5].split("#")[0]
        rr_type = chopped[12]
        dns_question = chopped[10]

    return timestamp, dns_question, rr_type, client_ip


def processcli():
    """ parses the CLI arguments and returns a list
        of domains and logfiles to process
    """

    parser = argparse.ArgumentParser(description='DNS Statistics Processor')

    parser.add_argument('--matrix', help="Print client to domain resolution info",
                        action="store_true")
    parser.add_argument('--histogram', help="Print histogram of queries",
                        action="store_true")
    parser.add_argument('--count', nargs=1, help="Number of entries to display",
                        default=100, metavar="Count")
    parser.add_argument('--excludeip', nargs='*', help="IPs to exclude from resolution matrix",
                        default="", metavar="IP Address")
    parser.add_argument('--excludenet', nargs='*', help="Networks to exclude from resolution matrix",
                        default="", metavar="Network")
    parser.add_argument('--domains', nargs='*', help="Create statistics for specific domains",
                        default=".", metavar="Domain")
    parser.add_argument('logfiles', nargs='*',
                        help="List of Bind query logs to process",
                        metavar="Logfile")
    parser.add_argument('--starttime', nargs=1, help="Create statistics from this time forward",
                        default="", metavar="Start Time")
    parser.add_argument('--endtime', nargs=1, help="Process statistics until this period of time",
                        default="", metavar="End Time")
    args = parser.parse_args()

    return args.count, args.domains, args.logfiles, args.excludeip, args.excludenet, args.matrix, args.histogram


def process_logs(logs):
    """ Takes a list of logfiles and calls a DNSStats
        method to process each logfile entry
    """

    for log in logs:
        print "Processing logfile " + log
        try:
            with open(log, 'r') as query_log:
                for query in query_log:
                    timestamp, dns_question, rr_type, client_ip = process_query(query)
                    process_time(timestamp)
                    generate_statistics(dns_question, rr_type, client_ip)
                    if ENABLE_HISTOGRAMS:
                        populate_histograms(timestamp)
        except IOError:
            print "Could not open file " + log + " for processing"
            sys.exit(1)

def populate_histograms(timestamp):
    """
       Create stats about when queries occurred
       06-Nov-2016 11:44:43.946
    """
    day, month, year, hour, minute, second, _ = re.split(r'[-:.\s]', timestamp)
    HISTOGRAM_HOUR[hour] += 1
    HISTOGRAM_MINUTE[minute] += 1


def create_histogram(label, dns_dict):
    """
       Create a histogram for queries per minute, hour, day, etc.
    """
    LARGEST_VALUE = max(dns_dict.values())
    SCALE = 50.00 / LARGEST_VALUE

    print "\nQueries per %s:" % label
    for interval, queries in sorted(dns_dict.iteritems()):
        hist_size = "*" * int(queries * SCALE)
        print "  %2s: %s (%d)" % (interval, hist_size, queries)

if __name__ == "__main__":

    (COUNT, DOMAINS, LOGFILES, IPS_TO_EXCLUDE, NETS_TO_EXCLUDE, 
     ENABLE_RESOLUTION_MATRIX, ENABLE_HISTOGRAMS) = processcli()

    if not LOGFILES:
        print "No log files specified on command line"
        sys.exit(1)

    process_logs(LOGFILES)
    print_dns_summary()
    print_top_dns_requests(COUNT)
    print_top_dns_clients(COUNT)

    if ENABLE_HISTOGRAMS:
        create_histogram("minute", HISTOGRAM_MINUTE)
        create_histogram("hour", HISTOGRAM_HOUR)

    if ENABLE_RESOLUTION_MATRIX:
        print_dns_resolution_matrix()
