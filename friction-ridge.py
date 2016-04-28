#!/usr/bin/env python
import re
import os
import sys
import csv
import pycurl
import OpenSSL
import socket
import ssl

from libnmap.parser import NmapParser

# colors
class b:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# transform list into string
def list_to_str(str_list):
    return re.sub('[\[\]\']', '', str(str_list))


# remove duplicated words
def unique_list(l):
    ulist = []
    [ulist.append(x) for x in l if x not in ulist]
    return ulist


def fingerprint(nmap_host_object, cpematches):
    if nmap_host_object.os.osmatches:
        for match in nmap_host_object.os.osmatches:
            for osclass in match.osclasses:
                for cpe in osclass.cpelist:
                    # store cpe object and os match accuracy
                    cpematches[cpe] = osclass.accuracy

    return cpematches


# TODO: Fingerprint decision, based on OS cpe objects and open services cpe objects
def fingerprint_decision(cpematches, services):
    '''
    Takes a dict with cpe objects with nmap accuracy scores, apply some intel and
    return most probable OS and most probable OS version.
    '''
    most_prob_os = ""
    most_prob_version = ""

    if cpematches:
        # get the highest accuracy from SO cpe dict
        cpe = max(cpematches, key=cpematches.get)

        # set the highest probable os and os version
        most_prob_os = "%s %s" % (cpe.get_vendor(), cpe.get_product().replace('_', ' '))
        most_prob_os = ' '.join(unique_list(most_prob_os.split())).title()
        most_prob_version = cpe.get_version()

    # if we can't get from host cpe, let's try with services instead
    # "hardore" fingerprint mode (guess so from services cpe)
    if not most_prob_os:
        # print("\n[*] Host fingerprint cpe failed, trying guess from open port cpe...")
        for service in services:
            if service.open():
                for cpe in service.cpelist:
                    most_prob_os = "%s %s" % (cpe.get_vendor(), cpe.get_product().replace('_', ' '))
                    most_prob_os = ' '.join(unique_list(most_prob_os.split())).title()
                    most_prob_version = cpe.get_version()
                    #most_prob_os = service.service_dict['ostype']
    
    return most_prob_os, most_prob_version


def cert_hostname(ip_address, port):
    try:
        cert = ssl.get_server_certificate((ip_address, port), ssl_version=ssl.PROTOCOL_SSLv23)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for compoment in x509.get_subject().get_components():
            compoment_name, hostname = compoment
            if compoment_name.lower() == 'cn':
                if not "*" in hostname:
                    resolved_ip_address = socket.gethostbyname(hostname.lower())
                    if resolved_ip_address == ip_address:
                        return hostname.lower()
    except Exception, e:
        print("[!] %s:%s\n[!] Error retrieving hostname via certificate.\nDetails:\n%s" % (ip_address, port, e))
        pass

    return


def _check_hostname_from_cert(curl_error_msg):
    # take curl error msg code 51 and verify IP against name
    # ex: "SSL: certificate subject name 'qa-clientlinkconnector.blabla.com' does not match target host name '50.200.62.206'"
    hostname = ""

    # hostname from error
    err_hostname = curl_error_msg.split("'")[1]
    # ip address from error
    err_address = curl_error_msg.split("'")[3]
    
    try:
        # ignore hostname with wildcards
        if "*" not in err_hostname:
            # verify if cert hostname matches the candidate IP address
            resolved_ip_address = socket.gethostbyname(err_hostname)
            if resolved_ip_address == address:
                hostname = err_hostname.lower()
    except Exception, e:
        pass

    return hostname


def check_hostname(nmap_host_object, hostnames):
    # add nmap resolved hostname to hostnames list if it exist
    if nmap_host_object.hostnames:
        hostnames += nmap_host_object.hostnames

    # add reversed name lookup
    try:
        hostname, aliaslist, addresslist = socket.gethostbyaddr(nmap_host_object.address)
        if hostname and hostname not in hostnames:
            hostnames.append(hostname.lower())
    except Exception, e:
        pass

    # add HTTP SSL enabled certificate hostnames
#    curl = pycurl.Curl()
#    curl.setopt(pycurl.SSL_VERIFYPEER, 0)
#    curl.setopt(pycurl.TIMEOUT, 10L)
#    curl.setopt(pycurl.OPT_CERTINFO, 1)

    # suppress curl output
#    devnull = open('/dev/null', 'w')
#    curl.setopt(pycurl.WRITEFUNCTION, devnull.write)

    # run through all HTTP SSL enabled ports
    for service in nmap_host_object.services:
        # check hostname inside certificates
        if service.open() and "http" in service.service.lower() and service.tunnel.lower() == "ssl":
            hostname = cert_hostname(nmap_host_object.address, service.port)
            if hostname:
                hostnames.append(hostname)
#            url = "https://%s:%s" % (nmap_host_object.address, service.port)
#            curl.setopt(pycurl.URL, url)
#            try:
                # run curl
 #               curl.perform()
 #               curl.close()
                #for certinfo in c.getinfo(pycurl.INFO_CERTINFO):
                #    for info in certinfo:
                #        if "Subject" in str(info):
                #            print info
#            except Exception, error:
                # if exception occours, we can grab the hostname from it
#                code, error_msg = error
#                if code == 51 and "does not match target host name" in error_msg:
#                    hostname = _check_hostname_from_cert(error_msg)
#                    if hostname:
#                        hostnames.append(hostname)
#                pass

    return unique_list(hostnames)


def check_ports(services):
    # take service object list and put in the right format
    # 443/tcp, 80/tcp, 22/tcp
    ports = []
    for service in services:
        if service.open():
            # filter add only to udp/tcp ports (avoiding nmap-protocols results)
            if service.protocol == "udp" or service.protocol == "tcp":
                port = "%s/%s" % (service.port, service.protocol.lower())
                ports.append(port)

    ports = unique_list(ports)

    return list_to_str(ports)


def check_services(nmap_host_object, services):
    for service in nmap_host_object.services:
        if service.open():
            services.append(service)

    return unique_list(services)


def nmap_combine(nmap_report, report):
    # receive NmapParser.parse_fromfile object and transcript it to dict
    # including os_name, os_version, open_ports
    for h in nmap_report.hosts:
        # finger only hosts with detected open ports
        if h.get_open_ports():
            # check if report has previously info about the current host
            if not report.has_key(h.address):
                report[h.address] = {'Port/Protocol': [], 'Domains': [], 'Operating System': {}, 'OS Version': "", 'Notes': ""}

            # add cpe objects and os match accuracy to Operating System dict
            report[h.address]['Operating System'] = fingerprint(h, report[h.address]['Operating System'])

            # add open nmap service objects to Port/Protocol list
            report[h.address]['Port/Protocol'] = check_services(h, report[h.address]['Port/Protocol'])

            # add possible hostnames to Domains list
            report[h.address]['Domains'] = check_hostname(h, report[h.address]['Domains'])

            # print report[h.address]

    return report


def search_xml_recursively(directory):
    full_path_files = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            if f.lower().endswith('.xml'):
                full_path_files.append("%s/%s" % (root, f))
    
    return unique_list(full_path_files)


# avoiding directory string problems
directory = sys.argv[1]
if directory.endswith('/'):
    directory = directory[:-1]

# find all xml files recursively
nmap_xml_reports = search_xml_recursively(directory)

# results = cumulative dictionary
results = {}

# open final report file
with open("recon.csv", 'w') as csvwrite:
    # set field names
    fieldnames = ['IP Address', 'Port/Protocol', 'Domains', 'Operating System', 'OS Version', 'Notes']
    writer = csv.DictWriter(csvwrite, fieldnames=fieldnames, dialect=csv.excel, quoting=csv.QUOTE_ALL)
    
    # write CSV header
    writer.writeheader()

    # iterate through xml(s)
    for xml_report in nmap_xml_reports:
        try:
            # trying to load xml file
            nmap_report = NmapParser.parse_fromfile(xml_report)
            print "[%sOK%s] %s, %s host(s) loaded." % (b.OKGREEN, b.ENDC, xml_report, len(nmap_report.hosts))
        except Exception, e:
            print "[%sFAIL%s] %s invalid format." % (b.FAIL, b.ENDC, xml_report)
            # keep looking for others xml
            continue

        # start a cumulative dictionary
        results = nmap_combine(nmap_report, results)
        #print "results: %s" % len(results)

    for ip_address in results:
        # colecting info for each field
        open_ports = check_ports(results[ip_address]['Port/Protocol'])
        hostnames = list_to_str(results[ip_address]['Domains'])
        notes = results[ip_address]['Notes']
        os, os_version = fingerprint_decision(results[ip_address]['Operating System'], results[ip_address]['Port/Protocol'])

        # write down to the final report file
        writer.writerow({'IP Address': ip_address, 'Port/Protocol': open_ports, 'Domains': hostnames, 'Operating System': os, 'OS Version': os_version, 'Notes': notes})
        print("%s,%s,%s,%s,%s,%s" % (ip_address, open_ports, hostnames, os, os_version, notes))

