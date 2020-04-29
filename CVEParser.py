#!/usr/bin/env python3.7
import datetime as dt
import requests
import hashlib
import secrets
import gzip as gz
import json
import os
import sys
import argparse as ap


def main():
    global OPTIONS

    parser = ap.ArgumentParser()
    parser.add_argument("-cvss2", default=False, action="store_true", help="Show CVSSv2 information")
    parser.add_argument("-cvss3", default=False, action="store_true", help="Show CVSSv3 information")
    parser.add_argument("-s", "--short-list", default=False, action="store_true", help="Show only basic information")
    parser.add_argument("-f", "--local-file", type=str, help="Parse a local file instead of fetching online resources, requires --sha256 to function")
    parser.add_argument("--sha256", type=str, help="Expected SHA256 HASH string of local file")
    parser.add_argument("--filter-list", type=str, help="Line separated filter list for filtering only relevant CVEs")
    args = parser.parse_args()
    OPTIONS = args

    if OPTIONS.local_file is not None:
        if OPTIONS.sha256 is None:
            print("ERROR: Parsing local archives require the --hash argument to be set!")
            sys.exit(1)
        local_source(OPTIONS.local_file, OPTIONS.sha256)

    else:
        source_list = sources() 

        # Fetch source packages
        for key in source_list:
            source = source_list[key]
            fetch_source(source, key)


def fetch_source_file(url):
    temp_file = "/tmp/{}.gz".format(secrets.token_hex(nbytes=16))
    with open(temp_file, "wb") as f:
        res = requests.get(url)
        print("Writing content to file: {}".format(temp_file))
        f.write(res.content)
        f.close()
    
    return temp_file


def unpack(source_file, source_hash):
    f = gz.GzipFile(source_file, "rb")
    content = f.read()
    content_hash = hashlib.sha256(content).hexdigest()
    f.close()

    print("""
    Validating downloaded content:
    Expected:   {}
    Downloaded: {}
    """.format(source_hash.lower(), content_hash.lower()))

    if source_hash.lower() == content_hash.lower():
        print("-> Validation OK!")
        return json.loads(content)
    else:
        raise Exception("(!!) Hash missmatch, it is not safe to continue. Quitting.")


def verify(source):
    meta = source["meta"]

    req = requests.get(meta)

    # Strip the meta file of any empty string values
    content = [i for i in req.text.split("\r\n") if i]
   
    last_modified = dt.datetime.strptime(content[0], "lastModifiedDate:%Y-%m-%dT%H:%M:%S%z")
    current_time = dt.datetime.now()

    # Strip the string sha256:
    source_hash = content[-1][7:]

    temp_file = fetch_source_file(source["data"])
    json_data = unpack(temp_file, source_hash)

    # Cleaning up the temp gunzip file
    try:
        os.unlink(temp_file)
    except Exception as e:
        print(e)


    print("The fetched file is {} days old".format(abs(current_time.date() - last_modified.date()).days))
    return json_data
    
    


def parse(source):
    global OPTIONS

    search_strings = []

    if OPTIONS.filter_list is not None:
        if os.path.isfile(OPTIONS.filter_list):
            with open(OPTIONS.filter_list, "r") as f:
                search_strings = f.read().splitlines()
                f.close()

    print("""
    Type:       {}
    Format:     {}
    Version:    {}
    CVE Count:  {}
    Date:       {}
            """.format(
                source["CVE_data_type"],
                source["CVE_data_format"],
                source["CVE_data_version"],
                source["CVE_data_numberOfCVEs"],
                source["CVE_data_timestamp"]))

    if len(search_strings) > 0:
        print("-> Filtering content! Using filter list: {} with {} filter(s)".format(OPTIONS.filter_list, len(search_strings)), end="\n\n")

    for item in source["CVE_Items"]:
        # Look for searchwords, skip CVE unless search matches
        if len(search_strings) > 0:
            found = 0
            for s in search_strings:
                if s.lower() in item["cve"]["description"]["description_data"][-1]["value"].lower():
                    found +=1
                    break
            if found == 0:
                continue

        cvss2 = "Available"
        cvss3 = "Available"

        if OPTIONS.short_list:
            if "baseMetricV3" in item["impact"]:
                score = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                severity = item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
            
            elif "baseMetricV2" in item["impact"] and OPTIONS.cvss2:
                score = item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                severity = item["impact"]["baseMetricV2"]["severity"] 
            else:
                score = "N/A"
                severity = "N/A"

            print("{0} ({1}) SCORE: {2}, SEVERITY: {3}, DESCRIPTION: {4}, URL: https://cve.mitre.org/cgi-bin/cvename.cgi?name={0}".format(
                item["cve"]["CVE_data_meta"]["ID"],
                item["publishedDate"],
                score,
                severity,
                item["cve"]["description"]["description_data"][-1]["value"]))
            continue

        if not "baseMetricV2" in item["impact"] and OPTIONS.cvss2:
            cvss2 = "N/A"
        if not "baseMetricV3" in item["impact"] and OPTIONS.cvss3:
            cvss3 = "N/A"

        print("""
        {}:
        Publishd:       {}
        Modified:       {}
        CVSSv2:         {}
        CVSSv3:         {}
        Description:    {}""".format(
            item["cve"]["CVE_data_meta"]["ID"],
            item["publishedDate"],
            item["lastModifiedDate"],
            cvss2,
            cvss3,
            item["cve"]["description"]["description_data"][-1]["value"]))
        
        if "baseMetricV2" in item["impact"] and OPTIONS.cvss2:
            print("""
            CVSSv2 Rating   (Score: {8}, Severity: {9})
            -------------------------------------------------------
            CVSS Version:           {0}
            Vector String:          {1}
            Access Vector:          {2}
            Complexity:             {3}
            Authentication:         {4}

            Impact:
                Score:              {11}
                Confidentiality:    {5}
                Integrity:          {6}
                Availability:       {7}

            Exploitability:         {10}
            """.format(
                item["impact"]["baseMetricV2"]["cvssV2"]["version"],
                item["impact"]["baseMetricV2"]["cvssV2"]["vectorString"],
                item["impact"]["baseMetricV2"]["cvssV2"]["accessVector"],
                item["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"],
                item["impact"]["baseMetricV2"]["cvssV2"]["authentication"],
                item["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"],
                item["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"],
                item["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"],
                item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"],
                item["impact"]["baseMetricV2"]["severity"],
                item["impact"]["baseMetricV2"]["exploitabilityScore"],
                item["impact"]["baseMetricV2"]["impactScore"]))

        if "baseMetricV3" in item["impact"] and OPTIONS.cvss3:
            print("""
            CVSSv3 Rating   (Score: {10}, Severity: {11})
            -------------------------------------------------------
            CVSS Version:           {0}
            Vector String:          {1}
            Attack Vector:          {2}
            Complexity:             {3}
            Required Privilege:     {4}
            User Interacion:        {5}
            Scope:                  {6}

            Impact:
                Score:              {13}
                Confidentiality:    {7}
                Integrity:          {8}
                Availability:       {9}

            Exploitablity:          {12}
            """.format(
                item["impact"]["baseMetricV3"]["cvssV3"]["version"],
                item["impact"]["baseMetricV3"]["cvssV3"]["vectorString"],
                item["impact"]["baseMetricV3"]["cvssV3"]["attackVector"],
                item["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"],
                item["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"],
                item["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"],
                item["impact"]["baseMetricV3"]["cvssV3"]["scope"],
                item["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"],
                item["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"],
                item["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"],
                item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"],
                item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"],
                item["impact"]["baseMetricV3"]["exploitabilityScore"],
                item["impact"]["baseMetricV3"]["impactScore"]))
        # Add some padding
        print("\n\n")


def fetch_source(source, key):
    print("-> Fetching vulnerabilities from source {}".format(key.upper()), end="\n\n")
    if "data" in source:
        if "meta" in source:
            if source["meta"] != "":
                json_data = verify(source)
                parse(json_data)
            else:
                print("Error! META-information configured for source {} but URL is not configured!".format(key))
                return
        else:
            print("Warning! No META-information for source: {}".format(key))
    else:
        print("Error! no data-url found for source: {}".format(key))

    return


def local_source(source, key):
    if os.path.isfile(source):
        print("-> Fetching vulnerabilities from source {}".format(key.upper()))
        json_data = unpack(source, key)
        parse(json_data)
    else:
        print("Unable to locate {}".format(source))


def sources():
    # Vulnerability feed source data
    return {
            "nvd": {
                "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.meta",
                "data": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
                }
            }

if __name__ == "__main__":
    OPTIONS = {}
    main()

