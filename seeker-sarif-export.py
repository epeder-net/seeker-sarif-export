import requests
import logging
import json
import argparse
import re

logging.basicConfig(format='%(asctime)s:%(levelname)s %(message)s', level=logging.INFO)

def get_args():
    parser = argparse.ArgumentParser(
        prog = 'Seeker SARIF export script',
        description = 'Export all project vulnerabilities to SARIF')
    parser.add_argument('--project', type=str,
                    help='The Seeker project key')
    parser.add_argument('--url', type=str,
                    help='The Seeker base url http://example.com:8080')
    parser.add_argument('--token', type=str,
                    help='The Seeker API token')
    return parser

def get(url, token):
    logging.info("GET: {0}".format(url))
    seekerHeaders = {
        "Authorization": "Bearer {0}".format(token)
    }

    response = requests.get(url, headers=seekerHeaders, verify=False)
    if response.status_code < 200 or response.status_code >= 300 and response.status_code != 404:
        logging.info(response)
        logging.info(response.text)
        exit(0)
    else:
        return response.json()

def get_all_vulnerabilities(seeker_base, token, projectKeys):
    more_results = True
    offset = 0
    limit = 1000
    results = []
    while more_results:
        url = "/rest/api/latest/vulnerabilities?format=JSON&language=en&limit={0}&offset={1}&includeStacktrace=true&projectKeys={2}&includeHttpHeaders=true&includeHttpParams=true&includeDescription=true&includeRemediation=true&includeSummary=true&includeVerificationProof=true&includeTriageEvents=false&includeComments=false".format(limit, offset, projectKeys)
        url = "{0}{1}".format(seeker_base, url)
        result = get(url, token)
        
        results = results + result
        offset += limit
        logging.info("{0} of {1}".format(len(result), len(results)))
        if len(result) < limit:
            more_results = False

    #logging.info(json.dumps(results, indent=2))
    logging.info("Found {0} vulnerabilities for project {1}".format(len(results), projectKeys))
    return results

def create_sarif_file(vulns, artifacts, rules):
    rules_list = []
    for rule in rules:
        rules_list.append(rules[rule])
    artifact_list = []
    for artifact in artifacts:
        artifact_list.append(artifacts[artifact])
    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Seeker",
                        "rules": rules_list
                    }
                },
                "artifacts": artifact_list,
                "results": vulns
            }
        ],
    }

def cleanhtml(raw_html):
  cleanr = re.compile('<.*?>')
  cleantext = re.sub(cleanr, '', raw_html)
  return cleantext

def convert_to_sarif_results(vuln, artifacts, rules):
    logging.info(json.dumps(vuln, indent=2))
    code_location = vuln['CodeLocation'].split(':')
    if not code_location[0] in artifacts:
        artifacts[code_location[0]] = {
          "location": {
            "uri": code_location[0]
          },
          #"length": 3444,
          #"sourceLanguage": "c",
          #"hashes": {
          #  "sha-256": "b13ce2678a8807ba0765ab94a0ecd394f869bc81"
          #}
        }
    if not vuln['CheckerKey'] in rules:
        rules[vuln['CheckerKey']] = {
            "id": vuln['CheckerKey'],
            "messageStrings": {
                "default": {
                  "text": cleanhtml(vuln['Description']),
                  "markdown": vuln['Description']
                }
              },
            "properties": {
                "OWASP2013": vuln['OWASP2013'],
                "PCI-DSS": vuln['PCI-DSS'],
                "CWE-SANS": vuln['CWE-SANS'],
                "OWASP2017": vuln['OWASP2017'],
                "GDPR": vuln['GDPR'],
                "CAPEC": vuln['CAPEC'],
                "OWASPAPI2019": vuln['OWASPAPI2019'],
                "OWASPAPI2023": vuln['OWASPAPI2023'],
                "OWASP2021": vuln['OWASP2021'],
              }
        }
    code_index = list(artifacts.keys()).index(code_location[0])
    rule_index = list(rules.keys()).index(vuln['CheckerKey'])
    headers = {}
    for header in vuln['LastDetectionHttpHeaders']:
        header_item = header.split(': ')
        headers[header_item[0]] = header_item[1]
    params = {}
    for param_item in vuln['LastDetectionHttpParams']:
        param_item = header.split(': ')
        params[param_item[0]] = param_item[1]
    stack_frames = []
    for frame in vuln['StackTrace'].split('\n  '):
        stack_frames.append({"module": frame})
    sariff = {
        "message": {
            "text": cleanhtml(vuln['Summary']),
            "markdown": vuln['Summary']
        },
        "ruleId": vuln['CheckerKey'],
        "ruleIndex": rule_index,
        "level": "error",
        "properties": {
            "severity": vuln['Severity'],
            "CodeLocationType": vuln['CodeLocationType'],
            "LastDetectionCodeLocation": vuln['LastDetectionCodeLocation'],
            "LastDetectionSourceName": vuln['LastDetectionSourceName'],
            "LastDetectionSourceType": vuln['LastDetectionSourceType'],
            "Status": vuln['Status'],
            "VerificationTag": vuln['VerificationTag'],
            "VulnerabilityName": vuln['VulnerabilityName']
        },
        "stacks": [
            {
                "frames": stack_frames,
            }
        ],
        "occurrenceCount": vuln['DetectionCount'],
        "hostedViewerUri": vuln['SeekerServerLink'],
        "webRequest": {
            "protocol": "http",
            "target": vuln['LastDetectionURL'],
            "headers": headers,
            'parameters': params
        },
        "locations": [
            {
            "physicalLocation": {
                "artifactLocation": {
                "uri": code_location[0],
                    "index": code_index
                },

            }
            }
        ]
    }
    if len(code_location) > 1:
        sariff['locations'][0]['physicalLocation']['region'] = {"startLine": int(code_location[1])}

    #TODO: webrequest
    #TODO: triage / status
    return sariff, artifacts, rules

def main():
    #TODO: load params
    parser = get_args()
    args = parser.parse_args() 
    logging.info(args)
    if not args.project or not args.url or not args.token:
        logging.error("url, token, and project are required input fields. Use -h for more information.")
        exit(1)
    # get seeker vulns
    vulnerabilities = get_all_vulnerabilities(args.url, args.token, args.project)

    sarif = []
    artifacts = {}
    rules = {}
    for vuln in vulnerabilities:
        # convert to sarif
        vuln_sarif, artifacts, rules = convert_to_sarif_results(vuln, artifacts, rules)
        sarif.append(vuln_sarif)
    
    logging.info("Converted {0} Seeker vulnerabilities to SARIF".format(len(sarif)))
    # export to file
    logging.info("Creating SARIF file.")
    sarif_file = create_sarif_file(sarif, artifacts, rules)
    with open("{0}.sarif".format(args.project), 'w') as f:
        f.write(json.dumps(sarif_file, indent=2))
    logging.info("Done.")

if __name__ == "__main__":
    main()