'''
Name: Alexander Zsikla
Date: 10/28/20
fuzz.py

This is a program that runs a basic fuzzer on a webpage and reports
which javascript objects were able to penetrate the webpage
'''

import argparse
import time
import requests
from bs4 import BeautifulSoup as bs

NUM_VULNERABILITIES = 1
URL = "http://www.cs.tufts.edu/comp/120/hackme.php"
VERBOSITY = 15

def extract_details(form):
    '''
    Extracts the action, method, and the input attributes
    from a given form

    Input
    * form - a beautifulsoup object that is one of the forms
             on a given webpage

    Output
    * a dictionary with 3 fields
        - action: a string with the action of the form
        - method: a string with the method of the form
        - inputs: a list of objects with the name and value
                  of each input in the form
    '''

    details = {
        'action': form['action'].lower(),
        'method': form['method'].lower(),
        'inputs': []
    }

    for html_input in form.find_all('input'):
        if html_input.get('name') == None:
            continue

        details['inputs'].append({
            'name': html_input.get('name'),
            'value': html_input.get('value')
        })

    return details

def create_payload(fields):
    '''
    Creates the default payload

    Input
    * fields: a dictionary with 3 fields
              (same as the output of extract_details)

    Output:
    * a dictionary which represents a payload
    '''
    init = {
        'action': fields['action'],
        'methods': fields['method']
    }

    for field in fields['inputs']:
        init[field['name']] = field['value']

    return init

def try_payloads(info, web, fuzzFile):
    '''
    Given a fuzzFile, a webpage, and information about a form,
    checks the webpage for any vulnerablilites

    Input:
    * info - a dictionary with 3 fields
              (same as the output of extract_details)
    * web - a string representing a webpage
    * fuzzFile - a filename whose contents have fuzz vectors 
                 separated by newlines

    Output:
    * a list of vulnerabilities
    '''
    global VERBOSITY
    
    fileInfo = open(fuzzFile, "r")
    possValues = fileInfo.read().split('\n')
    fileInfo.close()

    if info['action'] not in web:
        default_targetURL = web + info['action']
    else:
        default_targetURL = web
    
    default_payload = create_payload(info)

    cnt = 0
    max_iter = (len(default_payload) - 2) * len(possValues)
    next_print = (max_iter // VERBOSITY)

    vulnerabilities = []
    print("Starting the vulnerability scans")
    print(f"Scan Completion Percentage: {(cnt / max_iter) * 100:.2f}%")
    for field in default_payload.keys():
        if field == 'action' or field == 'methods':
            continue

        for js_line in possValues:
            targetURL = default_targetURL
            payload = default_payload.copy()

            payload[field] = js_line
            try:
                if info['method'] == 'post':
                    res = requests.post(targetURL, data=payload)
                else:
                    res = requests.get(targetURL, params=payload)
            except:
                time.sleep(3)
                if info['method'] == 'post':
                    res = requests.post(targetURL, data=payload)
                else:
                    res = requests.get(targetURL, params=payload)

            if js_line in res.text:
                vulnerabilities.append((targetURL, field, js_line))

            targetURL += f"?{field}={js_line}"
            try:
                if info['method'] == 'post':
                    res = requests.post(targetURL)
                else:
                    res = requests.get(targetURL)
            except:
                time.sleep(3)
                if info['method'] == 'post':
                    res = requests.post(targetURL)
                else:
                    res = requests.get(targetURL)

            if js_line in res.text:
                vulnerabilities.append((targetURL, None, None))

            cnt += 1
            if cnt >= next_print:
                print(f"Scan Completion Percentage: {(cnt / max_iter) * 100:.2f}%")
                next_print += (max_iter // VERBOSITY)

    return vulnerabilities

def print_vulnerability(vulner, oFile):
    '''
    prints out all vulnerabilities of a given website

    Input
    * vulner: a list of tuples that have the url, js script, and the field
    * oFile: a filename that the client wants the output piped to

    Output: N/A
    '''
    global NUM_VULNERABILITIES

    if oFile != None:
        outputFile = open(oFile, 'w')
        for url,js,field in vulner:
            outputFile.write(f"Vulnerability #{NUM_VULNERABILITIES}\n")
            outputFile.write(f"* URL: {url}\n")
            outputFile.write(f"* Javascript: {js}\n")
            outputFile.write(f"* Field: {field}\n\n")
            NUM_VULNERABILITIES += 1

        return

    print()
    for url,js,field in vulner:
        print(f"Vulnerability #{NUM_VULNERABILITIES}")
        print(f"* URL: {url}")
        print(f"* Javascript: {js}")
        print(f"* Field: {field}\n")
        NUM_VULNERABILITIES += 1

def main():
    parser = argparse.ArgumentParser(description='A fuzzer to determine basic \
                                            XSS vulnerabilities \
                                            on any website')
    parser.add_argument('-l', dest='fuzz', required=True,
                              help='A text file containing a list \
                                    of fuzz vectors')
    parser.add_argument('-w', dest='website', required=False, default=URL
                        help='A website to detect vulnerabilities on')
    parser.add_argument('-o', dest='oFile', required=False,
                        help='A file to store the output of the program')
    parser.add_argument('-v', dest='verb', required=False, default=15,
                        help="Verbosity of the program"

    args = parser.parse_args()

    try:
        data = requests.get(args.website)
    except:
        print(f"\nERROR - '{args.website}' is not a website")
        print("Input a valid URL\n")
        exit(2)

    if data.status_code not in range(200,300):
        print(f"\nERROR - STATUS CODE WAS {data.status_code}")
        print("Now exiting\n")
        exit(3)

    try:
        forms = bs(data.content, 'html.parser').find_all("form")
    except:
        print(f"ERROR - {args.website} could not be parsed \
                into html attributes")
        exit(4)

    for form in forms:
        details = extract_details(form)
        vulnerabilities = try_payloads(details, args.website, args.fuzz)
        print_vulnerability(vulnerabilities, args.oFile)

if __name__ == '__main__':
    main()
    exit(0)
