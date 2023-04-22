import requests
import argparse
import json
from rich.progress import track
import threading 

file_contents = []

def setup_parser():
    '''
    Setup argparse stuff
    '''
    parser = argparse.ArgumentParser(description="Grab malware family hashes from OTX")
    parser.add_argument("family", type=str, help="Specify the malware family you want in the format [name]:[platform]/[sample]. Ex: TrojanDownloader:Win32/Cutwail")
    parser.add_argument("-f", "--format", help="Hash output from md5, sha1, sha256, or all")
    parser.add_argument("-k", "--key", type=str, help="You OTX API key")
    parser.add_argument("-o", "--output", type=str, help="Name of your output file")
    return parser

def grab_hash(page_num: int, key: str, family: str, format: str):

    # Some important variables
    url = "https://otx.alienvault.com/otxapi/malware/samples?"

    headers = {
        "X-OTX-API-KEY":key
    }

    # These are the URL parameters, change them as you see fit
    payload = {
        "family":family,
        "limit":1000,
        "page":page_num
    }

    # Make the updated request and parse to JSON
    hashes = json.loads(requests.get(url, headers=headers, params=payload).text)

    # Loop over the results
    for result in hashes["results"]:
        if format == "md5":
            file_contents.append(result['md5'])
        elif format == "sha1":
            file_contents.append(result['sha1'])
        elif format == "sha256":
            file_contents.append(result['sha256'])
        else:
            file_contents.append(f"{result['md5']} {result['sha1']} {result['sha256']}")

def main():

    print("Starting!")

    # Some important variables
    url = "https://otx.alienvault.com/otxapi/malware/samples?"
    key = ""

    # Setup the argument parser
    parser = setup_parser()
    user_args = parser.parse_args()

    # Check if the API key was supplied, if no then use the supplied key
    if key == "" and user_args.key != None:
        thread_key = user_args.key
        headers = {
            "X-OTX-API-KEY":user_args.key
        }
    elif key != "":
        thread_key = key
        headers = {
            "X-OTX-API-KEY":key
        }
    else:
        print("Missing API key...")
        exit()

    # These are the URL parameters, change them as you see fit
    payload = {
        "family":user_args.family,
        "limit":1,
        "page":1
    }

    # Make first request to get the number of samples
    number = json.loads(requests.get(url, headers=headers, params=payload).text)
    num_samples = number["count"]
    print(f"Expecting {num_samples} hashes")

    # Change the payload back to what it should be normally
    payload["limit"] = 1000
    
    # Create threads array
    threads = []
    for i in range(1, (num_samples//1000)+2):
        t = threading.Thread(target=grab_hash, args=(i,thread_key,user_args.family,user_args.format))
        threads.append(t)
        t.start()

    print(f"Started {len(threads)} threads...")

    for thread in threads:
        thread.join()

     # Check if we should write to a file if so do that
    if user_args.output != None:
        file = open(user_args.output, "w")
        file.write('\n'.join([str(content) for content in file_contents]))
        file.close()
    else:
        for i in file_contents:
            print(i)

    print(f"Successfully wrote hashes to {user_args.output}")
   
if __name__ == "__main__":
    main()
