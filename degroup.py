"""
Author: Phatkone
Description: Bulk update tool for Fortigates to expand address and service groups into policies.
Dependencies: requests, urllib3, argparse, json
Usage: `python3 degroup.py` or `python3 degroup.py -fw <host ip or fqdn> -p <host mgmt port> -k <api key> -vd <vdom>`
 All inputs required are in prompt format within the script.
Version: 1.2
DISCLAIMER: By using this tool, the user accepts all liability for the results 
and agree that the creator accepts no liability for any unintended outcomes or interruptions to systems
 
GNU GPL License applies.

           ,,,
          (. .)
-------ooO-(_)-Ooo-------

"""
import urllib3, argparse
from requests import session
from json import dumps

def session_init(headers: dict = {}, verify: bool = True) -> session:
    s = session()
    s.verify = verify
    s.headers = headers
    return s

def api_get(s: session, url: str) -> dict:
    r = s.get(url)
    if r.status_code == 200:
        return r.json()
    return {}

def get_members(in_dict: dict) -> dict:
    out_dict = {}
    if not 'results' in in_dict.keys() or not in_dict['size'] > 0:
        return out_dict
    for r in in_dict['results']:
        gname = r['name']
        members = []
        for m in r['member']:
            members.append(m['name'])
        out_dict[gname] = members
    return out_dict

def parse_policies(in_dict: dict) -> dict:
    out_dict = {}
    if 'results' in in_dict.keys() and in_dict['size'] > 0:
        for p in in_dict['results']:
            id = p['policyid']
            name = p['name']
            sorc = p['srcaddr']
            sorc6 = p['srcaddr6']
            dest = p['dstaddr']
            dest6 = p['dstaddr6']
            srvc = p['service']
            src = []
            src6 = []
            dst = []
            dst6 = []
            svc = []
            for i in sorc:
                src.append(i['name'])
            for i in sorc6:
                src6.append(i['name'])
            for i in dest:
                dst.append(i['name'])
            for i in dest6:
                dst6.append(i['name'])
            for i in srvc:
                svc.append(i['name'])
            out_dict[id] = {
                'id': id,
                'name': name,
                'src': src,
                'src6': src6,
                'dst': dst,
                'dst6': dst6,
                'svc': svc,
                'obj': p
            }
    return out_dict

def main(host: str, apikey: str, vdom: str = 'root', port: int = 443, verbose: bool = False, verify: bool = True, *args, **kwargs):
    if not verify:
        urllib3.disable_warnings()
        if verbose:
            print("Insecure mode enabled, Disabling insecure requests warning")
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(apikey)
    }
    if verbose:
        print("Enabling verbose logging for requests calls")
        import logging
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    s = session_init(headers, verify)
    base_url = 'https://{}:{}/api/v2/cmdb/'.format(host, port)
    if verbose:
        print("Retrieving firewall service groups")
    svc_groups = api_get(s, base_url + 'firewall.service/group?vdom={}'.format(vdom))
    if verbose:
        print("Successfully retrieved service groups, raw output: {}\n\n Retrieving Firewall IPv4 Address Groups".format(dumps(svc_groups, indent=2)))
    addr_groups = api_get(s, base_url + 'firewall/addrgrp?vdom={}'.format(vdom))
    if verbose:
        print("Successfully retrieved service groups, raw output: {}\n\n Retrieving Firewall IPv6 Address Groups".format(dumps(addr_groups, indent=2)))
    addr6_groups = api_get(s, base_url + 'firewall/addrgrp6?vdom={}'.format(vdom))
    if verbose:
        print("Successfully retrieved service groups, raw output: {}\n\n Retrieving Firewall Policies".format(dumps(addr6_groups, indent=2)))
    policies = api_get(s, base_url + 'firewall/policy?vdom={}'.format(vdom))
    if verbose:
        print("Successfully retrieved service groups, raw output: {}\n\n Processing Groups and Policies into dictionaries to simplify manipulation".format(dumps(policies, indent=2)))
    
    svc_grps = get_members(svc_groups) if 'results' in svc_groups.keys() and svc_groups['size'] > 0 else {}
    addr_grps = get_members(addr_groups) if 'results' in addr_groups.keys() and addr_groups['size'] > 0 else {}
    addr6_grps = get_members(addr6_groups) if 'results' in addr6_groups.keys() and addr6_groups['size'] > 0 else {}
    pols = parse_policies(policies) if 'results' in policies.keys() and policies['size'] > 0 else {}
    if verbose:
        print("GrProcessed groups:\n Service Groups: {}\n IPv4 Address Groups: {}\n IPv6 Address Groups: {}\n Policies: {}".format(dumps(svc_groups, indent=2), dumps(addr_grps, indent=2), dumps(addr6_grps, indent=2), dumps(pols, indent=2)))

    if verbose:
        print("Looping through policies, identifying groups in policies, building dictionary of policies to be updated.")
    edit_list = {}
    for id, pol in pols.items():
        edit_list[id] = {}
        for i in pol['src']:
            if i in addr_grps.keys():
                if 'src' in edit_list[id].keys():
                    edit_list[id]['src'] += addr_grps[i]
                else:
                    edit_list[id]['src'] = addr_grps[i]
                if 'src_rm' in edit_list[id].keys():
                    edit_list[id]['src_rm'].append(i) 
                else:
                    edit_list[id]['src_rm'] = [i]
        for i in pol['src6']:
            if i in addr6_grps.keys():
                if 'src6' in edit_list[id].keys():
                    edit_list[id]['src6'] += addr6_grps[i]
                else:
                    edit_list[id]['src6'] = addr6_grps[i]
                if 'src6_rm' in edit_list[id].keys():
                    edit_list[id]['src6_rm'].append(i) 
                else:
                    edit_list[id]['src6_rm'] = [i]
        for i in pol['dst']:
            if i in addr_grps.keys():
                if 'dst' in edit_list[id].keys():
                    edit_list[id]['dst'] += addr_grps[i]
                else:
                    edit_list[id]['dst'] = addr_grps[i]
                if 'dst_rm' in edit_list[id].keys():
                    edit_list[id]['dst_rm'].append(i) 
                else:
                    edit_list[id]['dst_rm'] = [i]
        for i in pol['dst6']:
            if i in addr6_grps.keys():
                if 'dst6' in edit_list[id].keys():
                    edit_list[id]['dst6'] += addr6_grps[i]
                else:
                    edit_list[id]['dst6'] = addr6_grps[i]
                if 'dst6_rm' in edit_list[id].keys():
                    edit_list[id]['dst6_rm'].append(i) 
                else:
                    edit_list[id]['dst6_rm'] = [i]
        for i in pol['svc']:
            if i in svc_grps.keys():
                if 'svc' in edit_list[id].keys():
                    edit_list[id]['svc'] += svc_grps[i]
                else:
                    edit_list[id]['svc'] = svc_grps[i]
                if 'svc_rm' in edit_list[id].keys():
                    edit_list[id]['svc_rm'].append(i) 
                else:
                    edit_list[id]['svc_rm'] = [i]
        if verbose:
            print("Removing policies without groups from dictionary.")
        if not bool(edit_list[id]):
            edit_list.pop(id)
        if verbose:
            print("Policies to be edited: {}".format(dumps(edit_list, indent=2)))
    
    if not bool(edit_list):
        print("No Policies found with Service or Address groups.")
        exit()

    if verbose:
        print("Looping through policies in edit-list, formatting field data structures ")

    for id, pol in edit_list.items():

        p = pols[id]['obj']
        p_src = p['srcaddr']
        p_src6 = p['srcaddr6']
        p_dst = p['dstaddr']
        p_dst6 = p['dstaddr6']
        p_svc = p['service']
        
        if verbose:
            print("Removing duplicate entries from object lists.")

        if 'src' in pol.keys():
            pol['src'] = list(dict.fromkeys(pol['src']))
        if 'dst' in pol.keys():
            pol['dst'] = list(dict.fromkeys(pol['dst']))
        if 'src6' in pol.keys():
            pol['src6'] = list(dict.fromkeys(pol['src6']))
        if 'dst6' in pol.keys():
            pol['dst6'] = list(dict.fromkeys(pol['dst6']))
        if 'svc' in pol.keys():
            pol['svc'] = list(dict.fromkeys(pol['svc']))

        
        if verbose:
            print("Building data structure for policy {}:{}".format(id, pols[id]['name']))
        changes = {}
        if 'src' in pol.keys():
            changes['src'] = []
            changes['src_rm'] = []
            pol['src'] += pols[id]['src']
            for i in pol['src_rm']:
                changes['src_rm'].append(i)
                pol['src'].remove(i)
            p_src = []
            for src in pol['src']:
                changes['src'].append(src)
                p_src.append({
                    "name": src,
                    "q_origin_key": src
                })
            if verbose:
                print("Source IPv4 Address structures made: {}".format(p_src))
        if 'dst' in pol.keys():
            changes['dst'] = []
            changes['dst_rm'] = []
            pol['dst'] += pols[id]['dst']
            for i in pol['dst_rm']:
                changes['dst_rm'].append(i)
                pol['dst'].remove(i)
            p_dst = []
            for dst in pol['dst']:
                changes['dst'].append(dst)
                p_dst.append({
                    "name": dst,
                    "q_origin_key": dst
                })
            if verbose:
                print("Destination IPv4 Address structures made: {}".format(p_dst))
        if 'src6' in pol.keys():
            changes['src6'] = []
            changes['src6_rm'] = []
            pol['src6'] += pols[id]['src6']
            for i in pol['src6_rm']:
                changes['src6_rm'].append(i)
                pol['src6'].remove(i)
            p_src6 = []
            for src6 in pol['src6']:
                changes['src6'].append(src6)
                p_src6.append({
                    "name": src6,
                    "q_origin_key": src6
                })
            if verbose:
                print("Source IPv6 Address structures made: {}".format(p_src6))
        if 'dst6' in pol.keys():
            changes['dst6'] = []
            changes['dst6_rm'] = []
            pol['dst6'] += pols[id]['dst6']
            for i in pol['dst6_rm']:
                changes['dst6_rm'].append(i)
                pol['dst6'].remove(i)
            p_dst6 = []
            for dst6 in pol['dst6']:
                changes['dst6'].append(dst6)
                p_dst6.append({
                    "name": dst6,
                    "q_origin_key": dst6
                })
            if verbose:
                print("Destination IPv6 Address structures made: {}".format(p_dst6))
        if 'svc' in pol.keys():
            changes['svc'] = []
            changes['svc_rm'] = []
            pol['svc'] += pols[id]['svc']
            for i in pol['svc_rm']:
                changes['svc_rm'].append(i)
                pol['svc'].remove(i)
            p_svc = []
            for svc in pol['svc']:
                changes['svc'].append(svc)
                p_svc.append({
                    "name": svc,
                    "q_origin_key": svc
                })
            if verbose:
                print("Service structures made: {}".format(p_svc))
        
        print("\n\nPolicy {},  ID: {} has the following changes: ".format(p['name'], id))
        if 'src' in changes.keys():
            print("Source IPv4 from: \n {} \nto \n {} \nRemoving Group(s): {}\n".format(", ".join(pols[id]['src']), ", ".join(changes['src']), ", ".join(changes['src_rm'])))
        if 'src6' in changes.keys():
            print("Source IPv6 from: \n {} \nto \n {} \nRemoving Group(s): {}\n".format(", ".join(pols[id]['src6']), ", ".join(changes['src6']), ", ".join(changes['src6_rm'])))
        if 'dst' in changes.keys():
            print("Destination IPv4 from: \n {} \nto \n {} \nRemoving Group(s): {}\n".format(", ".join(pols[id]['dst']), ", ".join(changes['dst']), ", ".join(changes['dst_rm'])))
        if 'dst6' in changes.keys():
            print("Destination IPv6 from: \n {} \nto \n {} \nRemoving Group(s): {}\n".format(", ".join(pols[id]['dst6']), ", ".join(changes['dst6']), ", ".join(changes['dst6_rm'])))
        if 'svc' in changes.keys():
            print("Service from: \n {} \nto \n {} \nRemoving Group(s): {}\n".format(", ".join(pols[id]['svc']), ", ".join(changes['svc']), ", ".join(changes['svc_rm'])))


        p['srcaddr'] = p_src
        p['srcaddr6'] = p_src6
        p['dstaddr'] = p_dst
        p['dstaddr6'] = p_dst6
        p['service'] = p_svc
        if input("\nUpdate policy: {}? (y/n)  ".format(p['name'])).lower() == 'y':
            r = s.put(base_url + "firewall/policy/{}?vdom={}&policyid={}".format(id, vdom, id), data=dumps([p]))
            if r.status_code == 200:
                print("Successfully updated policy {}: {}\n\n".format(id, p['name']))
        else:
            print("Skipping {}\n\n".format(p['name']))


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='Fortigate Group Expander')
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output") # To be implemented still
        parser.add_argument('-i', '--insecure', action='store_true', help="Ignore unknown or untrusted certificates")
        parser.add_argument('-fw', '--host', type=str, metavar="HOST", help="Fortigate IP / Hostname")
        parser.add_argument('-p', '--port', type=int, help="Port for management interface, defaults to 443 if not defined")
        parser.add_argument('-k', '--key', type=str, help="API Key for firewall connection. Note: Must have read permissions on firewall objects and read/write for firewall policies")
        parser.add_argument('-vd', '--vdom', type=str, help="VDOM to modify, defaults to root if not defined")
        args = parser.parse_args()

        verbose = args.verbose
        verify = False if args.insecure else True
        port = args.port if args.port else 443 
        host = args.host if args.host is not None else input("What is the IP or FQDN of the Fortigate? \n> ")
        key = args.key if args.key is not None else input("What is the API Key? \n> ")
        vdom = args.vdom if args.vdom else 'root'
        
        main(**{'host': host, 'apikey': key, 'vdom': vdom, 'verbose': verbose, 'verify': verify, 'port': port})
    except KeyboardInterrupt:
        print("Stopped by Keyboard Interrupt")