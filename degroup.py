"""
Author: Phatkone
Description: Bulk update tool for Fortigates to expand address and service groups into policies.
Dependencies: requests, urllib3, argparse, json
Usage: `python3 degroup.py` or `python3 degroup.py -fw <host ip or fqdn> -p <host mgmt port> -k <api key> -vd <vdom>`
 All inputs required are in prompt format within the script.
Version: 1.1
DISCLAIMER: By using this tool, the user accepts all liability for the results 
and agree that the creator accepts no liability for any unintended outcomes or interruptions to systems
 
GNU GPL License applies.

           ,,,
          (. .)
-------ooO-(_)-Ooo-------

"""
import urllib3, argparse, json
from requests import session

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
                'svc': svc
            }
    return out_dict

def main(host: str, apikey: str, vdom: str = 'root', port: int = 443, verbose: bool = False, verify: bool = True, *args, **kwargs):
    if not verify:
        urllib3.disable_warnings()
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(apikey)
    }
    s = session_init(headers, verify)
    base_url = 'https://{}:{}/api/v2/cmdb/'.format(host, port)
    svc_groups = api_get(s, base_url + 'firewall.service/group?vdom={}'.format(vdom))
    addr_groups = api_get(s, base_url + 'firewall/addrgrp?vdom={}'.format(vdom))
    addr6_groups = api_get(s, base_url + 'firewall/addrgrp6?vdom={}'.format(vdom))
    policies = api_get(s, base_url + 'firewall/policy?vdom={}'.format(vdom))
    svc_grps = get_members(svc_groups) if 'results' in svc_groups.keys() and svc_groups['size'] > 0 else {}
    addr_grps = get_members(addr_groups) if 'results' in addr_groups.keys() and addr_groups['size'] > 0 else {}
    addr6_grps = get_members(addr6_groups) if 'results' in addr6_groups.keys() and addr6_groups['size'] > 0 else {}
    pols = parse_policies(policies) if 'results' in policies.keys() and policies['size'] > 0 else {}

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
        if not bool(edit_list[id]):
            edit_list.pop(id)

    for id, pol in edit_list.items():
        r = api_get(s, base_url + 'firewall/policy/{}?vdom={}'.format(id, vdom))
        if not 'results' in r.keys():
            print("Unable to pull existing policy. Skipping.")
            continue
        
        p = r['results'][0]
        p_src = p['srcaddr']
        p_src6 = p['srcaddr6']
        p_dst = p['dstaddr']
        p_dst6 = p['dstaddr6']
        p_svc = p['service']
        

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

        print("Policy ID: {} has the following changes: {}".format(id, json.dumps(pol, indent=2)))
        
        if 'src' in pol.keys():
            pol['src'] += pols[id]['src']
            for i in pol['src_rm']:
                pol['src'].remove(i)
            p_src = []
            for src in pol['src']:
                p_src.append({
                    "name": src,
                    "q_origin_key": src
                })
        if 'dst' in pol.keys():
            pol['dst'] += pols[id]['dst']
            for i in pol['dst_rm']:
                pol['dst'].remove(i)
            p_dst = []
            for dst in pol['dst']:
                p_dst.append({
                    "name": dst,
                    "q_origin_key": dst
                })
        if 'src6' in pol.keys():
            pol['src6'] += pols[id]['src6']
            for i in pol['src6_rm']:
                pol['src6'].remove(i)
            p_src6 = []
            for src6 in pol['src6']:
                p_src6.append({
                    "name": src6,
                    "q_origin_key": src6
                })
        if 'dst6' in pol.keys():
            pol['dst6'] += pols[id]['dst6']
            for i in pol['dst6_rm']:
                pol['dst6'].remove(i)
            p_dst6 = []
            for dst6 in pol['dst6']:
                p_dst6.append({
                    "name": dst6,
                    "q_origin_key": dst6
                })
        if 'svc' in pol.keys():
            pol['svc'] += pols[id]['svc']
            for i in pol['svc_rm']:
                pol['svc'].remove(i)
            p_svc = []
            for svc in pol['svc']:
                p_svc.append({
                    "name": svc,
                    "q_origin_key": svc
                })
        
        p['srcaddr'] = p_src
        p['srcaddr6'] = p_src6
        p['dstaddr'] = p_dst
        p['dstaddr6'] = p_dst6
        p['service'] = p_svc
        r['results'][0] = p
        if input("Update policy: {}? (y/n)".format(p['name'])).lower() == 'y':
            r = s.put(base_url + "firewall/policy/{}?vdom={}&policyid={}".format(id, vdom, id), data=json.dumps([p]))
            if r.status_code == 200:
                print("Successfully updated policy {}: {}".format(id, p['name']))


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='Fortigate Group Expander')
        # parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output") # To be implemented still
        parser.add_argument('-i', '--insecure', action='store_true', help="Ignore unknown or untrusted certificates")
        parser.add_argument('-fw', '--host', type=str, metavar="HOST", help="Fortigate IP / Hostname")
        parser.add_argument('-p', '--port', type=int, help="Port for management interface, defaults to 443 if not defined")
        parser.add_argument('-k', '--key', type=str, help="API Key for firewall connection. Note: Must have read permissions on firewall objects and read/write for firewall policies")
        parser.add_argument('-vd', '--vdom', type=str, help="VDOM to modify, defaults to root if not defined")
        args = parser.parse_args()
        # verbose = args.verbose
        verbose = False
        verify = False if args.insecure else True
        port = args.port if args.port else 443 
        host = args.host if args.host is not None else input("What is the IP or FQDN of the Fortigate? \n> ")
        key = args.key if args.key is not None else input("What is the API Key? \n> ")
        vdom = args.vdom if args.vdom else 'root'
        
        main(**{'host': host, 'apikey': key, 'vdom': vdom, 'verbose': verbose, 'verify': verify, 'port': port})
    except KeyboardInterrupt:
        print("Stopped by Keyboard Interrupt")