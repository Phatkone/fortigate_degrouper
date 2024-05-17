# Fortigate De-Grouper
## Description
Expands Address, Address6 and Service groups into individual objects for firewall policies  
Great for cleaning up poorly named groups converted from other systems such as ASAs  

## Usage
`python degroup.py -fw <host> -p <port> -k <apikey> -vd <vdom>`


## Dependancies
The following pip packages are dependancies
- urllib3
- requests
- json
- argparse


## Author
Credit to anyone who worked on the code or provided code
yourself as author
[Phatkone](https://github.com/phatkone)

## License
[GNU GPL 3.0](LICENSE) License applies.
