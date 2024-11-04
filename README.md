# Pleasant Lookup
## Installation
Python dependencies

* requests

The latest version is v1.2.0

```commandline
ansible-galaxy collection install tombosmansibm.pleasant_lookup
```

## Configuration parameters
In ansible.cfg, you can add these global settings:
```
[pleasant_lookup]
ca_path = /etc/ssl/certs/ca-bundle.crt
timeout = 15
host = https://pleasant.com:10001
username = XXXXXX
password = YYYYYY

```
## Parameters
### Required

* pleasant_host: the pleasant host (https://pleasant.com:10001)
* username: username to authenticate to Pleasant
* password: password to authenticate to Pleasant
* pleasant_search: the search term to look for

### Optional

* pleasant_filter_username: only return search results for this username
* pleasant_filter_path: only return results that begin with this path.  Should always begin with '/Root'
* verify: set to False to disable SSL verification
* timeout: defaults to 5
* pleasant_api_version: defaults to v5.  Other choice is v6.

## Examples

Simple lookup
```yaml
- name: password
  debug: msg="{{ lookup('tombosmansibm.pleasant_lookup.password', pleasant_host='https://pleasant.com:10001', username='bob', password='hunter2', pleasant_search='itemname') }}"
```

lookup example with search parameter and filter on username and path with reference to the ca bundle of the system.

```yaml
- name: Lookup
  run_once: True
  debug:
    msg: "{{ lookup('tombosmansibm.pleasant_lookup.password', pleasant_host='https://pleasant.com:10001', username='myuser', password='mypassword', pleasant_filter_path='Root/DEV/', pleasant_filter_username='root', pleasant_search='root', verify='/etc/ssl/certs/ca-bundle.crt', timeout=2) }}"
  delegate_to: localhost
```
The result is a list of items:
```json
 [{
     "password": "the password",
     "path": "Root/Path/",
     "username": "the username"
 }]
```