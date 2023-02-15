# tombosmansibm.pleasant_lookup collection

# Overview
This is a Ansible collection that contains a lookup plugin to retrieve passwords from Pleasant Solutions.

# Requirements
## Operating systems

This role will work on the following operating systems:

 * Red Hat
 * Debian
 * Ubuntu

So, you'll need one of those operating systems.. :-)
Please send Pull Requests or suggestions when you want to use this role for other Operating systems.

## Ansible 2.10 and higher

Tested on Ansible 2.10, but may work on lower versions.

## Pleasant versions

Only tested on Pleasant server 7.x

# Installation
## Python dependencies
Install the requests module

* requests

## Installation
```commandline
ansible-galaxy collection install tombosmansibm.pleasant_lookup
```

# Variables

## Configuration

In ansible.cfg, you can add these settings:

```
[pleasant_lookup]
ca_path = /etc/ssl/certs/ca-bundle.crt
timeout = 15
```

## Required

* pleasant_host: the host
* username: username to authenticate to Pleasant
* password: password to authenticate to Pleasant
* pleasant_search: the search term to look for

## Optional

* pleasant_filter_username: only return search results for this username
* pleasant_filter_path: only return results that begin with this path.  Should always begin with '/Root'
* verify: set to False to disable SSL verification
* timeout: defaults to 5
* pleasant_api_version: defaults to v5.  Other choice is v6.

# Author Information

Please send suggestion or pull requests to make this role better. 
Also let us know if you encounter any issues installing or using this role.


