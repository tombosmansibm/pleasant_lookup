pleasant_attachment
=========

This role retrieves attachments from Pleasant.
It's suited to retrieve certificates directly from Pleasant.

See https://pleasantpasswords.com/info/pleasant-password-server/m-programmatic-access/restful-api/restful-api-v5

Role Variables
--------------
You can pass your username as a variable, otherwise it's extrapolated from the linux user you're logged in with
    
    pleasant_user: root

The Pleasant server.  Defaults to https://localhost:10001

    pleasant_host: https://pleasant.com:10001

The directory the attachments are exported to.  Defaults to playbook_dir

    pleasant_export_dir: /tmp

The item to search for.  The first match is retrieved.
    
    pleasant_search_term: certificates

To filter only a specific type of files, you can use the attachment filter (using jinja search on the filename)
    
    pleasant_attachment_filter: ".*.p12"

Dependencies
------------

None

Example Playbook
----------------

    - hosts: servers
      vars:
        pleasant_host: https://pleasant.com:10001
      roles:
         - { role: duo.pleasant_attachment }

License
-------

Apache

Author Information
------------------
Tom Bosmans
