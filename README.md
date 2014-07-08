## ssh-agent-utils: ssh-agent proxy utilities
This is a set of utilities which create a new agent socket which proxies communication  
to/from the socket to the real ssh-agent, as specified in the `SSH_AUTH_SOCK` environment variable.  

### ssh-agent-on-demand
This is a semi-transparent proxy which can add public key(s) to the public key identity  
response produced by the ssh-agent, if not already present. If the client then requests  
that the agent sign with a key which was added to the response, (ie. the real  
ssh-agent does not have the corresponding private key), ssh-add is called to add the  
corresponding private key on-demand, which then uses `SSH_ASKPASS` as necessary.  
This is useful for pass-phrase protected private keys which are not automatically loaded  
and/or which have a limited lifetime. The pass-phrase need only be entered when the key  
is used for the first time, or after it has expired.  
This avoids having to manually remember to (re-)add the required key before attempting to use  
it, if it is not loaded/expired.  
When used with agent-forwarding, it also avoids the need to switch to another shell to run ssh-add.  
Optionally, this can also add the public key file comment to the corresponding key data comment  
returned by the real agent.  

#### For example

    ssh foo
        SSH askpass pops up
        Enter key passphrase
        Success

Instead of:

    ssh foo
        Enter password:
    <ctrl-c>
    <switch shell, if using agent forwarding>
    ssh-add bar
        Enter key passphrase
    <switch back, if using agent forwarding>
    ssh foo
        Success

### ssh-agent-passthrough
This is a trivial transparent proxy stub which proxies all communications without change.

### URLs
* This project is hosted at: https://github.com/JGRennison/ssh-agent-utils
* A Ubuntu PPA is currently available at https://launchpad.net/~j-g-rennison/+archive/ssh-agent-utils

### Build dependencies
* libb64  
* libmhash  

### Building
Should build out of the box with `./configure`, `make` and `make install`.  
Requires C++11 support.  

### License:
GPLv2
