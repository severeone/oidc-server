OIDC Authorization Server
==============================

## Local Server Setup

* Install Mustache

    ```bash
    sudo apt-get install -y ruby-mustache 
    ```

* Install docker

    ```bash
    sudo apt-get install -y docker.io
    sudo groupadd docker
    sudo gpasswd -a ${USER} docker
    sudo service docker restart
    # logout and then log back in.
    # If you're using Ubuntu, that means click 'log out' of your
    # whole desktop session, not just close and re-open gnome-terminals
    ```

* Install python's docker extension

    ```bash
    sudo apt-get install python-pip
    sudo pip install docker
    ```

* Build a local auth server

    ```bash
    ./build-local.sh
    ```
    
* Local server is listening on port 9000
