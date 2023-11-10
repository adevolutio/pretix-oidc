Mozilla OIDC Auth Backend
==========================

This is a plugin for `pretix`_. 

This is a plugin for pretix that provides a pluggable authentication backend for OIDC servers.

Development setup
-----------------

1. Make sure that you have a working `pretix development setup`_.

2. Clone this repository.

3. Activate the virtual environment you use for pretix development.

4. Execute ``python setup.py develop`` within this directory to register this application with pretix's plugin registry.

5. Execute ``make`` within this directory to compile translations.

6. Restart your local pretix server. You can now use the plugin from this repository for your events by enabling it in
   the 'plugins' tab in the settings.

This plugin has CI set up to enforce a few code style rules. To check locally, you need these packages installed::

    pip install flake8 isort black docformatter

To check your plugin for rule violations, run::

    docformatter --check -r .
    black --check .
    isort -c .
    flake8 .

You can auto-fix some of these issues by running::

    docformatter -r .
    isort .
    black .

To automatically check for these issues before you commit, you can run ``.install-hooks``.

Docker Production setup
-----------------

1. Create a custom Docker-Image with installed plugin like described on the pretix documentation (https://docs.pretix.eu/en/latest/admin/installation/docker_smallscale.html#install-a-plugin)
   This is an example Dockerfile::
       FROM pretix/standalone:stable
       USER root
       RUN pip3 install pretix-keycloak-oidc
       USER pretixuser
       RUN cd /pretix/src && make production

   Now build the new Image with the following command:
   ``$ docker build . -t mypretix``

2. Start your Docker-Container

3. Edit the pretix.cfg
   Add the following Section::
       [pretix_oidc]
       OIDC_OP_TOKEN_ENDPOINT=https://add_your_url.dev/realms/your_realm/protocol/openid-connect/token
       OIDC_OP_USER_ENDPOINT=https://add_your_url.dev/realms/your_realm/protocol/openid-connect/userinfo
       OIDC_OP_JWKS_ENDPOINT=https://add_your_url.dev/realms/your_realm/protocol/openid-connect/certs
       OIDC_RP_CLIENT_ID=name_of_your_client
       OIDC_RP_CLIENT_SECRET=your*****client******secret
       OIDC_RP_SIGN_ALGO=RS256
       OIDC_RP_IDP_SIGN_KEY=
    

License
-------


Copyright 2022 Evolutio

Released under the terms of the Apache License 2.0



.. _pretix: https://github.com/pretix/pretix
.. _pretix development setup: https://docs.pretix.eu/en/latest/development/setup.html
