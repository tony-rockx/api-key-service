API Key Service
=====================================

<URL>

How does this work?
----------------

API Key Service allow admin users and internal applications to create corresponding API keys and secrets for permissioned access to Wallet Services. This service is recommended to be hosted on a separate server from other security conscious services.


Application Flow
-------

Admin UI <-> API Key Service

Address Whitelisting Service <-> API Key Service

Wallet Aggregator <-> API Key Service


Available End points
-------
- GET /test
- POST /account/
- POST /authorisation/

ENV parameters
-------
Available at ./instructions/env.md


Database Initialisation
-------
Available at ./instructions/db.md


## Instructions

To test application:

```bash
$ npm test
```

Install NPM modules on fresh deployment:

```bash
$ npm install
```

To run in development mode:

```bash
$ node index.js
```

To run in production mode:

```bash
$ pm2 start api-key-service/index.js --name "api-key-service"
```
