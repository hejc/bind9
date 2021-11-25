.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.21
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Set Extended DNS Error Code 18 - Prohibited if query access is denied to the
  specific client. :gl:`#1836`

- A new configuration option ``require-cookie`` has been introduced, it
  specifies if there should be a DNS COOKIE in the response for a given
  prefix and if not named falls back to TCP.  This is useful if you know
  a given server support DNS COOKIE.  It can also be used to force all
  non DNS COOKIE responses to fall back to TCP.  :gl:`#2295`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- Removing a configured ``catalog-zone`` clause from the configuration, running
  ``rndc reconfig``, then bringing back the removed ``catalog-zone`` clause and
  running ``rndc reconfig`` again caused ``named`` to crash. This has been fixed.
  :gl:`#1608`
