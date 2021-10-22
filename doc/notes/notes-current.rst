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

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

- Restore NSEC Aggressive Cache (``synth-from-dnssec``) as active by default
  following reworking of the code to find the potentially covering NSEC record.
  :gl:`#1265`

Bug Fixes
~~~~~~~~~

- None.
