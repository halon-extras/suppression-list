# Suppression list plugin

This plugin allows you to define custom suppression lists which may be check from HSL (```suppression_list(id, email)```).

## Installation

Follow the [instructions](https://docs.halon.io/manual/comp_install.html#installation) in our manual to add our package repository and then run the below command.

### Ubuntu

```
apt-get install halon-extras-suppression-list
```

### RHEL

```
yum install halon-extras-suppression-list
```

## Configuration

For the configuration schema, see [suppression-list.schema.json](suppression-list.schema.json).

### smtpd.yaml

```
plugins:
  - id: suppression-list
    config:
      lists:
        - id: list1
          path: /var/run/halon/list1.txt
```

### Suppression list format

The following syntax is supported in the suppression list file.

```
localpart@example.com
@example.com
localpart@
/localpart/
```

Lines starting with `#` are treated as comments.

## Exported commands

The default is to auto reload suppression-list files when the configuration changes (`halonctl config reload`). However they can also be be reloaded manually using the halonctl command.

```
halonctl plugin command suppression-list reload list1
```

It's possible to test if an e-mail address is in a suppression list by issuing this command

```
halonctl plugin command suppression-list test list1 local-part@example.com
```

## Exported functions

These functions needs to be [imported](https://docs.halon.io/hsl/structures.html#import) from the `extras://suppression-list` module path.

### suppression_list(id, email)

Check is email in in a suppression list based on its ID.

**Params**

- id `string` - The suppression list ID
- email `string` - The email address

**Returns**

Returns a `boolean` if the email was on the list or not. On error `none` is returned.

**Example**

```
import { suppression_list } from "extras://suppression-list";
echo suppression_list("list1", "user@example.com");
```