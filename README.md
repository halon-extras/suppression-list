# Suppression plugin

This plugin allows you to define custom suppression lists which may be check from HSL (```suppression(id, email)```). The file may be reloaded after being updated using the halonctl command.

```
halonctl plugin command suppression reload list1
```

## Installation

Follow the [instructions](https://docs.halon.io/manual/comp_install.html#installation) in our manual to add our package repository and then run the below command.

### Ubuntu

```
apt-get install halon-extras-suppression
```

### RHEL

```
yum install halon-extras-suppression
```

## Configuration

For the configuration schema, see [suppression.schema.json](suppression.schema.json).

### Suppression list format

The following syntax is supported in the suppression list file.

```
localpart@example.com
@example.com
localpart@
/localpart/
```

## Exported functions

These functions needs to be [imported](https://docs.halon.io/hsl/structures.html#import) from the `extras://suppression` module path.

### suppression(id, email)

Check is email in in a suppression list based on its ID.

**Params**

- id `string` - The suppression list ID
- email `string` - The email address

**Returns**

Returns a `boolean` if the email was on the list or not. On error `none` is returned.

**Example**

```
import { suppression } from "extras://suppression";
echo suppression("list1", "user@example.com");
```