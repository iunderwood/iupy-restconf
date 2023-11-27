# iupy-restconf

Ian Underwood's Python RESTCONF Module

## About

This package provides a RESTCONF class to manage interactions with network devices that use the RESTCONF protocol as defined in RFC-8040.

This document is woefully incomplete.

## Installation

Module installation can be managed with PIP:

pip3 install iupy-restconf

## Usage

This provides a top-level restconf import which should be imported into your project as such:

```python
import restconf

router = restconf.RestConf()

router.connect(transport='https',
               host='192.168.1.1',
               un='restuser',
               pw='restpass')
```

From there, using the module is a matter of defining the method and path that is useful for your application:

```python
response = router.get("data/native/interfaces")
```

Operations such as push, post, and patch use a second positional arguement as a dictionary that provides the structure required.

```python
response = router.post("data/openconfig-interfaces:interface", newconfig_dict)
```

For POST, it is possible to set the dictionary as None if there is nothing to pass along.

```python
response = router.post("operations/cisco-ia:save-config", None)
```

Since RESTCONF is authorized on a per-request basis, there is no connection open or close method as with a general REST API which generates and stores a session.

## Device Capabilities

Routers that are RFC-8040 compliant provide a list of modules that they support.  This allows a script to check for basic capabilities.

```python
router.get_data_modules()

if router.check_data_modules("Cisco-IOS-XE-native"):
    print("This supports IOS-XE Native Calls")
```

## Semi-Compliant Devices

Arista Networks routers are not strictly RFC compliant.  Because of this, they will not properly complete RESTCONF discovery upon router connection.  The discovery process can be bypassed by passing the "port" and "base" parameters on the connect:

```python
router.connect(transport='https',
               host='192.168.1.1',
               port=6020,
               base='restconf',
               un='username',
               pw='password')
```