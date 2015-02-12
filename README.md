# PAM USB Serial authentication

PAM Module to authenticate users with serial of USB devices 

## About
`pam-usb-serial` is a PAM module to authenticate users with serial from USB device serial. Simpler than pam-usb, it doesn't need to mount file system. It allows to use any device with iSerial specified and compare it with simple flat file.

Basically it's used to add authentication check with `login` (physical access). So it should be use with PAM option `required`.

By default the user to use is `root` and the file which contains keys is `/etc/pam_serial_keys` but it can be configure in PAM configuration like following : `pam-usb-serial.so <user> <keys file>`

## Limitation
This is the first version for POC (not productized), there are some limitations:
  * To use different USB device by user just create multiple entry in PAM configuration (see examples)
  * Unable to cancel USB device check (or set login timeout, e.g. pam_faildelay.so)

## Examples
Below some PAM configuration examples.

Force any user to plug valid USB device :
```
auth       optional    pam_faildelay.so   delay=3000000
auth       required    pam-usb-serial     *  /etc/pam-usb-serial.keys
```

## Author(s)
Raphael Medaer <raphael.medaer@straightforward.me>


