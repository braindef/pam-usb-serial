#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include <libusb-1.0/libusb.h>

#include <syslog.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define MAX_SERIAL_LENGTH 1024


void wait4hotplug(struct libusb_context* context)
{
	ssize_t count;
	libusb_device **list = NULL;

	count = libusb_get_device_list(context, &list);

	do {
		libusb_free_device_list(list, 1);
		usleep(500);
	} while (count == libusb_get_device_list(context, &list));

	libusb_free_device_list(list, 1);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	libusb_context *context = NULL;
	libusb_device **list    = NULL;

	int rc        = 0;
	ssize_t count = 0;
	ssize_t index = 0;

	const char *pam_user;
	const char *user      = "root";
	const char *keys_file = "/etc/pam_usb_serial_keys";

    int retry     = 0;
    int max_retry = -1;

	FILE *file;
	char line[MAX_SERIAL_LENGTH];

	int found = 0;

	// Open logs
	openlog("pam_usb_serial", LOG_CONS, LOG_AUTH);

	// Retrieve options from arguments ...
	// ... users
	if (argc >= 1) {
		user = argv[0];
	}

	// ... keys file
	if (argc >= 2) {
		keys_file = argv[1];
	}

    if (argc >= 3) {
        max_retry = atoi(argv[2]);
    }

	if (pam_get_user(pamh, &pam_user, NULL) != 0) {
		return PAM_AUTH_ERR;
	}

	if ((strcmp(user, "*") != 0) && (strcmp(user, pam_user) != 0)) {
		return PAM_SUCCESS;
	}

	// Attempt to open keys file
	if (! (file = fopen(keys_file, "r"))) {
		syslog(LOG_EMERG, "Failed to open serial keys file %s.\n", keys_file);
		return PAM_SYSTEM_ERR;
	}

	// Initialize USB library context
	rc = libusb_init(&context);
	if (rc != 0) {
		syslog(LOG_EMERG, "Failed to initialize libusb (libusb_init)");
		return PAM_SYSTEM_ERR;
	}

	while (! found) {
		// Retrieve USB device list
		count = libusb_get_device_list(context, &list);
		if (count < 0) {
			syslog(LOG_EMERG, "Failed to get USB device list");
			return PAM_SYSTEM_ERR;
		}

		for (index = 0; (index < count) && (! found); ++index) {
			libusb_device *device = list[index];
			libusb_device_handle *device_handle;
			struct libusb_device_descriptor desc = {0};

			rc = libusb_get_device_descriptor(device, &desc);

			if (rc != 0) {
				// Unable to get device descriptor
				syslog(LOG_ERR, "Failed to get USB device descriptor");
				continue;
			}

			if (desc.iSerialNumber <= 0) {
				// Not any serial number for this device
				syslog(LOG_DEBUG, "No serial number found for device %x:%x", desc.idVendor, desc.idProduct);
				continue;
			}

			// Open device to get handle
			if (libusb_open(device, &device_handle) != 0) {
				// Failed to open device
				syslog(LOG_EMERG, "Error openning device %x:%x", desc.idVendor, desc.idProduct);
				continue;
			}

			unsigned char serial[MAX_SERIAL_LENGTH];
			if (libusb_get_string_descriptor_ascii(device_handle, desc.iSerialNumber, serial, sizeof(serial)) >= 0) {

				// Parse keys file line by line and compare with current serial device
				rewind(file);
				while (fgets(line, sizeof(line), file) && (! found)) {
					char *nl;
					if ((nl = strchr(line, '\n')) != NULL) {
						*nl = '\0';
					}

                    if (strcmp(line, "") == 0) {
                        // by pass empty lines
                        continue;
                    }

					if (strcmp(line, serial) == 0) {
						syslog(LOG_NOTICE, "Well USB device serial detected");
						found = 1;
					}
				}
			}

			libusb_close(device_handle);
		}

		// Free device list
		libusb_free_device_list(list, 1);

        if (max_retry == retry) {
            break;
        }
        retry++;

		if (! found) {
			// Display advertise for user
			printf("No USB device found, please plug in...\n");

			wait4hotplug(context);
		} else {
			printf("USB device detected !\n");
		}
	}

	// Close USB library session
	libusb_exit(context);

	// Close file
	fclose(file);
	
	// Close log
	closelog();

	// Return success (or not) depending found key
	if (! found) {
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SERVICE_ERR;
}
