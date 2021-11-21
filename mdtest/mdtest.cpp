#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <freefare.h>
extern "C" {
#include <freefare_internal.h>
}

#include <nfc/nfc.h>
#include <nfc/nfc-types.h>

#include <libutil.h>

#include "proxydriver.h"
#include "mycutter.h"	// testing library.


// ==================================================================
// CUT - testing library.
// ==================================================================
#define	cut_message printf

#define cut_assert_success(last_command) \
    do { \
	cut_assert_equal_int (OPERATION_OK, mifare_desfire_last_picc_error (tag), cut_message ("PICC replied %s", mifare_desfire_error_lookup (mifare_desfire_last_picc_error (tag)))); \
	cut_assert_not_equal_int (-1, res, cut_message ("Wrong return value")); \
    } while (0)

// ==================================================================
static bool
desfire_show_info(MifareTag tag, char* tag_uid)
{
	int res;
	struct mifare_desfire_version_info info;


	res = mifare_desfire_get_version (tag, &info);
	if (res < 0) {
		freefare_perror (tag, "mdtest: mifare_desfire_get_version");
		return false;
	}

	printf ("===> Version information for tag %s:\n", tag_uid);
	printf ("UID:					  0x%02x%02x%02x%02x%02x%02x%02x\n", info.uid[0], info.uid[1], info.uid[2], info.uid[3], info.uid[4], info.uid[5], info.uid[6]);
	printf ("Batch number:			 0x%02x%02x%02x%02x%02x\n", info.batch_number[0], info.batch_number[1], info.batch_number[2], info.batch_number[3], info.batch_number[4]);
	printf ("Production date:		  week %x, 20%02x\n", info.production_week, info.production_year);
	printf ("Hardware Information:\n");
	printf ("	Vendor ID:			0x%02x\n", info.hardware.vendor_id);
	printf ("	Type:				 0x%02x\n", info.hardware.type);
	printf ("	Subtype:			  0x%02x\n", info.hardware.subtype);
	printf ("	Version:			  %d.%d\n", info.hardware.version_major, info.hardware.version_minor);
	printf ("	Storage size:		 0x%02x (%s%d bytes)\n", info.hardware.storage_size, (info.hardware.storage_size & 1) ? ">" : "=", 1 << (info.hardware.storage_size >> 1));
	printf ("	Protocol:			 0x%02x\n", info.hardware.protocol);
	printf ("Software Information:\n");
	printf ("	Vendor ID:			0x%02x\n", info.software.vendor_id);
	printf ("	Type:				 0x%02x\n", info.software.type);
	printf ("	Subtype:			  0x%02x\n", info.software.subtype);
	printf ("	Version:			  %d.%d\n", info.software.version_major, info.software.version_minor);
	printf ("	Storage size:		 0x%02x (%s%d bytes)\n", info.software.storage_size, (info.software.storage_size & 1) ? ">" : "=", 1 << (info.software.storage_size >> 1));
	printf ("	Protocol:			 0x%02x\n", info.software.protocol);

	uint8_t settings;
	uint8_t max_keys;
	res = mifare_desfire_get_key_settings (tag, &settings, &max_keys);
	if (res == 0) {
		printf ("Master Key settings (0x%02x):\n", settings);
		printf ("	0x%02x configuration changeable;\n", settings & 0x08);
		printf ("	0x%02x PICC Master Key not required for create / delete;\n", settings & 0x04);
		printf ("	0x%02x Free directory list access without PICC Master Key;\n", settings & 0x02);
		printf ("	0x%02x Allow changing the Master Key;\n", settings & 0x01);
	} else if (AUTHENTICATION_ERROR == mifare_desfire_last_picc_error (tag)) {
		printf ("Master Key settings: LOCKED\n");
	} else {
		freefare_perror (tag, "mifare_desfire_get_key_settings");
		return false;
	}

	uint8_t version;
	mifare_desfire_get_key_version (tag, 0, &version);
	printf ("Master Key version: %d (0x%02x)\n", version, version);

	uint32_t size;
	res = mifare_desfire_free_mem (tag, &size);
	printf ("Free memory: ");
	if (0 == res) {
		printf ("%d bytes\n", size);
	} else {
		printf ("unknown\n");
	}

	printf ("Use random UID: %s\n", (strlen (tag_uid) / 2 == 4) ? "yes" : "no");
	return true;
}

// ==================================================================
uint8_t key_data_null[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static bool
desfire_access(MifareTag tag, char* tag_uid)
{
	int	res;

	MifareDESFireKey key = mifare_desfire_des_key_new_with_version (key_data_null);
	res = mifare_desfire_authenticate (tag, 0, key);
	if (res < 0)
		errx (EXIT_FAILURE, "Authentication on master application failed");

	MadAid mad_aid = { 0x12, 0x34 };
	MifareDESFireAID aid = mifare_desfire_aid_new_with_mad_aid (mad_aid, 0x5);
	res = mifare_desfire_create_application (tag, aid, 0xFF, 0x1);
	if (res < 0)
	{
		printf("Application creation failed, res=%d.\n", res);
	}

	res = mifare_desfire_select_application (tag, aid);
	if (res < 0)
		errx (EXIT_FAILURE, "Application selection failed");

	res = mifare_desfire_authenticate (tag, 0, key);
	if (res < 0)
		errx (EXIT_FAILURE, "Authentication on application failed");

	res = mifare_desfire_create_std_data_file (tag, 1, MDCM_ENCIPHERED, 0x0000, 20);
	if (res < 0)
	{
		printf("File creation failed, res=%d.\n", res);
	}

	// const char *s= "Hello World";
	const char s[11] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };
	res = mifare_desfire_write_data (tag, 1, 0, sizeof(s), s);
	if (res < 0)
	{
		printf("res=%d\n", res);
		errx (EXIT_FAILURE, "File write failed");
	}

	char buffer[20];
	res = mifare_desfire_read_data (tag, 1, 0, 0, buffer);
	if (res < 0)
		errx (EXIT_FAILURE, "File read failed");
	hexdump(buffer, 20, "File read:", HD_OMIT_CHARS|HD_OMIT_COUNT);


	res = mifare_desfire_delete_file(tag, 1);
	if (res < 0)
		errx (EXIT_FAILURE, "Delete file 1 failed!");

	res = mifare_desfire_select_application (tag, NULL);
	if (res < 0)
		errx (EXIT_FAILURE, "Master application selection failed");

	res = mifare_desfire_authenticate (tag, 0, key);
	if (res < 0)
		errx (EXIT_FAILURE, "Authentication on master application failed");

	res = mifare_desfire_format_picc (tag);
	if (res < 0)
		errx (EXIT_FAILURE, "PICC format failed");

	mifare_desfire_key_free (key);
	free (aid);

	return true;
} // desfire_access

// ==================================================================
uint8_t null_key_data[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t new_key_data[8]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

#define NEW_KEY_VERSION 0x34

static bool
desfire_default_key(MifareTag tag, char* tag_uid)
{
	int error = EXIT_SUCCESS;
	int res;

	struct mifare_desfire_version_info info;
	res = mifare_desfire_get_version (tag, &info);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_get_version");
		error = 1;
		return false;
	}
	if (info.software.version_major < 1) {
		warnx ("Found old DESFire, skipping");
		return false;
	}

	printf ("Found %s with UID %s. ", freefare_get_tag_friendly_name (tag), tag_uid);

	MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);
	res = mifare_desfire_authenticate (tag, 0, default_key);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_authenticate");
		error = EXIT_FAILURE;
		return false;
	}
	mifare_desfire_key_free (default_key);

	MifareDESFireKey new_key = mifare_desfire_des_key_new (new_key_data);
	mifare_desfire_key_set_version (new_key, NEW_KEY_VERSION);
	res = mifare_desfire_set_default_key (tag, new_key);
	free (new_key);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_set_default_key");
		error = EXIT_FAILURE;
		return false;
	}

	/*
	* Perform some tests to ensure the function actually worked
	* (it's hard to create a unit-test to do so).
	*/

	MifareDESFireAID aid = mifare_desfire_aid_new (0x112233);
	res = mifare_desfire_create_application (tag, aid, 0xFF, 1);

	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_create_application");
	}

	res = mifare_desfire_select_application (tag, aid);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_select_application");
		error = EXIT_FAILURE;
		return false;
	}

	uint8_t version;
	res = mifare_desfire_get_key_version (tag, 0, &version);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_get_key_version");
		error = EXIT_FAILURE;
		return false;
	}

	if (version != NEW_KEY_VERSION) {
		fprintf (stderr, "Wrong key version: %02x (expected %02x).\n", version, NEW_KEY_VERSION);
		error = EXIT_FAILURE;
		return false;
	}

	new_key = mifare_desfire_des_key_new (new_key_data);
	res = mifare_desfire_authenticate (tag, 0, new_key);
	free (new_key);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_authenticate");
		error = EXIT_FAILURE;
		return false;
	}

	free (aid);

	/* Resetdefault settings */

	res = mifare_desfire_select_application (tag, NULL);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_select_application");
		error = EXIT_FAILURE;
		return false;
	}

	default_key = mifare_desfire_des_key_new (null_key_data);

	res = mifare_desfire_authenticate (tag, 0, default_key);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_authenticate");
		error = EXIT_FAILURE;
		return false;
	}

	res = mifare_desfire_set_default_key (tag, default_key);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_set_default_key");
		error = EXIT_FAILURE;
		return false;
	}

	mifare_desfire_key_free (default_key);

	/* Wipeout the card */

	res = mifare_desfire_format_picc (tag);
	if (res < 0) {
		freefare_perror (tag, "mifare_desfire_format_picc");
		error = EXIT_FAILURE;
		return false;
	}

	return true;
}

// ==================================================================
uint8_t key_data_3des[16]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
uint8_t key_data_3des_app_a[16]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
//uint8_t key_data_3des[16] = { 'C', 'a', 'r', 'd', ' ', 'M', 'a', 's', 't', 'e', 'r', ' ', 'K', 'e', 'y', '!' };

static bool
desfire_change_keys(MifareTag tag, char* tag_uid)
{
	int	res;

	MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);
	MifareDESFireKey key = mifare_desfire_3des_key_new_with_version (key_data_3des);
	MifareDESFireKey key_app_a = mifare_desfire_3des_key_new_with_version (key_data_3des_app_a);

	res = mifare_desfire_authenticate(tag, 0, default_key);
	cut_assert_success ("mifare_desfire_authenticate(default_key)");

	// 1.CHANGE to new key.
	mifare_desfire_change_key (tag, 0, key, NULL);
	cut_assert_success ("mifare_desfire_change_key()");

	res = mifare_desfire_authenticate(tag, 0, key);
	cut_assert_success ("mifare_desfire_authenticate(key)");

	// 2. CREATE applications.
	MifareDESFireAID aid_a = mifare_desfire_aid_new (0x00AAAAAA);
	res = mifare_desfire_create_application (tag, aid_a, 0xFF, 6);
	cut_assert_success ("mifare_desfire_create_application()");

	res = mifare_desfire_select_application (tag, aid_a);
	cut_assert_success ("mifare_desfire_select_application()");

	res = mifare_desfire_authenticate(tag, 0, default_key);
	cut_assert_success ("mifare_desfire_authenticate(default_key)");

	// 3. CREATE FILES
	uint8_t std_data_file_id = 15;

	res = mifare_desfire_create_std_data_file (tag, std_data_file_id, MDCM_PLAIN, 0xEEEE, 100);
	cut_assert_success ("mifare_desfire_create_std_data_file()");

	// 4. Write some data in the standard data file
	res = mifare_desfire_write_data (tag, std_data_file_id, 0, 30, (uint8_t *)"Some data to write to the card");
	cut_assert_success ("mifare_desfire_write_data()");
	cut_assert_equal_int (30, res, cut_message ("Wrong number of bytes writen"));

	res = mifare_desfire_write_data (tag, std_data_file_id, 34, 22, (uint8_t *)"Another block of data.");
	cut_assert_success ("mifare_desfire_write_data()");
	cut_assert_equal_int (22, res, cut_message ("Wrong number of bytes writen"));


	// 1.CHANGE to new key.
	mifare_desfire_change_key (tag, 0, key_app_a, NULL);
	cut_assert_success ("mifare_desfire_change_key()");

	res = mifare_desfire_authenticate(tag, 0, key_app_a);
	cut_assert_success ("mifare_desfire_authenticate(key)");

	// Make the file read-only
	/*
	res = mifare_desfire_change_file_settings (tag, std_data_file_id, MDCM_PLAIN, 0xEFFF);
	cut_assert_success ("mifare_desfire_change_file_settings()");
	*/

	res = mifare_desfire_delete_file (tag, std_data_file_id);
	cut_assert_success ("mifare_desfire_delete_file()");


	// Delete application A
	res = mifare_desfire_select_application (tag, NULL);
	cut_assert_success ("mifare_desfire_select_application(NULL)");

	res = mifare_desfire_authenticate(tag, 0, key);
	cut_assert_success ("mifare_desfire_authenticate(key)");

	res = mifare_desfire_delete_application (tag, aid_a);
	cut_assert_success ("mifare_desfire_delete_application()");

	// BACK to old key.
	mifare_desfire_change_key (tag, 0, default_key, NULL);
	cut_assert_success ("mifare_desfire_change_key()");

	mifare_desfire_key_free (key);
	mifare_desfire_key_free (default_key);

	return true;
}

// ==================================================================
int
main(int argc, char *argv[])
{
	int error = EXIT_SUCCESS;
	nfc_device *device = NULL;
	MifareTag *tags = NULL;

	if (argc > 1)
	{
		errx (EXIT_FAILURE, "usage: %s", argv[0]);
	}

	nfc_connstring devices[8];

	nfc_context *context;
	nfc_init (&context);

	nfc_driver* proxydriver = proxydriver_new("192.168.5.107", 1555);
	if (proxydriver == NULL)
	{
		printf("mdtest:Emulation driver failure.\n");
	}
	else
	{
		const int r = nfc_register_driver(proxydriver);
		printf("mdtest:Emulation driver registration: %d\n", r);
	}

	int device_count = nfc_list_devices (context, devices, 8);
	if (device_count <= 0)
	{
		errx (EXIT_FAILURE, "No NFC device found.");
	}

	printf("mdtest: Found %d device(s).\n", device_count);

	for (int d = 0; d < device_count; d++)
	{
		printf("mdtest: opening device %d.\n", d);
		device = nfc_open (context, devices[d]);
		if (!device)
		{
			warnx ("mdtest: nfc_open() failed.");
			error = EXIT_FAILURE;
			continue;
		}

		printf("mdtest: Getting tags.\n");
		tags = freefare_get_tags (device);
		if (!tags) {
			nfc_close (device);
			errx (EXIT_FAILURE, "Error listing tags.");
		}

		printf("mdtest: Enumerating tags...\n");
		for (int i = 0; (!error) && tags[i]; i++)
		{
			if (DESFIRE != freefare_get_tag_type (tags[i]))
			{
				continue;
			}
			char *tag_uid = freefare_get_tag_uid (tags[i]);
			int res = mifare_desfire_connect (tags[i]);
			if (res < 0) {
				warnx ("mdtest: Can't connect to Mifare DESFire target.");
				continue;
			}

#if (0)
			bool r = desfire_show_info(tags[i], tag_uid);
#endif
#if (0)
			bool r = desfire_access(tags[i], tag_uid);
#endif
#if (0)
			bool r = desfire_default_key(tags[i], tag_uid);
#endif
#if (1)
			bool r = desfire_change_keys(tags[i], tag_uid);
#endif
			if (!r)
			{
				error = 1;
			}
			free (tag_uid);
			mifare_desfire_disconnect (tags[i]);
		}

		printf("mdtest: Freeing tags.\n");
		freefare_free_tags (tags);
		printf("mdtest: Closing device.\n");
		nfc_close (device);
	}
	printf("mdtest: Finished.\n");
	nfc_exit (context);
	exit (error);
} /* main() */

