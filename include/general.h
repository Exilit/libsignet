#ifndef SIGNET_GENERAL_H
#define SIGNET_GENERAL_H

#define SIGNET_VER_NO                0x1
#define SIGNET_HEADER_SIZE	     5
#define SIGNET_MAX_SIZE		     16777220
#define SIGNET_PRIVATE_KEYCHAIN	     "SIGNET PRIVATE KEYCHAIN"
#define SIGNET_PEM_TAG		     "SIGNET"
#define KEYS_HEADER_SIZE	     5
#define FIELD_NAME_MAX_SIZE	     255
#define UNSIGNED_MAX_1_BYT	     255
#define UNSIGNED_MAX_2_BYTE	     65535
#define UNSIGNED_MAX_3_BYTE          16777215
#define SIGNET_FID_MAX               255
#define KEYS_FID_MAX		     3

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "error.h"
#include "misc.h"
#include "dcrypto.h"


typedef enum 
{
SIGNET_TYPE_ERROR,
SIGNET_TYPE_ORG = 1,
SIGNET_TYPE_USER, 
SIGNET_TYPE_SSR
} signet_type_t;


typedef struct {
	signet_type_t type;
	uint32_t fields[256]; 		/* each index corresponds to a different field type identifier. The value of fields[index] is the byte directly after the first occurence of the corresponding field type identifier*/
					/* if fields[index] is 0 it means that the corresponding field type identifier occurred 0 times.*/
	uint32_t size;			/* Combined length of all the fields*/
	unsigned char* data;
} signet_t;

typedef enum
{
DIME_ORG_SIGNET = 1776,			/* File contains an organizational signet */
DIME_USER_SIGNET = 1789,		/* File contains a user signet */
DIME_SSR = 1216,			/* File contains an ssr*/
DIME_ORG_KEYS = 1952,			/* File contains organizational keys*/
DIME_USER_KEYS = 2013,			/* File contains user keys*/
} dime_number_t;


typedef enum
{
KEYS_TYPE_ERROR = 0,
KEYS_TYPE_ORG,
KEYS_TYPE_USER
} keys_type_t;


typedef enum
{
SIGNET_ORG_POK = 1,           		/* The ed25519 public signing key of the signet holder */
SIGNET_ORG_ENC_KEY,			/* The ECC public encryption key of the signet holder */
SIGNET_ORG_SOK_KEY,			/* Secondary Organization Signing keys */
SIGNET_ORG_HOST = 16,			/* Dark Mail Access Host */
SIGNET_ORG_CERT,			/* Dark Mail Access Certificate */
SIGNET_ORG_WEBMAIL,			/* Web Mail Access Location */
SIGNET_ORG_NAME = 25,			/* Organization name */
SIGNET_ORG_WEBSITE,			/* Organization website */
SIGNET_ORG_ADDRESS,			/* Organization Address */
SIGNET_ORG_LOCALTIY,			/* Organization locality */
SIGNET_ORG_PROVINCE,			/* Organization state/province */
SIGNET_ORG_COUNTRY,			/* Organization country */
SIGNET_ORG_POSTAL,			/* Organization zip code */
SIGNET_ORG_PHONE,			/* Organization phone number */
SIGNET_ORG_PHOTO = 124,			/* Organizational photo*/
SIGNET_ORG_UNDEFINED,			/* UNICODE undefined field*/
SIGNET_ORG_CORE_SIG,			/* ORG signature*/
SIGNET_ORG_ID,				/* Org Signet ID */
SIGNET_ORG_FULL_SIG			/* Org Signature following the ID field */
} SIGNET_ORG_FIELD_T;


typedef enum
{
SIGNET_USER_SIGN_KEY = 1,		/* The ed25519 public signing key of the signet holder*/
SIGNET_USER_ENC_KEY,			/* The ECC public encryption key of the signet holder*/
SIGNET_USER_ALT_KEY,			/* Alternative encryption keys for the user */
SIGNET_USER_COC_SIG,			/* Chain of custody signature by user's previous signing key*/
SIGNET_USER_SSR_SIG,			/* User signature with user's signing key*/
SIGNET_USER_INITIAL_SIG,		/* Initial signature by the organization's signing key*/
SIGNET_USER_NAME = 25,			/* User name */
SIGNET_USER_WEBSITE,			/* User website */
SIGNET_USER_ADDRESS,			/* User address */
SIGNET_USER_LOCALITY,			/* User locality */
SIGNET_USER_PROVINCE,			/* User state/province */
SIGNET_USER_COUNTRY,			/* User country */
SIGNET_USER_POSTAL,			/* User zip code */
SIGNET_USER_PHONE,			/* User phone number */
SIGNET_USER_PHOTO = 124,		/* User photo*/
SIGNET_USER_UNDEFINED,			/* ASCII undefined field*/
SIGNET_USER_CORE_SIG, 			/* Final Organizational Signature*/
SIGNET_USER_ID,				/* User Signet ID */
SIGNET_USER_FULL_SIG			/* Org Signature following the ID field */
} SIGNET_USER_FIELD_T; 


typedef enum
{
SIGNET_SSR_SIGN_KEY = 1,		/* The proposed ed25519 public signing key of the ssr creator*/
SIGNET_SSR_ENC_KEY,			/* The ed25519 ECC public encryption key of the ssr creator*/
SIGNET_SSR_ALT_KEY,			/* Alternative encryption keys for the ssr creator */
SIGNET_SSR_COC_SIG,			/* Chain of custody signature by user's previous signing key*/
SIGNET_SSR_SSR_SIG,			/* User signature with user's signing key*/
} SIGNET_SSR_FIELD_T;


typedef enum
{
KEYS_ORG_PRIVATE_POK = 1,
KEYS_ORG_PRIVATE_ENC,
KEYS_ORG_PRIVATE_SOK,
} KEYS_ORG_T;


typedef enum
{
KEYS_USER_PRIVATE_SIGN = 1,
KEYS_USER_PRIVATE_ENC,
} KEYS_USER_T;


typedef enum
{
SIGNET_SOK_NONE   = 0x00000001,		/* This key can not be used for signing signets or messages */
SIGNET_SOK_SIGNET = 0x00000011,		/* This key can only be used for signing signets */
SIGNET_SOK_MSG    = 0x00000101,		/* This key can only be used for signing messages */
SIGNET_SOK_ALL	  = 0x00000111		/* This key can only be used for signing signets and messages */
} sok_flag_t;


typedef enum 
{
SS_UNKNOWN = 0,				/* Invalid signet, state unknown/currently unclassified */
SS_MALFORMED, 				/* Invalid signet, it either doesn't fit the field format or has multiple unique fields */
SS_OVERFLOW,				/* Invalid signet due to it being too large. */
SS_INCOMPLETE, 				/* Invalid signet, it is missing fields required to fit one of the valid categories, likely unsigned */
SS_UNVERIFIED,				/* Invalid signet, one or more signatures can not be verified */
SS_SSR,					/* Valid unsigned SSR */
SS_USER_CORE,				/* Valid core of a user signet with all fields after the Ssr-signature removed */
SS_CORE, 				/* Valid signet without ID and organizational-final-signature */
SS_FULL, 				/* Valid signet with ID and organizational-final-signature */
} signet_state_t;

typedef enum 				/* Currently barely used, meant to classify signet field data types*/
{
B64, 
HEX, 
PNG, 
UNICODE
} data_t;

typedef struct {

/* field properties */

	unsigned int required;		/* is this field required*/
	unsigned int unique;		/* can there be multiple fields of this identifier */
	unsigned int flags;		/* Does this field have a byte for flags */

	unsigned char bytes_name_size;	/* Is this a defined field */
	unsigned char bytes_data_size;	/* Number of bytes for this */
	uint32_t data_size;    	    	/* data_size = 0 indicates the size being variable */
	
	data_t data_type;		/* Dump format for the field */

	char* name;
	char* description;		/* field type description*/

} signet_field_key_t;


/* A signet field index structure for temporary convenience organzation of field data */
typedef struct Field {

	const signet_t * signet;
	signet_field_key_t * key;	
	unsigned char flags;
	unsigned char name_size;
	unsigned int data_size;

	unsigned int id_offset;
	unsigned int name_offset;
	unsigned int data_offset;

	struct Field * next;
} signet_field_t;

PUBLIC_FUNC_DECL(int, write_pem_data, const char *b64_data, const char *tag, const char *filename);

ED25519_KEY *		_deserialize_ed25519_pubkey(const unsigned char * serial_pubkey); //TODO move crypto.c in libcommon
ED25519_KEY *		_deserialize_ed25519_privkey(const unsigned char * serial_privkey);

const char *		signet_state_to_str(signet_state_t state);
const char *		dime_number_to_str(dime_number_t number);

extern signet_field_key_t signet_org_field_keys[256];
extern signet_field_key_t signet_user_field_keys[256];
extern signet_field_key_t signet_ssr_field_keys[256];

#endif
