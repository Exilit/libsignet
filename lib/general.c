#include "general.h"

#include <stdio.h>

#define SKEY_EMPTY {     0,     0,     0, 0, 0, 0, 0, NULL, NULL }
 
signet_field_key_t signet_org_field_keys[256] = {
//	{ .required .unique .flags .bytes_name_size .bytes_data_size, .data_size, .data_type, .name, .description }
/*0*/	SKEY_EMPTY,
/*1*/	{     1,     1,     0, 0, 0, 32,     HEX,                "Primary-Org-Key", "Primary organizational signing key, also located in the DIME record SIGNET." },
/*2*/	{     1,     1,     0, 0, 0, 97,     HEX,             "Org-Encryption-Key", "The ECC public key used to encrypt data sent to the holder of organizational SIGNET holder." },
/*3*/	{     0,     0,     1, 0, 0, 32,     HEX,              "Secondary-Org-Key", "Secondary organizational signing key fields." },
/*4*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*10*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*16*/	{     0,     0,     0, 0, 2,  0, UNICODE,          "Dark-Mail-Access-Host", "TODO." },
/*17*/	{     0,     0,     0, 0, 0, 64,     HEX,   "Dark-Mail-Access-Certificate", "TODO." },
/*18*/	{     0,     1,     0, 0, 2,  0, UNICODE,       "Web-Mail-Access-Location", "TODO." },
/*19*/  SKEY_EMPTY,
/*20*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*25*/	{     0,     1,     0, 0, 1,  0, UNICODE,                             "Name", "Organization name." },
/*26*/	{     0,     1,     0, 0, 1,  0, UNICODE,                          "Website", "Organization website." },
/*27*/	{     0,     1,     0, 0, 1,  0, UNICODE,                          "Address", "Organization address." },
/*28*/	{     0,     1,     0, 0, 1,  0, UNICODE,                         "Locality", "Organization locality." },
/*29*/	{     0,     1,	    0, 0, 1,  0, UNICODE,                         "Province", "Organization state/province." },
/*30*/	{     0,     1,     0, 0, 1,  0, UNICODE,                          "Country", "Organization country." },
/*31*/	{     0,     1,     0, 0, 1,  0, UNICODE,                      "Postal-Code", "Organization zip or postal code." },
/*32*/  {     0,     0,     0, 0, 1,  0, UNICODE,                     "Phone-Number", "Organization phone number." },
/*33*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*40*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*50*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*60*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*70*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*80*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*90*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*100*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*110*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*120*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*124*/ {     0,     1,     0, 0, 3,  0,     PNG,                            "Photo", "Organization photo." },
/*125*/ {     0,     0,     0, 1, 2,  0, UNICODE,                  "Undefined-Field", "Organization undefined field specified by a name." },
/*126*/ {     1,     1,     0, 0, 0, 64,     HEX,    "Organizational-Core-Signature", "HMAC of all the previous fields signed by the organization POK." },
/*127*/ {     1,     1,     0, 0, 1,  0, UNICODE,                "Signet-Identifier", "Mail service domain name." },
/*128*/ {     1,     1,     0, 0, 0, 64,     HEX,    "Organizational-Full-Signature", "HMAC of all the previous fields including the Signet-Identifer field signed by the organization POK." }, // TODO
/*129*/ SKEY_EMPTY, 
/*130*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*140*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*150*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*160*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*170*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*180*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*190*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*200*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*210*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*220*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*230*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*240*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*250*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY
};


signet_field_key_t signet_user_field_keys[256] = {
//	{ .required .unique .flags .bytes_name_size .bytes_data_size, .data_size, .data_type, .name, .description }
/*0*/	SKEY_EMPTY,
/*1*/	{     1,     1,     0, 0, 0, 32,     HEX,                 "User-Signing-Key", "User signing key." },
/*2*/	{     1,     1,     0, 0, 0, 97,     HEX,              "User-Encryption-Key", "User encryption key which is used to encrypt messages to the holder of the user signet." },
/*3*/	{     0,     0,     1, 0, 1,  0,     HEX,         "Alternate-Encryption-Key", "Alternative user encryption keys." },
/*4*/   {     0,     1,     0, 0, 0, 64,     HEX,       "Chain-Of-Custody-Signature", "The 'Chain-of-custody' Signature. HMAC of the previous fields signed by user's previous private signing key." },
/*5*/   {     1,     1,     0, 0, 0, 64,     HEX,               "User-Ssr-Signature", "User's signature and the last field of the User's SSR. HMAC of the previous fields signed by user's private Signing key." },
/*6*/   {     1,     1,     0, 0, 0, 64,     HEX, "Organizational-Initial-Signature", "HMAC of the fields provided by the user's SSR signed by the Organization's private Signing Key." },
/*7*/   SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*10*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*20*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*25*/	{     0,     1,     0, 0, 1,  0, UNICODE,                             "Name", "User name." },
/*26*/	{     0,     1,     0, 0, 1,  0, UNICODE,                          "Website", "User website." },
/*27*/	{     0,     1,     0, 0, 1,  0, UNICODE,                          "Address", "User address." },
/*28*/	{     0,     1,     0, 0, 1,  0, UNICODE,                         "Locality", "User locality." },
/*29*/	{     0,     1,	    0, 0, 1,  0, UNICODE,                         "Province", "User state/province." },
/*30*/	{     0,     1,     0, 0, 1,  0, UNICODE,                          "Country", "User country." },
/*31*/	{     0,     1,     0, 0, 1,  0, UNICODE,                      "Postal-Code", "User zip or postal code." },
/*32*/  {     0,     0,     0, 0, 1,  0, UNICODE,                     "Phone-Number", "User phone number." },
/*33*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*40*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*50*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*60*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*70*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*80*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*90*/  SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*100*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*110*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*120*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*124*/ {     0,     1,     0, 0, 3,  0,     PNG,                            "Photo", "User photo." },
/*125*/ {     0,     0,     0, 1, 2,  0, UNICODE,                  "Undefined-Field", "User undefined field specified by a name." },
/*126*/ {     1,     1,     0, 0, 0, 64,     HEX,    "Organizational-Core-Signature", "HMAC of all the previous fields signed by the organization POK." },
/*127*/ {     1,     1,     0, 0, 1,  0, UNICODE,                "Signet-Identifier", "User mail address." },
/*128*/ {     1,     1,     0, 0, 0, 64,     HEX,    "Organizational-Full-Signature", "HMAC of all the previous fields including the Signet-Identifer field signed by the organization POK." }, // TODO
/*129*/ SKEY_EMPTY, 
/*130*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*140*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*150*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*160*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*170*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*180*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*190*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*200*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*210*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*220*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*230*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*240*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*250*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY
};


signet_field_key_t signet_ssr_field_keys[256] = {
//	{ .required .unique .flags .bytes_name_size .bytes_data_size, .data_size, .data_type, .name, .description }
/*0*/	SKEY_EMPTY,
/*1*/	{     1,     1,     0, 0, 0, 32,     HEX,                 "User-Signing-Key", "User signing key." },
/*2*/	{     1,     1,     0, 0, 0, 97,     HEX,              "User-Encryption-Key", "User encryption key which is used to encrypt messages to the holder of the user signet." },
/*3*/	{     0,     0,     1, 0, 1,  0,     HEX,         "Alternate-Encryption-Key", "Alternative user encryption keys." },
/*4*/   {     0,     1,     0, 0, 0, 64,     HEX,       "Chain-Of-Custody-Signature", "The 'Chain-of-custody' Signature. HMAC of the previous fields signed by user's previous private signing key." },
/*5*/   {     1,     1,     0, 0, 0, 64,     HEX,               "User-Ssr-Signature", "User's signature and the last field of the User's SSR. HMAC of the previous fields signed by user's private Signing key." },
/*6*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*10*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*20*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*30*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*40*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*50*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*60*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*70*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*80*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*90*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*100*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*110*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*120*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*130*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*140*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*150*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*160*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*170*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*180*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*190*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*200*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*210*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*220*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*230*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*240*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*250*/	SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY
};


/**
 * @brief	Create a pem file with specified tags and filename.
 * @param	b64_data	Null terminated base64 encoded data.
 * @param	tag		Null terminated ASCII string containing the desired PEM tag.
 * @param	filename	Null terminated string containing the desired filename.
 * @return	0 on success, -1 on failure.
*/
int _write_pem_data(const char *b64_data, const char *tag, const char *filename) {

	FILE *fp;
	char fbuf[BUFSIZ];
	size_t data_size;
	unsigned int i;

	if(!b64_data || !tag || !filename) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	} else if(!strlen(filename) || !strlen(tag) || !(data_size = strlen(b64_data))) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!(fp = fopen(filename, "w"))) {
		PUSH_ERROR_SYSCALL("fopen");
		RET_ERROR_INT_FMT(ERR_UNSPEC, "could not open file for writing: %s", filename);
	}
	setbuf(fp, fbuf);

	fprintf(fp, "-----BEGIN %s-----\n", tag);

	for(i = 0; i < data_size; ++i) {
		
		if(i % 128 == 0 && i) {
			fprintf(fp, "\n");
		}

		fprintf(fp, "%c", b64_data[i]);
	}

	fprintf(fp, "\n-----END %s-----\n", tag);
	fclose(fp);
	_secure_wipe(fbuf, sizeof(fbuf));

	return 0;
}


/**
 * @brief	Deserializes an ed25519 public key into a public-only ED25519_KEY structure that can only be used for signature verification, not signing.
 * @param	serial_pubkey Serialized ed25519 public key.
 * @return	Pointer to ED25519_KEY structure.
*/
ED25519_KEY * _deserialize_ed25519_pubkey(const unsigned char *serial_pubkey) {

	ED25519_KEY *key;

	if(!serial_pubkey) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(key = malloc(sizeof(ED25519_KEY))) ) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	memset(key, 0, sizeof(ED25519_KEY));
	memcpy(key->public, serial_pubkey, ED25519_KEY_SIZE);

	return key;
}


/**
 * @brief	Deserializes an ed25519 private key into a ED25519_KEY structure.
 * @param	serial_privkey	Serialized ed25519 private key.
 * @return	Pointer to the ED25119_KEY structure.
*/
ED25519_KEY * _deserialize_ed25519_privkey(const unsigned char * serial_privkey) {

	ED25519_KEY *key;

	if(!serial_privkey) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(key = malloc(sizeof(ED25519_KEY))) ) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	memset(key, 0, sizeof(ED25519_KEY));
	memcpy(key->private, serial_privkey, ED25519_KEY_SIZE);
	ed25519_publickey(key->private, key->public);

	return key;
}


/**
 * @brief	Returns a string from a signet_state_t enum type.
 * @param	state	Signet state.
 * @return	Null terminated string corresponding to the state.
*/
const char * signet_state_to_str(signet_state_t state) {

	switch(state) {

		case SS_UNKNOWN:
			return "unknown";
		case SS_MALFORMED:
			return "malformed";
		case SS_OVERFLOW:
			return "overflow";
		case SS_INCOMPLETE:
			return "incomplete";
		case SS_UNVERIFIED:
			return "unverified";
		case SS_SSR:
			return "SSR";
		case SS_USER_CORE:
			return "user cryptographic portion";
		case SS_CORE:
			return "id-stripped signet";
		case SS_FULL:
			return "full signet";

	}

	return NULL;
}


/**
 * @brief	Returns a string from a dime_number_t enum type.
 * @param	number	Dime number input.
 * @return	Null terminated string corresponding to the dime number.
*/
const char * dime_number_to_str(dime_number_t number) {

	switch(number) {

		case DIME_ORG_SIGNET:
			return "organizational signet";
		case DIME_USER_SIGNET:
			return "user signet";
		case DIME_SSR:
			return "SSR";
		case DIME_ORG_KEYS:
			return "organizational signet keychain";
		case DIME_USER_KEYS:
			return "user signet keychain";

	}

	return NULL;
}
