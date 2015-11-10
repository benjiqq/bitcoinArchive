/*
 * scc.h
 *	Definitions for IBM 4758 Secure Crypto Coprocessor data structures
 */

#ifndef SCC_H
#define SCC_H


#if defined(_WIN32)
#pragma pack(push,1)
#define PACK_DATA
#else
#define PACK_DATA __attribute__ ((__packed__))
#endif

#define NSEGS				3
#define ADAPTERID_LENGTH  	8
#define VPD_LENGTH			256
#define IMAGE_NAME_LENGTH	80
#ifndef SHA1_HASH_LENGTH
#define SHA1_HASH_LENGTH	20
#endif

#define KEYTYPE_RSA			0x00
#define CERT_IBM_ROOT		0x8000
#define CERT_CLASS_ROOT		0x0001
#define CERT_MB				0x0101
#define CERT_SEG2_SEG3		0x0201
#define CERT_SEG3_CONFIG	0x0301
#define CERT_SEG3_EPOCH		0x0302

#define SCCLAYERDESC_T		0x54
#define SCCLAYERDESC_VER	0x00
#define SCCHEAD_T			0x56
#define SCCHEAD_VER			0x00
#define SCCBODY_T			0x57
#define SCCBODY_VER			0x00


/* SCC current time */
typedef struct
{
	unsigned long		ticksperday;
	unsigned long		totalticks;
	unsigned char		hundredths;
	unsigned char		second;
	unsigned char		minute;
	unsigned char		hour;
	unsigned short		year;
	unsigned char		month;
	unsigned char		day;
	unsigned short		tick;
	unsigned short		tickhertz;
	unsigned short		daynumber;
	unsigned char		weekday;
	unsigned char		tickrate;
} PACK_DATA sccClockTime_t;


/* RSA Key */
/* This is just part of the SCC structure, relating to public keys */
/* The actual structure is longer */
typedef struct
{	unsigned long		type;
	unsigned long		length;
	unsigned long		n_BitLength;
	unsigned long		n_Length;
	unsigned long		e_Length;
	unsigned long		unused[8];
	unsigned long		n_Offset;
	unsigned long		e_Offset;
} PACK_DATA sccRSAKey_t;




typedef struct
{	unsigned long		off;
	unsigned long		len;
} PACK_DATA ptr_t;

typedef struct
{	unsigned char		name;
	unsigned char		version;
} PACK_DATA struct_id_t;

typedef struct
{	struct_id_t			struct_id;
	unsigned short		pic_version;
	unsigned short		rom_version;
	unsigned char		page1_certified;
	unsigned short		boot_count_left;
	unsigned long		boot_count_right;
	unsigned char		adapterID[ADAPTERID_LENGTH];
	unsigned char		vpd[VPD_LENGTH];
	unsigned char		init_state;
	unsigned char		seg2_state;
	unsigned char		seg3_state;
	unsigned short		owner2;
	unsigned short		owner3;
	unsigned char		active_seg1;
} PACK_DATA rom_status_t;




typedef struct {
   unsigned long		creation_boot;
   unsigned short		name_type;
   unsigned short		index;
} PACK_DATA sccName_t;

typedef struct {
   struct_id_t struct_id;
   short				year;
   char					month;
   char					day;
   char					hour;
   char					minute;
} PACK_DATA sccTime_t;

typedef struct {
	struct_id_t			struct_id;
	unsigned char		padbytes[2];
	unsigned char		adapterID[ADAPTERID_LENGTH];
	sccTime_t			when_certified;
} PACK_DATA sccDeviceName_t;

typedef struct {
	struct_id_t			struct_id;
	unsigned char		padbytes[2];
	unsigned long		epoch_start;
	unsigned long		config_start;
	unsigned long		config_count;
} PACK_DATA sccLayerName_t;

typedef struct {
	struct_id_t			struct_id;
	unsigned char		padbyte;
	unsigned char		layer_number;
	unsigned long		ownerID;
	unsigned char		image_name[IMAGE_NAME_LENGTH];
	unsigned long		image_revision;
	unsigned char		image_hash[SHA1_HASH_LENGTH];
	sccLayerName_t		layer_name;
} PACK_DATA sccLayerDesc_t;

typedef struct {
	struct_id_t			struct_id;
	unsigned char		padbytes[2];
	rom_status_t		rom_status;
	ptr_t				vSeg_ids[NSEGS];
	long				free_space[NSEGS];
	sccLayerName_t		layer_names[NSEGS];
	sccDeviceName_t		device_name;
} PACK_DATA sccStatus_t;

/* Certificate header; vData field points to body */
typedef struct {
	struct_id_t			struct_id;
	unsigned char		padbytes[2];
	unsigned long		tData;
	ptr_t				vData;
	ptr_t				vSig;
	unsigned long		tSig;
	sccName_t			cko_name;
	unsigned long		cko_type;
	unsigned long		cko_status;
	sccName_t			parent_name;
} PACK_DATA sccHead_t;

/* Certificate body */
typedef struct {
	struct_id_t			struct_id;
	unsigned char		padbytes[2];
	unsigned long		tPublic;
	ptr_t				vPublic;
	ptr_t				vDescA;
	ptr_t				vDescB;
	sccDeviceName_t		device_name;
	sccName_t			cko_name;
	unsigned long		cko_type;
	sccName_t  			parent_name;
} PACK_DATA sccBody_t;

typedef struct
{	char		   signature[4]; 
	unsigned char  vpd_length;	 
	unsigned short crc;			 
	char		   pn_tag[3];
	unsigned char  pn_length;	 
	char		   pn[8];		 
	char		   ec_tag[3];
	unsigned char  ec_length;	 
	char		   ec[8];		 
	char		   sn_tag[3];
	unsigned char  sn_length;	 
	char		   sn[8];		 
	char		   fn_tag[3];
	unsigned char  fn_length;	 
	char		   fn[8];		 
	char		   mf_tag[3];
	unsigned char  mf_length;	 
	char		   mf[6];		 
	char		   ds_tag[3];
	unsigned char  ds_length;	 
	char		   ds[42];		 
	char		   reserved[17];
} PACK_DATA vpd_t;


typedef struct
{
	unsigned short	id;
	unsigned short	length;
	unsigned char	AMCC_EEPROM[128];
	vpd_t			VPD;
	unsigned char	rsvd[7];
	unsigned char	POST0Version;
	unsigned char	POST1Version;
	unsigned char	MiniBoot0Version;
	unsigned char	MiniBoot1Version;
	unsigned char	OS_Name[6];
	unsigned short	OS_Version;
	unsigned short	CPU_Speed;
	unsigned char	DES_level;
	unsigned char	RSA_level;
	unsigned char	hwreserved[2];
	unsigned char	HardwareStatus;
	unsigned char	AdapterID[8];
	unsigned char	flashSize;
	unsigned char	bbramSize;
	unsigned long	dramSize;
	unsigned char	reserved[2];
} PACK_DATA sccAdapterInfo_t;


#if defined(_WIN32)
#pragma pack(pop)
#endif

#endif
