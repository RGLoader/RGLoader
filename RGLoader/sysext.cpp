
#include "sysext.h"
#include "utilities.h"
#include <string>
#include <vector>

#pragma warning (disable: 4996)
using namespace std;

DWORD threadWaitStatus = 0;
DWORD formatStatus = 0;

char hddSysEx[] = "\\Device\\Harddisk0\\SystemExtPartition\\";
char hddSysAux[] = "\\Device\\Harddisk0\\SystemAuxPartition\\";


//#define MANIFEST_FILE		"Game:\\$SystemUpdate\\system.manifest"
#define MANIFEST            "\\system.manifest"
//#define MANIFEST_BASE		"Game:\\$SystemUpdate\\"
#define DESTINATION_BASE	"USEP:\\"
#define PACKAGE_BASE		"Content\\0000000000000000\\" //FFFE07DF\\00008000"

typedef struct _ITEM_INFO {
	string source;
	string dest;
	PBYTE data;
	DWORD len;
} ITEM_INFO, *PITEM_INFO;

vector<ITEM_INFO> inf;
DWORD errcnt = 0;

u32 getBe32(unsigned char* data)
{
	u32 ret = (data[0]&0xFF)<<24;
	ret |= (data[1]&0xFF)<<16;
	ret |= (data[2]&0xFF)<<8;
	ret |= (data[3]&0xFF);
	return ret;
}

u16 getBe16(unsigned char* data)
{
	u16 ret = (data[0]&0xFF)<<8;
	ret |= (data[1]&0xFF);
	return ret;
}

BOOL checkZeros(void* vbuf, u32 len)
{
	unsigned char* buf = (unsigned char*)vbuf;
	u32 i;
	for(i = 0; i<len; i++)
	{
		if(buf[i] != 0x0)
			return FALSE;
	}
	return TRUE;
}

int getFileSize(FILE* fptr)
{
	int len;
	if(fptr == NULL)
	{
		return 0;
	}
	fseek(fptr, 0 , SEEK_END);
	len = ftell(fptr);
	rewind (fptr);
	return len;
}

u8* readFileToBuf(const char* fname, int* len)
{
	FILE* fin;
	unsigned char* buf = NULL;
	fin = fopen(fname, "rb");
	if(fin != NULL)
	{
		int sz = getFileSize(fin);
		//		DbgPrint("loading file %s 0x%x bytes...", fname, sz);
		buf = (unsigned char*)malloc(sz);
		if(buf != NULL)
		{
			fread(buf, sz, 1, fin);
			if(len != NULL)
				*len = sz;
			// 			DbgPrint("done!\n");
		}
		// 		else
		// 			DbgPrint("failed to allocate 0x%x bytes!\n", sz);
		fclose(fin);
	}
	return buf;
}

BOOL verifyManifestHeader(PSU_MANIFEST man)
{
	u8 shaBuf[0x14];
	BYTE* tdat;
	if(man->body.cont.dwSchemaVer != 3)
	{
		DbgPrint("manifest schema != 3!\n");
		return FALSE;
	}
	if((man->body.cont.dwMagic != MAGIC_XSYM)&&(man->body.cont.dwMagic != MAGIC_XONM))
	{
		DbgPrint("manifest revision 0x%08x != xonm|xsym!\n", man->body.cont.dwMagic);
		return FALSE;
	}
	if(man->header.dwMagic != MAGIC_XMNP)
	{
		DbgPrint("manifest magic 0x%08x != XMNP!\n", man->header.dwMagic);
		return FALSE;
	}
	tdat = new BYTE[man->body.cont.size];
	memcpy(tdat, &man->body.cont.dwMagic, man->body.cont.size);
	XeCryptSha(tdat, man->body.cont.size, NULL, 0, NULL, 0, shaBuf, 0x14);
	delete[] tdat;
	if(memcmp(shaBuf, man->header.baDataSha, 0x14) != 0)
	{
		DbgPrint("manifest checksum failed!\n");
		return FALSE;
	}
	return TRUE;
}

int getManifestString(BYTE* sdat, char* dest)
{
	WORD len;
	len = getBe16(sdat);
	if(len != 0)
	{
		memcpy(dest, &sdat[2], len);
		dest[len] = 0x0;
	}
	else
		DbgPrint("err len = 0!\n");
	return len;
}

//BYTE dataHash[0x14]; // 0x38
//DWORD dwContentType; // 0x4C ie 0x00008000
//DWORD dwContentTitleId; // 0x50 ie 0xFFFE07DF
//DWORD dwXContItemListOff; // 0x5C num items in container, followed by entry offsets for each item

BOOL loadVerifyFile(PITEM_INFO citm, BYTE* hdat)
{
	if(citm->len != 0)
	{
		DWORD len;
		citm->data = ReadFileToBuf(citm->source.c_str(), &len);
		if(citm->data != NULL)
		{
			if(len == citm->len)
			{
				BYTE hashbuf[0x14];
				PBYTE databuf = new BYTE[len];
				memcpy(databuf, citm->data, len);
				XeCryptSha(databuf, len, NULL, 0, NULL, 0, hashbuf, 0x14);
				delete[] databuf;
				if(memcmp(hashbuf, hdat, 0x14) == 0)
				{
					dprintf(" OK");
					return TRUE;
				}
				//else
				//	DbgPrint("file corrupt, hash check FAIL!!\n");
			}
			//else
			//	DbgPrint("file length 0x%x does not match 0x%x!\n", len, citm->len);
			delete[] citm->data;
		}
		//else
		//	DbgPrint("file hash check FAIL! could not read file!\n");
	}
	//else
	//	DbgPrint("file hash check FAIL! input len is 0!\n");
	dprintf(" FAILED!\n");
	errcnt++;
	return FALSE;
}

BOOL conCheckHashes(PXCONTENT_FULL_HEADER xcfh, BYTE* conData, DWORD conDataStart, DWORD conDataLen, u32* blockInfo)
{
	PBYTE tcon;
	PSTF_DIRECTORY_ENTRY dent;
	int i, j = 0;
	u32 currBlock = 0;
	u8 hashout[XECRYPT_SHA_DIGEST_SIZE];
	tcon = new BYTE[conDataStart-sizeof(XCONTENT_HEADER)];
	memcpy(tcon, &conData[sizeof(XCONTENT_HEADER)], conDataStart-sizeof(XCONTENT_HEADER));
	XeCryptSha(tcon, conDataStart-sizeof(XCONTENT_HEADER), NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
	delete[] tcon;
	// 	display_buffer_hex(xcfh->Header.ContentId, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
	// 	display_buffer_hex(hashout, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
	// checking header hash
//	DbgPrint("head hash:"); display_hash(xcfh->Header.ContentId, 0x14);

	if(memcmp(xcfh->Header.ContentId, hashout, XECRYPT_SHA_DIGEST_SIZE) == 0)
	{
		BOOL contProcess = TRUE;
		u32 currOffset = conDataStart+sizeof(STF_HASH_BLOCK);
		PSTF_HASH_BLOCK hb = (PSTF_HASH_BLOCK)&conData[conDataStart];
		PSTF_HASH_BLOCK mhb = NULL;
		dent = (PSTF_DIRECTORY_ENTRY)&conData[currOffset];
		//DbgPrint("header hash is OK, checking content hashes...\n");
 		//XeCryptSha(&conData[conDataStart], 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
 		//DbgPrint("master table hash (0x%x):", conDataStart);
 		//display_buffer_hex(hashout, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
 		//DbgPrint("\n");
		// checking fragment hashes
		while(contProcess)
		{
			for(i = 0; i < 0xAA; i++) // this fragment is complete at 0xAA
			{
				if(checkZeros(&hb->Entries[i], 0x18))
				{
					i = 0xAA;
					contProcess = FALSE;
				}
				else
				{
					BYTE tdat[0x1000];
					memcpy(tdat, &conData[currOffset], 0x1000);
					XeCryptSha(tdat, 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
					if(memcmp(hashout, hb->Entries[i].Hash, XECRYPT_SHA_DIGEST_SIZE))
					{
						//DbgPrint("FAIL entry 0x%x block offset 0x%x level 0x%x\n", i, currOffset, u32Rev(hb->Entries[i].LevelAsULONG));
						//fgetc(stdin);
						return FALSE;
					}
					//else
					//	DbgPrint("success entry 0x%x block offset 0x%x level 0x%x\n", i, currOffset, u32Rev(hb->Entries[i].LevelAsULONG));
					blockInfo[currBlock] = currOffset;
					currBlock++;
					currOffset += 0x1000;
				}
			}
			if((currOffset+0x2000) >= conDataLen)
			{
				contProcess = FALSE;
			}
			else
			{
				hb = (PSTF_HASH_BLOCK)&conData[currOffset];
				j++;
// 				XeCryptSha(&conData[currOffset], 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
// 				DbgPrint("table %d hash (0x%x):", j, currOffset);
// 				display_buffer_hex(hashout, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
// 				DbgPrint("\n");

				if(hb->Entries[0].LevelAsULONG == 0)
				{
					BYTE tdat[0x1000];

					mhb = hb; // the main hash block is backed by hash in header, and hashes all the other hash blocks
					memcpy(tdat, &conData[currOffset], 0x1000);
					XeCryptSha(tdat, 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
					if(memcmp(xcfh->Meta.Volume.StfsVolumeDescriptor.RootHash, hashout, XECRYPT_SHA_DIGEST_SIZE))
					{
// 						display_buffer_hex(xcfh->Meta.Volume.StfsVolumeDescriptor.RootHash, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
// 						display_buffer_hex(hashout, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
// 						DbgPrint("FAIL StfsVolumeDescriptor.RootHash\n");
// 						fgetc(stdin);
						return FALSE;
					}

					memcpy(tdat, &conData[conDataStart], 0x1000);
					XeCryptSha(tdat, 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
					if(memcmp(hashout, mhb->Entries[0].Hash, XECRYPT_SHA_DIGEST_SIZE))
					{
// 						display_buffer_hex(mhb->Entries[0].Hash, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
// 						display_buffer_hex(hashout, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
// 						DbgPrint("FAIL mhb->Entries[0]\n");
// 						fgetc(stdin);
						return FALSE;
					}

					currOffset += 0x1000;
					hb = (PSTF_HASH_BLOCK)&conData[currOffset];

				}
				if(mhb != NULL)
				{
					BYTE tdat[0x1000];
					memcpy(tdat, &conData[currOffset], 0x1000);
					XeCryptSha(tdat, 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
					if(memcmp(hashout, mhb->Entries[j].Hash, XECRYPT_SHA_DIGEST_SIZE))
					{
						// 						DbgPrint("FAIL mhb->Entries[%d]\n", j);
						// 						fgetc(stdin);
						return FALSE;
					}
				}

				currOffset += 0x1000;
			}
		}
		//display_buffer_hex(hashout, XECRYPT_SHA_DIGEST_SIZE, VERB_LV0);
		//DbgPrint("content hashes seem OK, everything looks good!\n");

		return TRUE;
	}
	return FALSE;
}

BOOL conCheckHeader(BYTE* conData, DWORD conDataLen, unsigned char* headHash)
{
	u32* blockInfo;
	u32 conDataStart;
	PXCONTENT_FULL_HEADER xcfh = (PXCONTENT_FULL_HEADER)conData;
	//u32 version = xcfh->Content.Installer.MetaData.SystemUpdate.NewVersion;
	conDataStart = XCONTENT_ROUND_UP_TO_ALIGNMENT(xcfh->Header.SizeOfHeaders);//((u32Rev(xcfh->Header.SizeOfHeaders))+0xFFF)&~0xFFF;
// 	DbgPrint("content type: %X\n", u32Rev(xcfh->Meta.ContentType));
// 	DbgPrint("content size: %016I64x\n", u64Rev(xcfh->Meta.ContentSize.QuadPart));
// 	DbgPrint("content tid : %X\n", u32Rev(xcfh->Meta.ExecutionId.Tid.TitleID));
// 	DbgPrint("content ctyp: %X\n", u32Rev(xcfh->Meta.VolumeType));
// 	DbgPrint("meta type   : %X\n", u32Rev(xcfh->Content.Installer.MetaDataType));
// 	DbgPrint("dataStart   : %X\n", conDataStart);
//	DbgPrint("version     : %X (%d.%d.%04d.%02d)\n", version, (version>>28)&0xF, (version>>24)&0xF, (version>>8)&0xFFFF, version&0xFF);
	//if(xcfh->Content.Installer.MetaDataType == INSTALLER_METADATA_TYPE_SYSTEM_UPDATE)
	//{
	//	if(xcfh->Meta.ContentType == 0xB0000)
	//	{
	//		if(xcfh->Meta.ExecutionId.Tid.TitleID == 0xFFFE07D1)
			{
				u32 numBlocks = (conDataLen/0x1000)+1;
				blockInfo = (u32*)malloc((numBlocks*4));
				if(blockInfo != NULL)
				{
					//DbgPrint("header seems valid, version %d.%d.%04d.%02d\n", (version>>28)&0xF, (version>>24)&0xF, (version>>8)&0xFFFF, version&0xFF);
					if(headHash)
					{
						if(!checkZeros(headHash, 0x14))
						{
							if(memcmp(xcfh->Header.ContentId, headHash, 0x14) != 0)
							{
								//DbgPrint("manifest hash does not match container header!\n");
								return FALSE;
							}
							//DbgPrint("manifest hash matches container header!\n");
						}
					}
					if(conCheckHashes(xcfh, conData, conDataStart, conDataLen, blockInfo))
					{
						return TRUE;
					}
				}
			}
	//	}
	//}
	return FALSE;
}

BOOL loadVerifyContainer(PITEM_INFO citm, unsigned char* hash)
{
	if(citm->len != 0)
	{
		DWORD len;
		citm->data = ReadFileToBuf(citm->source.c_str(), &len);
		//DbgPrint("checking container %s\n", citm->source.c_str());
		if(citm->data != NULL)
		{
			if(len == citm->len)
			{
				if(conCheckHeader(citm->data, citm->len, hash))
				{
					dprintf(" OK");
					//DbgPrint("container mount and manifest hash verified as OK\n");
					return TRUE;
				}
				//else
				//	DbgPrint("container FAIL, may be corrupt!\n");
			}
			//else
			//	DbgPrint("file length 0x%x does not match 0x%x!\n", len, citm->len);
			delete[] citm->data;
		}
		//else
		//	DbgPrint("file hash check FAIL! could not read file!\n");
	}
	//else
	//	DbgPrint("file hash check FAIL! input len is 0!\n");
	errcnt++;
	dprintf(" FAILED!\n");
	return FALSE;
}

BOOL verifyManifestItems(BYTE* bodydat, int maxlen, BOOL verifyOnly, char* manifest_base)
{
	char sbuf[512];
	char tbuf[512];
	PSU_MANIFEST_BODY bod = (PSU_MANIFEST_BODY)bodydat;
	DWORD i;
	dprintf("Loading and checking %d items in manifest contents...\n", bod->items.dwNumEntries);
	for(i = 0; i < bod->items.dwNumEntries; i++)
	{
		ITEM_INFO litm;
		PSU_ITEM_ENTRY itm;
		DWORD ver = 0;
		itm = &bod->items.ents[i];
		//DbgPrint("\n --- item %d of %d ---\n", i+1, bod->items.dwNumEntries);
		//DbgPrint("offset: %08x\n", (BYTE*)itm-bodydat);
		if(itm->dwSrcNameOff != 0)
		{
			getManifestString(&bodydat[itm->dwSrcNameOff], sbuf);
			litm.source = manifest_base;
			litm.source += sbuf;
			dprintf("\r\n%d - %s", i+1, sbuf);
			//DbgPrint("\tsource name  : %s\n", litm.source.c_str());
		}
		litm.len = itm->dwFileSize;
		ver = getBe32(&bodydat[itm->dwVersionOff]);
		//if(itm->dwIntNameOff != 0)
		//{
		//	getManifestString(&bodydat[itm->dwIntNameOff], sbuf);
		//	DbgPrint("\tinternal name: %s\n", sbuf);
		//}
		//if(itm->dwDestNameOff != 0)
		//{
		//	getManifestString(&bodydat[itm->dwDestNameOff], sbuf);
		//	DbgPrint("\tdest name    : %s\n", sbuf);
		//}
		//if(itm->dwVersionOff != 0)
		//{
		//	ver = getBe32(&bodydat[itm->dwVersionOff]);
		//	DbgPrint("\tversion      : %d.%d.%d.%d\n", (ver>>28)&0xF, (ver>>24)&0xF, (ver>>8)&0xFFFF, ver&0xF);
		//}
		//DbgPrint("\ttype         : %d ", itm->dwEntryType);
		//if(itm->dwEntryType == 2)
		//	DbgPrint("(xcontent)\n");
		//else if (itm->dwEntryType == 3)
		//	DbgPrint("(file)\n");
		//else
		//	DbgPrint("(unknown)\n");
		//DbgPrint("\tsize         : 0x%x (%d)\n", itm->dwFileSize, itm->dwFileSize);
		//if(itm->dwFlags != 0)
		//{
		//	DbgPrint("\tflags        : 0x%08x\n", itm->dwFlags);
		//}
		//if(itm->dwEntryType == 2)
		//{
		//	//u32 utempl = itm->dwXContItemListOff;
		//	DbgPrint("\tContentType  : 0x%08x\n", itm->dwContentType);// 0x4C ie 0x00008000
		//	DbgPrint("\tTitleId      : 0x%08x\n", itm->dwContentTitleId);// 0x50 ie 0xFFFE07DF
		//	//DbgPrint("\tContItemList : 0x%08x\n", utempl);// 0x5C num items in container, followed by entry offsets for each item
		//	//DbgPrint("\tContItemNum  : %d\n", getBe32(&bodydat[utempl]));
		//	//DbgPrint("\tdataHash     : "); display_hash(itm->dataHash, 20);
		//	//DbgPrint("\tcontHash     : "); display_hash(itm->contHash, 20); // corresponds to container hash at offset 0x32C
		//}
		//else
		//{
		//	if(itm->dwContentType != 0)
		//		DbgPrint("\tdwContentType is nonzero, 0x%08x\n", itm->dwContentType);
		//	if(itm->dwContentTitleId != 0)
		//		DbgPrint("\tdwContentTitleId is nonzero, 0x%08x\n", itm->dwContentTitleId);
		//	if(itm->dwXContItemListOff != 0)
		//		DbgPrint("\tdwXContItemListOff is nonzero, 0x%08x\n", itm->dwXContItemListOff);
		//}

		//if(itm->dwPad1 != 0)
		//	DbgPrint("\tdwPad1 is nonzero, 0x%08x\n", itm->dwPad1);
		//if(itm->dwPad2 != 0)
		//	DbgPrint("\tdwPad2 is nonzero, 0x%08x\n", itm->dwPad2);
		//if(itm->dwPad3 != 0)
		//	DbgPrint("\tdwPad3 is nonzero, 0x%08x\n", itm->dwPad3);
		//if(itm->dwPad4 != 0)
		//	DbgPrint("\tdwPad4 is nonzero, 0x%08x\n", itm->dwPad4);

		if(itm->dwSrcNameOff != 0)
		{
			getManifestString(&bodydat[itm->dwSrcNameOff], sbuf);
			if(strcmp(sbuf, "flash") != 0)
			{
				getManifestString(&bodydat[itm->dwDestNameOff], sbuf);
				switch(itm->dwEntryType)
				{
				case 2: // xcontent
					if(loadVerifyContainer(&litm, itm->contHash))
					{
						sprintf(tbuf, "%s%s%08X\\%08X\\%s", DESTINATION_BASE, PACKAGE_BASE, itm->dwContentTitleId, itm->dwContentType, sbuf);
						litm.dest = tbuf;
						inf.push_back(litm);
					}
					else if(!verifyOnly) // abort so as to not waste time
						return FALSE;
					break;
				case 3: // file
					if(loadVerifyFile(&litm, itm->dataHash))
					{
						sprintf(tbuf, "%s%08X\\%s", DESTINATION_BASE, ver, sbuf);
						litm.dest = tbuf;
						inf.push_back(litm);
					}
					else if(!verifyOnly) // abort so as to not waste time
						return FALSE;
					break;
				default:
					//litm.dest = "~not copied~";
					//litm.source = "~not copied~";
					break;
				}
				//DbgPrint("source: %s\n", litm.source.c_str());
				//DbgPrint("dest  : %s\n", litm.dest.c_str());
			}
			//else
			//{
			//	strcpy(srcFile, MANIFEST_BASE);
			//	strcat(srcFile, SU_PACKAGE);
			//	loadVerifyContainer(srcFile, 1, NULL);
			//	DbgPrint("~no copy~\n");
			//}
		}
	}
	return TRUE;
}

void cleanInfList(void)
{
	int sz = inf.size();
	if(sz != 0)
	{
		int i;
		for(i = 0; i < sz; i++)
		{
			if(inf.at(i).data != NULL)
				delete[] inf.at(i).data;
		}
	}
	inf.clear();
}

// load an parse manifest, and it's contents
BOOL loadManifest(BOOL verifyOnly, char* manifest_folder)
{
	char manifest_file[80];
	strcpy(manifest_file, manifest_folder);
	strcat(manifest_file, MANIFEST);

	ITEM_INFO litm;
	PSU_MANIFEST man;
	litm.data = ReadFileToBuf(manifest_file, &litm.len);
	if(litm.data != NULL)
	{
		man = (PSU_MANIFEST) litm.data;
		//DbgPrint("loaded manifest, %08x size\n", litm.len);
		if((litm.len <= 0x10000)&&(litm.len >= 0x164))
		{
			if(verifyManifestHeader(man))
			{
				DWORD ver = man->body.cont.dwFlashVer;
				if(!verifyOnly)
				{
					DWORD cver = XamGetSystemVersion();
					if(ver != cver)
					{
						dprintf("Error! Version mismatch\n");
						dprintf("Kernel version: %d.%d.%d.%d\n", (cver>>28)&0xF, (cver>>24)&0xF, (cver>>8)&0xFFFF, cver&0xF);
						dprintf("Update version: %d.%d.%d.%d\n", (ver>>28)&0xF, (ver>>24)&0xF, (ver>>8)&0xFFFF, ver&0xF);
						delete[] litm.data;
						return FALSE;
					}
				}
				dprintf("Manifest ok! Version: %d.%d.%d.%d\n", (ver>>28)&0xF, (ver>>24)&0xF, (ver>>8)&0xFFFF, ver&0xF);
				// check version match to running kernel!!!
				litm.source = manifest_file;
				litm.dest = DESTINATION_BASE;
				litm.dest += "system.manifest";
				inf.push_back(litm);
				if(verifyManifestItems(&litm.data[sizeof(SU_MAINIFEST_HEADER)], litm.len-sizeof(SU_MAINIFEST_HEADER), verifyOnly, manifest_folder))
				{
					dprintf("\n\nUpdate contents of %d installable items verified OK!\n", inf.size());
					return TRUE;
				}
				else if(verifyOnly)
					dprintf("total errors %d\n", errcnt);
					//cleanInfList();
			}
			//else
			//	DbgPrint("manifest header check failed!\n");
		}
		//else
		//	DbgPrint("manifest size error!\n");
		delete[] litm.data;
	}
	dprintf("could not load %s!\n", manifest_file);
	return FALSE;
}

BOOL installFiles(void)
{
	DWORD i;
	dprintf("installing %d files\n", inf.size());
	for(i = 0; i < inf.size(); i++)
	{
		dprintf("\r\n%d - %s", i+1, inf.at(i).dest.c_str());
		if(WriteBufToFile(inf.at(i).dest.c_str(), inf.at(i).data, inf.at(i).len, FALSE) == FALSE)
		{
			dprintf("ERROR WRITING TO DISK!\n");
		}
	}
	dprintf("\n");
	return TRUE;
}

// SEP:\203f4b00 << version specific
// SEP:\32000100
// SEP:\Content\0000000000000000\fffe07df\00008000
BOOL doDirCreate(char* cdir)
{
	char dirname[512] = DESTINATION_BASE;
	strcat(dirname, cdir);
	if(CreateDirectory(dirname, NULL) == 0)
	{
		dprintf("error %d creating directory %s\n", GetLastError(), dirname);
		return FALSE;
	}
	return TRUE;
}

char* dirs[] = {
	"32000100",
	"Content",
	"Content\\0000000000000000",
	"Content\\0000000000000000\\FFFE07DF",
	"Content\\0000000000000000\\FFFE07DF\\00008000",
};

BOOL createDefaultDirs(void)
{
	int i;
	char dirname[16];
	sprintf(dirname, "%08X", XamGetSystemVersion());
	if(doDirCreate(dirname) == FALSE)
		return FALSE;

	for(i = 0; i < sizeof(dirs)/sizeof(char*); i++)
	{
		if(doDirCreate(dirs[i]) == FALSE)
			return FALSE;
	}
	return TRUE;
}

void mountSepAux(void)
{
	MountPath("USEP:", "\\SEP", FALSE);
	MountPath("USAP:", "\\SAP", FALSE);
}

void unmountSepAux(void)
{
	DeleteLink("USEP:", FALSE);
	DeleteLink("USAP:", FALSE);
}

NTSTATUS wipePartition(char* path)
{
	NTSTATUS sts = -1;
	STRING devi;
	HANDLE hDevi;
	OBJECT_ATTRIBUTES oat;
	IO_STATUS_BLOCK ios;
	RtlInitAnsiString(&devi, path);
	oat.RootDirectory = 0;
	oat.ObjectName = &devi;
	oat.Attributes = FILE_ATTRIBUTE_DEVICE;
	
	sts = NtOpenFile(&hDevi, GENERIC_WRITE|GENERIC_READ|SYNCHRONIZE, &oat, &ios, OPEN_EXISTING, FILE_SYNCHRONOUS_IO_NONALERT);
	//sts = NtCreateFile(&hDevi, GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, &oat, &ios, 0, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, 1, FILE_SYNCHRONOUS_IO_NONALERT|8);
	if(sts >= 0)
	{
		BYTE buf[0x4000];
		LARGE_INTEGER lint;
		lint.QuadPart = 0ULL;
		XMemSet(buf, 0, 0x1000);
		//sta = NtWriteFile(hFile, 0, 0, 0, &ioFlash, src, writeSize, &lOffset);
		sts = NtWriteFile(hDevi, NULL, NULL, NULL, &ios, buf, 0x1000, &lint);
		if(sts >= 0)
			DbgPrint("wipe partition %s succeeded\n", path);
		else
			DbgPrint("wipe partition failed to overwrite header: 0x%08x\n", sts);
		NtClose(hDevi);
	}
	else
	{
		DbgPrint("wipe partition %s failed to open the partition: 0x%08x\n", path, sts);
	}
	return sts;
}

NTSTATUS formatPartition(char* path)
{
	STRING devi;
	DWORD val;
	RtlInitAnsiString(&devi, path);
	val = (DWORD)devi.Length;
	val = (val+0x10000)-1;
	devi.Length = val&0xFFFF;
	return XapiFormatFATVolume(&devi);
}

void delinkPartitions(void)
{
	HRESULT res;
	STRING LinkName;
	RtlInitAnsiString(&LinkName, "\\sap");
	res = ObDeleteSymbolicLink(&LinkName);
	DbgPrint("delete \\sap result %x\n", res);
	RtlInitAnsiString(&LinkName, "\\sep");
	res = ObDeleteSymbolicLink(&LinkName);
	DbgPrint("delete \\sep result %x\n", res);
}

void relinkPartitions(char* sepdev, char* sapdev)
{
	HRESULT res;
	STRING LinkName;
	STRING DeviName;
	RtlInitAnsiString(&LinkName, "\\sep");
	RtlInitAnsiString(&DeviName, sepdev);
	res = ObCreateSymbolicLink(&LinkName, &DeviName);
	DbgPrint("create \\sep result %x\n", res);

	RtlInitAnsiString(&LinkName, "\\sap");
	RtlInitAnsiString(&DeviName, sapdev);
	res = ObCreateSymbolicLink(&LinkName, &DeviName);
	DbgPrint("create \\sap result %x\n", res);
}

void formatThread(void)
{
	NTSTATUS ret;
	formatStatus = (DWORD)-1;
	DbgPrint("format thread started\n");
	delinkPartitions();
	ret = wipePartition(hddSysEx);
	DbgPrint("ex wipe  : 0x%x\n", ret);
	ret = formatPartition(hddSysEx);
	DbgPrint("ex format: 0x%x\n", ret);
	if(ret >= 0)
	{
		ret = wipePartition(hddSysAux);
		DbgPrint("ax wipe  : 0x%x\n", ret);
		ret = formatPartition(hddSysAux);
		DbgPrint("ax format: 0x%x\n", ret);
		if(ret >= 0)
		{
			relinkPartitions(hddSysEx, hddSysAux);
			formatStatus = 0;
		}
	}
	doLightSync(&formatStatus);
	threadWaitStatus = 0;
	doLightSync(&threadWaitStatus);
}

BOOL doFormatPartitions(void)
{
	HANDLE pthread;
	DWORD pthreadid;
	threadWaitStatus = 1;
	unmountSepAux();
	doLightSync(&threadWaitStatus);
	DbgPrint("starting format thread\n");
	ExCreateThread(&pthread, 0x8000, &pthreadid, (PVOID) XapiThreadStartup , (LPTHREAD_START_ROUTINE)formatThread, NULL, 0x2);
	XSetThreadProcessor(pthread, 4);
	ResumeThread(pthread);
	CloseHandle(pthread);
	while(threadWaitStatus == 1){Sleep(400);}
	if(formatStatus == 0)
	{
		mountSepAux();
		DbgPrint("format completed successfully!\n");
		return TRUE;
	}
	DbgPrint("format failed horribly!\n");
	return FALSE;
}

HRESULT setupSysPartitions(char* manifest){

	//Mount("\\SystemRoot", "Root:");

	if(!FileExists(manifest))
		return ERROR_SEVERITY_WARNING;

	//loadManifest(FALSE, manifest);
	if(doFormatPartitions())
	{
		dprintf("format succeeded!\n");
		//mountSepAux();
		Mount("\\Device\\Harddisk0\\SystemExtPartition", "\\System??\\SysExt:");
		int retError = CopyDirectory(manifest, "SysExt:");
		if(!retError){
			DeleteDirectory(manifest, TRUE);
			dprintf("sysex install successful!\n");
		}else{
			dprintf("failed to install sysex partition: %08X\n", retError);
		}

		Mount("\\Device\\Harddisk0\\SystemAuxPartition", "\\System??\\SysAux:");
		retError = CopyDirectory("HDD:\\Filesystems\\17489-dev\\$SystemUpdate_aux", "SysAux:");
		if(!retError){
			DeleteDirectory("HDD:\\Filesystems\\17489-dev\\$SystemUpdate_aux", TRUE);
			dprintf("sysaux install successful!\n");
		}else{
			dprintf("failed to install sysaux partition: %08X\n", retError);
		}

		/*if(createDefaultDirs())
		{
			dprintf("default directories created!\n");
			installFiles();
			DeleteDirectory(manifest, TRUE);
		}
		else
			dprintf("format FAILED!\n");*/
	}
	else
		dprintf("format FAILED!\n");

	cleanInfList();
	return ERROR_SEVERITY_SUCCESS;
}
