#pragma once

#define PROTECTED_KEYVAULT_MAGIC 'PRKV'
#define PROTECTED_KEYVAULT_SIZE (2048 / 8) + 0x4000

#pragma pack(push, 1)
struct KeyVaultProtectHeader {
	DWORD dwMagic;
	BYTE pbKey[0x10];
	BYTE pbIV[0x10];
	BYTE pbHash[XECRYPT_SHA_DIGEST_SIZE];
};
#pragma pack(pop)

typedef struct _KEY_VAULT { // Key #
	BYTE hmacShaDigest[0x10]; // 0x0
	BYTE confounder[0x08]; // 0x10
	BYTE manufacturingMode; // 0x18
	BYTE alternateKeyVault; // 0x1
	BYTE restrictedPrivilegesFlags; // 0x1A
	BYTE reservedByte3; // 0x1B
	WORD oddFeatures; // 0x1C
	WORD oddAuthtype; // 0x1E
	DWORD restrictedHvextLoader; // 0x20
	DWORD policyFlashSize; // 0x24
	DWORD policyBuiltinUsbmuSize; // 0x28
	DWORD reservedDword4; // 0x2C
	QWORD restrictedPrivileges; // 0x30
	QWORD reservedQword2; // 0x38
	QWORD reservedQword3; // 0x40
	QWORD reservedQword4; // 0x48
	BYTE reservedKey1[0x10]; // 0x50
	BYTE reservedKey2[0x10]; // 0x60
	BYTE reservedKey3[0x10]; // 0x70
	BYTE reservedKey4[0x10]; // 0x80
	BYTE reservedRandomKey1[0x10]; // 0x90
	BYTE reservedRandomKey2[0x10]; // 0xA0
	BYTE consoleSerialNumber[0xC]; // 0xB0
	BYTE moboSerialNumber[0xC]; // 0xBC
	WORD gameRegion; // 0xC8
	BYTE padding1[0x6]; // 0xCA
	BYTE consoleObfuscationKey[0x10]; // 0xD0
	BYTE keyObfuscationKey[0x10]; // 0xE0
	BYTE roamableObfuscationKey[0x10]; // 0xF0
	BYTE dvdKey[0x10]; // 0x100
	BYTE primaryActivationKey[0x18]; // 0x110
	BYTE secondaryActivationKey[0x10]; // 0x128
	BYTE globalDevice2desKey1[0x10]; // 0x138
	BYTE globalDevice2desKey2[0x10]; // 0x148
	BYTE wirelessControllerMs2desKey1[0x10]; // 0x158
	BYTE wirelessControllerMs2desKey2[0x10]; // 0x168
	BYTE wiredWebcamMs2desKey1[0x10]; // 0x178
	BYTE wiredWebcamMs2desKey2[0x10]; // 0x188
	BYTE wiredControllerMs2desKey1[0x10]; // 0x198
	BYTE wiredControllerMs2desKey2[0x10]; // 0x1A8
	BYTE memoryUnitMs2desKey1[0x10]; // 0x1B8
	BYTE memoryUnitMs2desKey2[0x10]; // 0x1C8
	BYTE otherXsm3DeviceMs2desKey1[0x10]; // 0x1D8
	BYTE otherXsm3DeviceMs2desKey2[0x10]; // 0x1E8
	BYTE wirelessController3p2desKey1[0x10]; // 0x1F8
	BYTE wirelessController3p2desKey2[0x10]; // 0x208
	BYTE wiredWebcam3p2desKey1[0x10]; // 0x218
	BYTE wiredWebcam3p2desKey2[0x10]; // 0x228
	BYTE wiredController3p2desKey1[0x10]; // 0x238
	BYTE wiredController3p2desKey2[0x10]; // 0x248
	BYTE memoryUnit3p2desKey1[0x10]; // 0x258
	BYTE memoryUnit3p2desKey2[0x10]; // 0x268
	BYTE otherXsm3Device3p2desKey1[0x10]; // 0x278
	BYTE otherXsm3Device3p2desKey2[0x10]; // 0x288
	XECRYPT_RSAPRV_1024 consolePrivateKey; // 0x298 //length 0x1D0
	XECRYPT_RSAPRV_2048 xeIkaPrivateKey; // 0x468 //length 0x390
	XECRYPT_RSAPRV_1024 cardeaPrivateKey; // 0x7F8
	XE_CONSOLE_CERTIFICATE consoleCertificate; // 0x9C8
	XEIKA_CERTIFICATE xeIkaCertificate; // 0xB70
	BYTE keyVaultSignature[0x100]; // 0x1DF8
	BYTE cardeaCertificate[0x2108]; // 0x1EF8 to 0x4000
} KEY_VAULT, *PKEY_VAULT;