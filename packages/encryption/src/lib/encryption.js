"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.verifyJwt = exports.decryptFile = exports.encryptFile = exports.decryptZipFileWithMetadata = exports.encryptFileAndZipWithMetadata = exports.encryptZip = exports.decryptZip = exports.zipAndEncryptFiles = exports.zipAndEncryptString = exports.decryptString = exports.encryptString = exports.decryptFromIpfs = exports.encryptToIpfs = void 0;
var constants_1 = require("@lit-protocol/constants");
var bls_sdk_1 = require("@lit-protocol/bls-sdk");
// @ts-ignore
var JSZip = require("jszip/dist/jszip.js");
var uint8arrays_1 = require("@lit-protocol/uint8arrays");
var crypto_1 = require("@lit-protocol/crypto");
var misc_1 = require("@lit-protocol/misc");
var params_validators_1 = require("./params-validators");
var ipfsClient = require("ipfs-http-client");
// ---------- Local Helpers ----------
/**
 *
 * Get all the metadata needed to decrypt something in the future.  If you're encrypting files with Lit and storing them in IPFS or Arweave, then this function will provide you with a properly formatted metadata object that you should save alongside the files.
 *
 * @param { MetadataForFile }
 *
 * @return { MetadataForFile }
 *
 */
var metadataForFile = function (_a) {
    var name = _a.name, type = _a.type, size = _a.size, accessControlConditions = _a.accessControlConditions, evmContractConditions = _a.evmContractConditions, solRpcConditions = _a.solRpcConditions, unifiedAccessControlConditions = _a.unifiedAccessControlConditions, chain = _a.chain, encryptedSymmetricKey = _a.encryptedSymmetricKey;
    return {
        name: name,
        type: type,
        size: size,
        accessControlConditions: accessControlConditions,
        evmContractConditions: evmContractConditions,
        solRpcConditions: solRpcConditions,
        unifiedAccessControlConditions: unifiedAccessControlConditions,
        chain: chain,
        encryptedSymmetricKey: (0, uint8arrays_1.uint8arrayToString)(encryptedSymmetricKey, 'base16')
    };
};
/**
 *
 * Encrypt a string or file, save the key to the Lit network, and upload all the metadata required to decrypt i.e. accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions & chain to IPFS using the ipfs-client-http SDK & returns the IPFS CID.
 *
 * @param { EncryptToIpfsProps }
 *
 * @returns { Promise<string> }
 *
 */
var encryptToIpfs = function (_a) {
    var authSig = _a.authSig, sessionSigs = _a.sessionSigs, accessControlConditions = _a.accessControlConditions, evmContractConditions = _a.evmContractConditions, solRpcConditions = _a.solRpcConditions, unifiedAccessControlConditions = _a.unifiedAccessControlConditions, chain = _a.chain, string = _a.string, file = _a.file, litNodeClient = _a.litNodeClient, ipfsURL = _a.ipfsURL;
    return __awaiter(void 0, void 0, void 0, function () {
        var paramsIsSafe, encryptedData, symmetricKey, encryptedString, encryptedFile, encryptedSymmetricKey, encryptedSymmetricKeyString, ipfs, encryptedDataJson, _b, _c, res, e_1;
        var _d;
        return __generator(this, function (_e) {
            switch (_e.label) {
                case 0:
                    paramsIsSafe = (0, params_validators_1.safeParams)({
                        functionName: 'encryptToIpfs',
                        params: {
                            authSig: authSig,
                            sessionSigs: sessionSigs,
                            accessControlConditions: accessControlConditions,
                            evmContractConditions: evmContractConditions,
                            solRpcConditions: solRpcConditions,
                            unifiedAccessControlConditions: unifiedAccessControlConditions,
                            chain: chain,
                            string: string,
                            file: file,
                            litNodeClient: litNodeClient
                        }
                    });
                    if (!paramsIsSafe)
                        return [2 /*return*/, (0, misc_1.throwError)({
                                message: "authSig, sessionSigs, accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions, chain, litNodeClient, string or file must be provided",
                                errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                                errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                            })];
                    if (string === undefined && file === undefined)
                        return [2 /*return*/, (0, misc_1.throwError)({
                                message: "Either string or file must be provided",
                                errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                                errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                            })];
                    if (!(string !== undefined && file !== undefined)) return [3 /*break*/, 1];
                    return [2 /*return*/, (0, misc_1.throwError)({
                            message: 'Provide only either a string or file to encrypt',
                            errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                            errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                        })];
                case 1:
                    if (!(string !== undefined)) return [3 /*break*/, 3];
                    return [4 /*yield*/, (0, exports.encryptString)(string)];
                case 2:
                    encryptedString = _e.sent();
                    encryptedData = encryptedString.encryptedString;
                    symmetricKey = encryptedString.symmetricKey;
                    return [3 /*break*/, 5];
                case 3: return [4 /*yield*/, (0, exports.encryptFile)({ file: file })];
                case 4:
                    encryptedFile = _e.sent();
                    encryptedData = encryptedFile.encryptedFile;
                    symmetricKey = encryptedFile.symmetricKey;
                    _e.label = 5;
                case 5: return [4 /*yield*/, litNodeClient.saveEncryptionKey({
                        accessControlConditions: accessControlConditions,
                        evmContractConditions: evmContractConditions,
                        solRpcConditions: solRpcConditions,
                        unifiedAccessControlConditions: unifiedAccessControlConditions,
                        symmetricKey: symmetricKey,
                        authSig: authSig,
                        sessionSigs: sessionSigs,
                        chain: chain
                    })];
                case 6:
                    encryptedSymmetricKey = _e.sent();
                    (0, misc_1.log)('encrypted key saved to Lit', encryptedSymmetricKey);
                    encryptedSymmetricKeyString = (0, uint8arrays_1.uint8arrayToString)(encryptedSymmetricKey, 'base16');
                    ipfs = ipfsClient.create({
                        url: ipfsURL
                    });
                    _c = (_b = Buffer).from;
                    return [4 /*yield*/, encryptedData.arrayBuffer()];
                case 7:
                    encryptedDataJson = _c.apply(_b, [_e.sent()]).toJSON();
                    _e.label = 8;
                case 8:
                    _e.trys.push([8, 10, , 11]);
                    return [4 /*yield*/, ipfs.add(JSON.stringify((_d = {},
                            _d[string !== undefined ? 'encryptedString' : 'encryptedFile'] = encryptedDataJson,
                            _d.encryptedSymmetricKeyString = encryptedSymmetricKeyString,
                            _d.accessControlConditions = accessControlConditions,
                            _d.evmContractConditions = evmContractConditions,
                            _d.solRpcConditions = solRpcConditions,
                            _d.unifiedAccessControlConditions = unifiedAccessControlConditions,
                            _d.chain = chain,
                            _d)))];
                case 9:
                    res = _e.sent();
                    return [2 /*return*/, res.path];
                case 10:
                    e_1 = _e.sent();
                    return [2 /*return*/, (0, misc_1.throwError)({
                            message: "There is something wrong that we can not upload to IPFS",
                            errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                            errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
                        })];
                case 11: return [2 /*return*/];
            }
        });
    });
};
exports.encryptToIpfs = encryptToIpfs;
/**
 *
 * Decrypt & return the string or file (in Uint8Array format) using its metadata stored on IPFS with the given ipfsCid.
 *
 * @param { DecryptFromIpfsProps }
 *
 * @returns { Promise<string | Uint8Array> }
 *
 */
var decryptFromIpfs = function (_a) {
    var authSig = _a.authSig, sessionSigs = _a.sessionSigs, ipfsCid = _a.ipfsCid, litNodeClient = _a.litNodeClient;
    return __awaiter(void 0, void 0, void 0, function () {
        var paramsIsSafe, metadata, symmetricKey, encryptedStringBlob, encryptedFileBlob, e_2;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    paramsIsSafe = (0, params_validators_1.safeParams)({
                        functionName: 'decryptFromIpfs',
                        params: {
                            authSig: authSig,
                            sessionSigs: sessionSigs,
                            ipfsCid: ipfsCid,
                            litNodeClient: litNodeClient
                        }
                    });
                    if (!paramsIsSafe)
                        return [2 /*return*/, (0, misc_1.throwError)({
                                message: "authSig, sessionSigs, ipfsCid, litNodeClient must be provided",
                                errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                                errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                            })];
                    _b.label = 1;
                case 1:
                    _b.trys.push([1, 8, , 9]);
                    return [4 /*yield*/, fetch("https://gateway.pinata.cloud/ipfs/".concat(ipfsCid))];
                case 2: return [4 /*yield*/, (_b.sent()).json()];
                case 3:
                    metadata = _b.sent();
                    return [4 /*yield*/, litNodeClient.getEncryptionKey({
                            accessControlConditions: metadata.accessControlConditions,
                            evmContractConditions: metadata.evmContractConditions,
                            solRpcConditions: metadata.solRpcConditions,
                            unifiedAccessControlConditions: metadata.unifiedAccessControlConditions,
                            toDecrypt: metadata.encryptedSymmetricKeyString,
                            chain: metadata.chain,
                            authSig: authSig,
                            sessionSigs: sessionSigs
                        })];
                case 4:
                    symmetricKey = _b.sent();
                    if (!(metadata.encryptedString !== undefined)) return [3 /*break*/, 6];
                    encryptedStringBlob = new Blob([Buffer.from(metadata.encryptedString)], { type: 'application/octet-stream' });
                    return [4 /*yield*/, (0, exports.decryptString)(encryptedStringBlob, symmetricKey)];
                case 5: return [2 /*return*/, _b.sent()];
                case 6:
                    encryptedFileBlob = new Blob([Buffer.from(metadata.encryptedFile)], {
                        type: 'application/octet-stream'
                    });
                    return [4 /*yield*/, (0, exports.decryptFile)({ file: encryptedFileBlob, symmetricKey: symmetricKey })];
                case 7: return [2 /*return*/, _b.sent()];
                case 8:
                    e_2 = _b.sent();
                    return [2 /*return*/, (0, misc_1.throwError)({
                            message: 'Invalid ipfsCid',
                            errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                            errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
                        })];
                case 9: return [2 /*return*/];
            }
        });
    });
};
exports.decryptFromIpfs = decryptFromIpfs;
// ---------- Local Helpers ----------
/**
 *
 * Encrypt a string.  This is used to encrypt any string that is to be locked via the Lit Protocol.
 *
 * @param { string } str The string to encrypt
 * @returns { Promise<Object> } A promise containing the encryptedString as a Blob and the symmetricKey used to encrypt it, as a Uint8Array.
 */
var encryptString = function (str) { return __awaiter(void 0, void 0, void 0, function () {
    var encodedString, symmKey, encryptedString, exportedSymmKey, _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                // -- validate
                if (!(0, misc_1.checkType)({
                    value: str,
                    allowedTypes: ['String'],
                    paramName: 'str',
                    functionName: 'encryptString'
                })) {
                    return [2 /*return*/, (0, misc_1.throwError)({
                            message: "{".concat(str, "} must be a string"),
                            errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                            errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                        })];
                }
                encodedString = (0, uint8arrays_1.uint8arrayFromString)(str, 'utf8');
                return [4 /*yield*/, (0, crypto_1.generateSymmetricKey)()];
            case 1:
                symmKey = _b.sent();
                return [4 /*yield*/, (0, crypto_1.encryptWithSymmetricKey)(symmKey, encodedString.buffer)];
            case 2:
                encryptedString = _b.sent();
                _a = Uint8Array.bind;
                return [4 /*yield*/, crypto.subtle.exportKey('raw', symmKey)];
            case 3:
                exportedSymmKey = new (_a.apply(Uint8Array, [void 0, _b.sent()]))();
                return [2 /*return*/, {
                        symmetricKey: exportedSymmKey,
                        encryptedString: encryptedString,
                        encryptedData: encryptedString
                    }];
        }
    });
}); };
exports.encryptString = encryptString;
/**
 *
 * Decrypt a string that was encrypted with the encryptString function.
 *
 * @param { AcceptedFileType } encryptedStringBlob The encrypted string as a Blob
 * @param { Uint8Array } symmKey The symmetric key used that will be used to decrypt this.
 *
 * @returns { Promise<string> } A promise containing the decrypted string
 */
var decryptString = function (encryptedStringBlob, symmKey) { return __awaiter(void 0, void 0, void 0, function () {
    var paramsIsSafe, importedSymmKey, decryptedStringArrayBuffer;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                paramsIsSafe = (0, params_validators_1.safeParams)({
                    functionName: 'decryptString',
                    params: [encryptedStringBlob, symmKey]
                });
                if (!paramsIsSafe) {
                    (0, misc_1.throwError)({
                        message: 'Invalid params',
                        errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                        errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                    });
                }
                return [4 /*yield*/, (0, crypto_1.importSymmetricKey)(symmKey)];
            case 1:
                importedSymmKey = _a.sent();
                return [4 /*yield*/, (0, crypto_1.decryptWithSymmetricKey)(encryptedStringBlob, importedSymmKey)];
            case 2:
                decryptedStringArrayBuffer = _a.sent();
                return [2 /*return*/, (0, uint8arrays_1.uint8arrayToString)(new Uint8Array(decryptedStringArrayBuffer), 'utf8')];
        }
    });
}); };
exports.decryptString = decryptString;
/**
 *
 * Zip and encrypt a string.  This is used to encrypt any string that is to be locked via the Lit Protocol.
 *
 * @param { string } string The string to zip and encrypt
 *
 * @returns { Promise<Object> } A promise containing the encryptedZip as a Blob and the symmetricKey used to encrypt it, as a Uint8Array.  The encrypted zip will contain a single file called "string.txt"
 */
var zipAndEncryptString = function (string) { return __awaiter(void 0, void 0, void 0, function () {
    var zip;
    return __generator(this, function (_a) {
        // -- validate
        if (!(0, misc_1.checkType)({
            value: string,
            allowedTypes: ['String'],
            paramName: 'string',
            functionName: 'zipAndEncryptString'
        }))
            (0, misc_1.throwError)({
                message: 'Invalid string',
                errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
            });
        try {
            zip = new JSZip["default"]();
        }
        catch (e) {
            zip = new JSZip();
        }
        zip.file('string.txt', string);
        return [2 /*return*/, (0, exports.encryptZip)(zip)];
    });
}); };
exports.zipAndEncryptString = zipAndEncryptString;
/**
 *
 * Zip and encrypt multiple files.
 *
 * @param { Array<File> } files An array of the files you wish to zip and encrypt
 *
 * @returns {Promise<Object>} A promise containing the encryptedZip as a Blob and the symmetricKey used to encrypt it, as a Uint8Array.  The encrypted zip will contain a folder "encryptedAssets" and all of the files will be inside it.
 
*/
var zipAndEncryptFiles = function (files) { return __awaiter(void 0, void 0, void 0, function () {
    var zip, i, folder;
    return __generator(this, function (_a) {
        try {
            zip = new JSZip["default"]();
        }
        catch (e) {
            zip = new JSZip();
        }
        // -- zip each file
        for (i = 0; i < files.length; i++) {
            // -- validate
            if (!(0, misc_1.checkType)({
                value: files[i],
                allowedTypes: ['File'],
                paramName: "files[".concat(i, "]"),
                functionName: 'zipAndEncryptFiles'
            }))
                (0, misc_1.throwError)({
                    message: 'Invalid file type',
                    errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                    errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                });
            folder = zip.folder('encryptedAssets');
            if (!folder) {
                (0, misc_1.log)("Failed to get 'encryptedAssets' from zip.folder() ");
                return [2 /*return*/, (0, misc_1.throwError)({
                        message: "Failed to get 'encryptedAssets' from zip.folder() ",
                        errorKind: constants_1.LIT_ERROR.UNKNOWN_ERROR.kind,
                        errorCode: constants_1.LIT_ERROR.UNKNOWN_ERROR.name
                    })];
            }
            folder.file(files[i].name, files[i]);
        }
        return [2 /*return*/, (0, exports.encryptZip)(zip)];
    });
}); };
exports.zipAndEncryptFiles = zipAndEncryptFiles;
/**
 *
 * Decrypt and unzip a zip that was created using encryptZip, zipAndEncryptString, or zipAndEncryptFiles.
 *
 * @param { AcceptedFileType } encryptedZipBlob The encrypted zip as a Blob
 * @param { SymmetricKey } symmKey The symmetric key used that will be used to decrypt this zip.
 *
 * @returns { Promise<Object> } A promise containing a JSZip object indexed by the filenames of the zipped files.  For example, if you have a file called "meow.jpg" in the root of your zip, you could get it from the JSZip object by doing this: const imageBlob = await decryptedZip['meow.jpg'].async('blob')
 */
var decryptZip = function (encryptedZipBlob, symmKey) { return __awaiter(void 0, void 0, void 0, function () {
    var paramsIsSafe, importedSymmKey, decryptedZipArrayBuffer, zip, unzipped;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                paramsIsSafe = (0, params_validators_1.safeParams)({
                    functionName: 'decryptZip',
                    params: {
                        encryptedZipBlob: encryptedZipBlob,
                        symmKey: symmKey
                    }
                });
                if (!paramsIsSafe) {
                    (0, misc_1.throwError)({
                        message: "encryptedZipBlob must be a Blob or File. symmKey must be a Uint8Array",
                        errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                        errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                    });
                }
                return [4 /*yield*/, (0, crypto_1.importSymmetricKey)(symmKey)];
            case 1:
                importedSymmKey = _a.sent();
                return [4 /*yield*/, (0, crypto_1.decryptWithSymmetricKey)(encryptedZipBlob, importedSymmKey)];
            case 2:
                decryptedZipArrayBuffer = _a.sent();
                try {
                    zip = new JSZip["default"]();
                }
                catch (e) {
                    zip = new JSZip();
                }
                return [4 /*yield*/, zip.loadAsync(decryptedZipArrayBuffer)];
            case 3:
                unzipped = _a.sent();
                return [2 /*return*/, unzipped.files];
        }
    });
}); };
exports.decryptZip = decryptZip;
/**
 *
 * Encrypt a zip file created with JSZip using a new random symmetric key via WebCrypto.
 *
 * @param { JSZip } zip The JSZip instance to encrypt
 *
 * @returns { Promise<Object> } A promise containing the encryptedZip as a Blob and the symmetricKey used to encrypt it, as a Uint8Array string.
 */
var encryptZip = function (zip) { return __awaiter(void 0, void 0, void 0, function () {
    var zipBlob, zipBlobArrayBuffer, symmKey, encryptedZipBlob, exportedSymmKey, _a, encryptedZip;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                if (!(0, misc_1.isBrowser)()) return [3 /*break*/, 3];
                return [4 /*yield*/, zip.generateAsync({ type: 'blob' })];
            case 1:
                zipBlob = _b.sent();
                return [4 /*yield*/, zipBlob.arrayBuffer()];
            case 2:
                zipBlobArrayBuffer = _b.sent();
                return [3 /*break*/, 5];
            case 3: return [4 /*yield*/, zip.generateAsync({ type: 'nodebuffer' })];
            case 4:
                zipBlobArrayBuffer = _b.sent();
                _b.label = 5;
            case 5: return [4 /*yield*/, (0, crypto_1.generateSymmetricKey)()];
            case 6:
                symmKey = _b.sent();
                return [4 /*yield*/, (0, crypto_1.encryptWithSymmetricKey)(symmKey, zipBlobArrayBuffer)];
            case 7:
                encryptedZipBlob = _b.sent();
                _a = Uint8Array.bind;
                return [4 /*yield*/, crypto.subtle.exportKey('raw', symmKey)];
            case 8:
                exportedSymmKey = new (_a.apply(Uint8Array, [void 0, _b.sent()]))();
                encryptedZip = {
                    symmetricKey: exportedSymmKey,
                    encryptedZip: encryptedZipBlob
                };
                return [2 /*return*/, encryptedZip];
        }
    });
}); };
exports.encryptZip = encryptZip;
/**
 *
 * Encrypt a single file, save the key to the Lit network, and then zip it up with the metadata.
 *
 * @param { EncryptFileAndZipWithMetadataProps }
 *
 * @returns { Promise<ThreeKeys> }
 *
 */
var encryptFileAndZipWithMetadata = function (_a) {
    var authSig = _a.authSig, sessionSigs = _a.sessionSigs, accessControlConditions = _a.accessControlConditions, evmContractConditions = _a.evmContractConditions, solRpcConditions = _a.solRpcConditions, unifiedAccessControlConditions = _a.unifiedAccessControlConditions, chain = _a.chain, file = _a.file, litNodeClient = _a.litNodeClient, readme = _a.readme;
    return __awaiter(void 0, void 0, void 0, function () {
        var paramsIsSafe, symmetricKey, exportedSymmKey, _b, encryptedSymmetricKey, fileAsArrayBuffer, encryptedZipBlob, zip, metadata, folder, zipBlob, threeKeys;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    paramsIsSafe = (0, params_validators_1.safeParams)({
                        functionName: 'encryptFileAndZipWithMetadata',
                        params: {
                            authSig: authSig,
                            sessionSigs: sessionSigs,
                            accessControlConditions: accessControlConditions,
                            evmContractConditions: evmContractConditions,
                            solRpcConditions: solRpcConditions,
                            unifiedAccessControlConditions: unifiedAccessControlConditions,
                            chain: chain,
                            file: file,
                            litNodeClient: litNodeClient,
                            readme: readme
                        }
                    });
                    if (!paramsIsSafe)
                        return [2 /*return*/, (0, misc_1.throwError)({
                                message: "authSig, sessionSigs, accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions, chain, file, litNodeClient, and readme must be provided",
                                errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                                errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                            })];
                    return [4 /*yield*/, (0, crypto_1.generateSymmetricKey)()];
                case 1:
                    symmetricKey = _c.sent();
                    _b = Uint8Array.bind;
                    return [4 /*yield*/, crypto.subtle.exportKey('raw', symmetricKey)];
                case 2:
                    exportedSymmKey = new (_b.apply(Uint8Array, [void 0, _c.sent()]))();
                    return [4 /*yield*/, litNodeClient.saveEncryptionKey({
                            accessControlConditions: accessControlConditions,
                            evmContractConditions: evmContractConditions,
                            solRpcConditions: solRpcConditions,
                            unifiedAccessControlConditions: unifiedAccessControlConditions,
                            symmetricKey: exportedSymmKey,
                            authSig: authSig,
                            sessionSigs: sessionSigs,
                            chain: chain
                        })];
                case 3:
                    encryptedSymmetricKey = _c.sent();
                    (0, misc_1.log)('encrypted key saved to Lit', encryptedSymmetricKey);
                    return [4 /*yield*/, file.arrayBuffer()];
                case 4:
                    fileAsArrayBuffer = _c.sent();
                    return [4 /*yield*/, (0, crypto_1.encryptWithSymmetricKey)(symmetricKey, fileAsArrayBuffer)];
                case 5:
                    encryptedZipBlob = _c.sent();
                    try {
                        zip = new JSZip["default"]();
                    }
                    catch (e) {
                        zip = new JSZip();
                    }
                    metadata = metadataForFile({
                        name: file.name,
                        type: file.type,
                        size: file.size,
                        encryptedSymmetricKey: encryptedSymmetricKey,
                        accessControlConditions: accessControlConditions,
                        evmContractConditions: evmContractConditions,
                        solRpcConditions: solRpcConditions,
                        unifiedAccessControlConditions: unifiedAccessControlConditions,
                        chain: chain
                    });
                    zip.file('lit_protocol_metadata.json', JSON.stringify(metadata));
                    if (readme) {
                        zip.file('readme.txt', readme);
                    }
                    folder = zip.folder('encryptedAssets');
                    if (!folder) {
                        (0, misc_1.log)("Failed to get 'encryptedAssets' from zip.folder() ");
                        return [2 /*return*/, (0, misc_1.throwError)({
                                message: "Failed to get 'encryptedAssets' from zip.folder()",
                                errorKind: constants_1.LIT_ERROR.UNKNOWN_ERROR.kind,
                                errorCode: constants_1.LIT_ERROR.UNKNOWN_ERROR.name
                            })];
                    }
                    folder.file(file.name, encryptedZipBlob);
                    return [4 /*yield*/, zip.generateAsync({ type: 'blob' })];
                case 6:
                    zipBlob = _c.sent();
                    threeKeys = {
                        zipBlob: zipBlob,
                        encryptedSymmetricKey: encryptedSymmetricKey,
                        symmetricKey: exportedSymmKey
                    };
                    return [2 /*return*/, threeKeys];
            }
        });
    });
};
exports.encryptFileAndZipWithMetadata = encryptFileAndZipWithMetadata;
/**
 *
 * Given a zip file with metadata inside it, unzip, load the metadata, and return the decrypted file and the metadata.  This zip file would have been created with the encryptFileAndZipWithMetadata function.
 *
 * @param { DecryptZipFileWithMetadataProps }
 *
 * @returns { Promise<DecryptZipFileWithMetadata> } A promise containing an object that contains decryptedFile and metadata properties.  The decryptedFile is an ArrayBuffer that is ready to use, and metadata is an object that contains all the properties of the file like it's name and size and type.
 */
var decryptZipFileWithMetadata = function (_a) {
    var authSig = _a.authSig, sessionSigs = _a.sessionSigs, file = _a.file, litNodeClient = _a.litNodeClient, additionalAccessControlConditions = _a.additionalAccessControlConditions;
    return __awaiter(void 0, void 0, void 0, function () {
        var paramsIsSafe, zip, jsonFile, metadata, _b, _c, symmKey, e_3, i, accessControlConditions, e_4, importedSymmKey, folder, _file, encryptedFile, decryptedFile, data;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    paramsIsSafe = (0, params_validators_1.safeParams)({
                        functionName: 'decryptZipFileWithMetadata',
                        params: {
                            authSig: authSig,
                            sessionSigs: sessionSigs,
                            file: file,
                            litNodeClient: litNodeClient,
                            additionalAccessControlConditions: additionalAccessControlConditions
                        }
                    });
                    if (!paramsIsSafe)
                        return [2 /*return*/];
                    return [4 /*yield*/, JSZip.loadAsync(file)];
                case 1:
                    zip = _d.sent();
                    jsonFile = zip.file('lit_protocol_metadata.json');
                    if (!jsonFile) {
                        (0, misc_1.log)("Failed to read lit_protocol_metadata.json while zip.file()");
                        return [2 /*return*/];
                    }
                    _c = (_b = JSON).parse;
                    return [4 /*yield*/, jsonFile.async('string')];
                case 2:
                    metadata = _c.apply(_b, [_d.sent()]);
                    (0, misc_1.log)('zip metadata', metadata);
                    _d.label = 3;
                case 3:
                    _d.trys.push([3, 5, , 14]);
                    return [4 /*yield*/, litNodeClient.getEncryptionKey({
                            accessControlConditions: metadata.accessControlConditions,
                            evmContractConditions: metadata.evmContractConditions,
                            solRpcConditions: metadata.solRpcConditions,
                            unifiedAccessControlConditions: metadata.unifiedAccessControlConditions,
                            toDecrypt: metadata.encryptedSymmetricKey,
                            chain: metadata.chain,
                            authSig: authSig,
                            sessionSigs: sessionSigs
                        })];
                case 4:
                    symmKey = _d.sent();
                    return [3 /*break*/, 14];
                case 5:
                    e_3 = _d.sent();
                    if (!(e_3.errorCode === 'NodeNotAuthorized' ||
                        e_3.errorCode === 'not_authorized')) return [3 /*break*/, 12];
                    // try more additionalAccessControlConditions
                    if (!additionalAccessControlConditions) {
                        throw e_3;
                    }
                    (0, misc_1.log)('trying additionalAccessControlConditions');
                    i = 0;
                    _d.label = 6;
                case 6:
                    if (!(i < additionalAccessControlConditions.length)) return [3 /*break*/, 11];
                    accessControlConditions = additionalAccessControlConditions[i].accessControlConditions;
                    (0, misc_1.log)('trying additional condition', accessControlConditions);
                    _d.label = 7;
                case 7:
                    _d.trys.push([7, 9, , 10]);
                    return [4 /*yield*/, litNodeClient.getEncryptionKey({
                            accessControlConditions: accessControlConditions,
                            toDecrypt: additionalAccessControlConditions[i].encryptedSymmetricKey,
                            chain: metadata.chain,
                            authSig: authSig,
                            sessionSigs: sessionSigs
                        })];
                case 8:
                    symmKey = _d.sent();
                    // okay we got the additional symmkey, now we need to decrypt the symmkey and then use it to decrypt the original symmkey
                    // const importedAdditionalSymmKey = await importSymmetricKey(symmKey)
                    // symmKey = await decryptWithSymmetricKey(additionalAccessControlConditions[i].encryptedSymmetricKey, importedAdditionalSymmKey)
                    return [3 /*break*/, 11]; // it worked, we can leave the loop and stop checking additional access control conditions
                case 9:
                    e_4 = _d.sent();
                    // swallow not_authorized because we are gonna try some more accessControlConditions
                    if (e_4.errorCode === 'NodeNotAuthorized' ||
                        e_4.errorCode === 'not_authorized') {
                        throw e_4;
                    }
                    return [3 /*break*/, 10];
                case 10:
                    i++;
                    return [3 /*break*/, 6];
                case 11:
                    // -- loop ends
                    if (!symmKey) {
                        // we tried all the access control conditions and none worked
                        throw e_3;
                    }
                    return [3 /*break*/, 13];
                case 12: throw e_3;
                case 13: return [3 /*break*/, 14];
                case 14:
                    if (!symmKey) {
                        return [2 /*return*/];
                    }
                    return [4 /*yield*/, (0, crypto_1.importSymmetricKey)(symmKey)];
                case 15:
                    importedSymmKey = _d.sent();
                    folder = zip.folder('encryptedAssets');
                    if (!folder) {
                        (0, misc_1.log)("Failed to get 'encryptedAssets' from zip.folder() ");
                        return [2 /*return*/];
                    }
                    _file = folder.file(metadata.name);
                    if (!_file) {
                        (0, misc_1.log)("Failed to get 'metadata.name' while zip.folder().file()");
                        return [2 /*return*/];
                    }
                    return [4 /*yield*/, _file.async('blob')];
                case 16:
                    encryptedFile = _d.sent();
                    return [4 /*yield*/, (0, crypto_1.decryptWithSymmetricKey)(encryptedFile, importedSymmKey)];
                case 17:
                    decryptedFile = _d.sent();
                    data = { decryptedFile: decryptedFile, metadata: metadata };
                    return [2 /*return*/, data];
            }
        });
    });
};
exports.decryptZipFileWithMetadata = decryptZipFileWithMetadata;
/**
 *
 * Encrypt a file without doing any zipping or packing.  This is useful for large files.  A 1gb file can be encrypted in only 2 seconds, for example.  A new random symmetric key will be created and returned along with the encrypted file.
 *
 * @param { Object } params
 * @param { AcceptedFileType } params.file The file you wish to encrypt
 *
 * @returns { Promise<Object> } A promise containing an object with keys encryptedFile and symmetricKey.  encryptedFile is a Blob, and symmetricKey is a Uint8Array that can be used to decrypt the file.
 */
var encryptFile = function (_a) {
    var file = _a.file;
    return __awaiter(void 0, void 0, void 0, function () {
        var symmetricKey, exportedSymmKey, _b, fileAsArrayBuffer, encryptedFile, _encryptedFile;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    // -- validate
                    if (!(0, misc_1.checkType)({
                        value: file,
                        allowedTypes: ['Blob', 'File'],
                        paramName: 'file',
                        functionName: 'encryptFile'
                    })) {
                        return [2 /*return*/, (0, misc_1.throwError)({
                                message: 'file must be a Blob or File',
                                errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                                errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                            })];
                    }
                    return [4 /*yield*/, (0, crypto_1.generateSymmetricKey)()];
                case 1:
                    symmetricKey = _c.sent();
                    _b = Uint8Array.bind;
                    return [4 /*yield*/, crypto.subtle.exportKey('raw', symmetricKey)];
                case 2:
                    exportedSymmKey = new (_b.apply(Uint8Array, [void 0, _c.sent()]))();
                    return [4 /*yield*/, file.arrayBuffer()];
                case 3:
                    fileAsArrayBuffer = _c.sent();
                    return [4 /*yield*/, (0, crypto_1.encryptWithSymmetricKey)(symmetricKey, fileAsArrayBuffer)];
                case 4:
                    encryptedFile = _c.sent();
                    _encryptedFile = {
                        encryptedFile: encryptedFile,
                        symmetricKey: exportedSymmKey
                    };
                    return [2 /*return*/, _encryptedFile];
            }
        });
    });
};
exports.encryptFile = encryptFile;
/**
 *
 * Decrypt a file that was encrypted with the encryptFile function, without doing any unzipping or unpacking.  This is useful for large files.  A 1gb file can be decrypted in only 1 second, for example.
 *
 * @property { Object } params
 * @property { AcceptedFileType } params.file The file you wish to decrypt
 * @property { Uint8Array } params.symmetricKey The symmetric key used that will be used to decrypt this.
 *
 * @returns { Promise<Object> } A promise containing the decrypted file.  The file is an ArrayBuffer.
 */
var decryptFile = function (_a) {
    var file = _a.file, symmetricKey = _a.symmetricKey;
    return __awaiter(void 0, void 0, void 0, function () {
        var paramsIsSafe, importedSymmKey, decryptedFile;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    paramsIsSafe = (0, params_validators_1.safeParams)({
                        functionName: 'decryptFile',
                        params: {
                            file: file,
                            symmetricKey: symmetricKey
                        }
                    });
                    if (!paramsIsSafe) {
                        return [2 /*return*/, (0, misc_1.throwError)({
                                message: "file type must be Blob or File, and symmetricKey type must be Uint8Array | string | CryptoKey | BufferSource",
                                errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                                errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
                            })];
                    }
                    return [4 /*yield*/, (0, crypto_1.importSymmetricKey)(symmetricKey)];
                case 1:
                    importedSymmKey = _b.sent();
                    return [4 /*yield*/, (0, crypto_1.decryptWithSymmetricKey)(file, importedSymmKey)];
                case 2:
                    decryptedFile = _b.sent();
                    return [2 /*return*/, decryptedFile];
            }
        });
    });
};
exports.decryptFile = decryptFile;
/**
 * // TODO check for expiration
 *
 * Verify a JWT from the LIT network.  Use this for auth on your server.  For some background, users can define resources (URLs) for authorization via on-chain conditions using the saveSigningCondition function.  Other users can then request a signed JWT proving that their ETH account meets those on-chain conditions using the getSignedToken function.  Then, servers can verify that JWT using this function.  A successful verification proves that the user meets the on-chain conditions defined in the saveSigningCondition step.  For example, the on-chain condition could be posession of a specific NFT.
 *
 * @param { VerifyJWTProps } jwt
 *
 * @returns { IJWT } An object with 4 keys: "verified": A boolean that represents whether or not the token verifies successfully.  A true result indicates that the token was successfully verified.  "header": the JWT header.  "payload": the JWT payload which includes the resource being authorized, etc.  "signature": A uint8array that represents the raw  signature of the JWT.
 */
var verifyJwt = function (_a) {
    var jwt = _a.jwt;
    // -- validate
    if (!(0, misc_1.checkType)({
        value: jwt,
        allowedTypes: ['String'],
        paramName: 'jwt',
        functionName: 'verifyJwt'
    }))
        return (0, misc_1.throwError)({
            message: 'jwt must be a string',
            errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
            errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
        });
    (0, misc_1.log)('verifyJwt', jwt);
    // verify that the wasm was loaded
    if (!globalThis.wasmExports) {
        (0, misc_1.log)('wasmExports is not loaded.');
    }
    var pubKey = (0, uint8arrays_1.uint8arrayFromString)(constants_1.NETWORK_PUB_KEY, 'base16');
    // log("pubkey is ", pubKey);
    var jwtParts = jwt.split('.');
    var sig = (0, uint8arrays_1.uint8arrayFromString)(jwtParts[2], 'base64url');
    // log("sig is ", uint8arrayToString(sig, "base16"));
    var unsignedJwt = "".concat(jwtParts[0], ".").concat(jwtParts[1]);
    // log("unsignedJwt is ", unsignedJwt);
    var message = (0, uint8arrays_1.uint8arrayFromString)(unsignedJwt);
    // log("message is ", message);
    // p is public key uint8array
    // s is signature uint8array
    // m is message uint8array
    // function is: function (p, s, m)
    var verified = Boolean(bls_sdk_1.wasmBlsSdkHelpers.verify(pubKey, sig, message));
    var _jwt = {
        verified: verified,
        header: JSON.parse((0, uint8arrays_1.uint8arrayToString)((0, uint8arrays_1.uint8arrayFromString)(jwtParts[0], 'base64url'))),
        payload: JSON.parse((0, uint8arrays_1.uint8arrayToString)((0, uint8arrays_1.uint8arrayFromString)(jwtParts[1], 'base64url'))),
        signature: sig
    };
    return _jwt;
};
exports.verifyJwt = verifyJwt;
