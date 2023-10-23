"use strict";
/**
 * Param Validators is an abstraction of validating params of a function, each validator
 * returns a boolean value indicating whether the validation is passed or not.
 */
exports.__esModule = true;
exports.paramsValidators = exports.safeParams = void 0;
var constants_1 = require("@lit-protocol/constants");
var misc_1 = require("@lit-protocol/misc");
var safeParams = function (_a) {
    var functionName = _a.functionName, params = _a.params;
    var validators = exports.paramsValidators;
    var validator = validators[functionName](params);
    if (!validator) {
        (0, misc_1.log)("This function ".concat(functionName, " is skipping params safe guarding."));
        return true;
    }
    return validator;
};
exports.safeParams = safeParams;
exports.paramsValidators = {
    executeJs: function (params) {
        // -- prepare params
        var code = params.code, ipfsId = params.ipfsId, authSig = params.authSig, jsParams = params.jsParams, debug = params.debug, sessionSigs = params.sessionSigs, _a = params.authMethods, authMethods = _a === void 0 ? [] : _a;
        // -- validate: either 'code' or 'ipfsId' must exists
        if (!code && !ipfsId) {
            var message = 'You must pass either code or ipfsId';
            (0, misc_1.throwError)({
                message: message,
                errorKind: constants_1.LIT_ERROR.PARAMS_MISSING_ERROR.kind,
                errorCode: constants_1.LIT_ERROR.PARAMS_MISSING_ERROR.name
            });
            return false;
        }
        // -- validate: 'code' and 'ipfsId' can't exists at the same time
        if (code && ipfsId) {
            var message = "You cannot have both 'code' and 'ipfs' at the same time";
            (0, misc_1.throwError)({
                message: message,
                errorKind: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_PARAM_TYPE.name
            });
            return false;
        }
        // -- validate: authSig and its type is correct
        if (authSig &&
            !(0, misc_1.checkType)({
                value: authSig,
                allowedTypes: ['Object'],
                paramName: 'authSig',
                functionName: 'executeJs'
            }))
            return false;
        // -- validate: sessionSigs and its type is correct
        if (sessionSigs && !(0, misc_1.is)(sessionSigs, 'Object', 'sessionSigs', 'executeJs'))
            return false;
        // -- validate: authMethods and its type is correct
        if (authMethods &&
            authMethods.length > 0 &&
            !(0, misc_1.checkType)({
                value: authMethods,
                allowedTypes: ['Array'],
                paramName: 'authMethods',
                functionName: 'executeJs'
            }))
            return false;
        // -- validate: if sessionSig or authSig exists
        if (!sessionSigs && !authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass either authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate: if sessionSig and authSig exists
        if (sessionSigs && authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass only one authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        return true;
    },
    saveEncryptionKey: function (params) {
        // -- prepare params
        var accessControlConditions = params.accessControlConditions, evmContractConditions = params.evmContractConditions, solRpcConditions = params.solRpcConditions, unifiedAccessControlConditions = params.unifiedAccessControlConditions, authSig = params.authSig, chain = params.chain, symmetricKey = params.symmetricKey, encryptedSymmetricKey = params.encryptedSymmetricKey, permanant = params.permanant, permanent = params.permanent, sessionSigs = params.sessionSigs;
        if (accessControlConditions &&
            !(0, misc_1.is)(accessControlConditions, 'Array', 'accessControlConditions', 'saveEncryptionKey'))
            return false;
        if (evmContractConditions &&
            !(0, misc_1.is)(evmContractConditions, 'Array', 'evmContractConditions', 'saveEncryptionKey'))
            return false;
        if (solRpcConditions &&
            !(0, misc_1.is)(solRpcConditions, 'Array', 'solRpcConditions', 'saveEncryptionKey'))
            return false;
        if (unifiedAccessControlConditions &&
            !(0, misc_1.is)(unifiedAccessControlConditions, 'Array', 'unifiedAccessControlConditions', 'saveEncryptionKey'))
            return false;
        // log('authSig:', authSig);
        if (authSig && !(0, misc_1.is)(authSig, 'Object', 'authSig', 'saveEncryptionKey'))
            return false;
        if (authSig &&
            !(0, misc_1.checkIfAuthSigRequiresChainParam)(authSig, chain, 'saveEncryptionKey'))
            return false;
        if (sessionSigs &&
            !(0, misc_1.is)(sessionSigs, 'Object', 'sessionSigs', 'saveEncryptionKey'))
            return false;
        if (!sessionSigs && !authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass either authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        if (symmetricKey &&
            !(0, misc_1.is)(symmetricKey, 'Uint8Array', 'symmetricKey', 'saveEncryptionKey'))
            return false;
        if (encryptedSymmetricKey &&
            !(0, misc_1.is)(encryptedSymmetricKey, 'Uint8Array', 'encryptedSymmetricKey', 'saveEncryptionKey'))
            return false;
        // to fix spelling mistake
        if (typeof params.permanant !== 'undefined') {
            params.permanent = params.permanant;
        }
        if ((!symmetricKey || symmetricKey == '') &&
            (!encryptedSymmetricKey || encryptedSymmetricKey == '')) {
            throw new Error('symmetricKey and encryptedSymmetricKey are blank.  You must pass one or the other');
        }
        if (!accessControlConditions &&
            !evmContractConditions &&
            !solRpcConditions &&
            !unifiedAccessControlConditions) {
            throw new Error('accessControlConditions and evmContractConditions and solRpcConditions and unifiedAccessControlConditions are blank');
        }
        // -- validate: if sessionSig and authSig exists
        if (sessionSigs && authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass only one authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        //   -- case: success
        return true;
    },
    getEncryptionKey: function (params) {
        var accessControlConditions = params.accessControlConditions, evmContractConditions = params.evmContractConditions, solRpcConditions = params.solRpcConditions, unifiedAccessControlConditions = params.unifiedAccessControlConditions, toDecrypt = params.toDecrypt, authSig = params.authSig, chain = params.chain, sessionSigs = params.sessionSigs;
        // -- validate
        if (accessControlConditions &&
            !(0, misc_1.is)(accessControlConditions, 'Array', 'accessControlConditions', 'getEncryptionKey'))
            return false;
        if (evmContractConditions &&
            !(0, misc_1.is)(evmContractConditions, 'Array', 'evmContractConditions', 'getEncryptionKey'))
            return false;
        if (solRpcConditions &&
            !(0, misc_1.is)(solRpcConditions, 'Array', 'solRpcConditions', 'getEncryptionKey'))
            return false;
        if (unifiedAccessControlConditions &&
            !(0, misc_1.is)(unifiedAccessControlConditions, 'Array', 'unifiedAccessControlConditions', 'getEncryptionKey'))
            return false;
        (0, misc_1.log)('TYPEOF toDecrypt in getEncryptionKey():', typeof toDecrypt);
        if (!(0, misc_1.is)(toDecrypt, 'String', 'toDecrypt', 'getEncryptionKey'))
            return false;
        if (authSig && !(0, misc_1.is)(authSig, 'Object', 'authSig', 'getEncryptionKey'))
            return false;
        if (sessionSigs &&
            !(0, misc_1.is)(sessionSigs, 'Object', 'sessionSigs', 'getEncryptionKey'))
            return false;
        // -- validate: if sessionSig or authSig exists
        if (!sessionSigs && !authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass either authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate: if sessionSig and authSig exists
        if (sessionSigs && authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass only one authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate if 'chain' is null
        if (!chain) {
            return false;
        }
        if (authSig &&
            !(0, misc_1.checkIfAuthSigRequiresChainParam)(authSig, chain, 'getEncryptionKey'))
            return false;
        return true;
    },
    decryptString: function (params) {
        var encryptedStringBlob = params[0];
        var symmKey = params[1];
        // -- validate
        if (!(0, misc_1.checkType)({
            value: encryptedStringBlob,
            allowedTypes: ['Blob', 'File'],
            paramName: 'encryptedStringBlob',
            functionName: 'decryptString'
        }))
            return false;
        if (!(0, misc_1.checkType)({
            value: symmKey,
            allowedTypes: ['Uint8Array'],
            paramName: 'symmKey',
            functionName: 'decryptString'
        }))
            return false;
        // -- success
        return true;
    },
    decryptFile: function (params) {
        // -- validate
        if (!(0, misc_1.checkType)({
            value: params.file,
            allowedTypes: ['Blob', 'File'],
            paramName: 'file',
            functionName: 'decryptFile'
        }))
            return false;
        // -- validate
        if (!(0, misc_1.checkType)({
            value: params.symmetricKey,
            allowedTypes: ['Uint8Array'],
            paramName: 'symmetricKey',
            functionName: 'decryptFile'
        }))
            return false;
        return true;
    },
    decryptZipFileWithMetadata: function (params) {
        // -- validate
        if (params.authSig &&
            !(0, misc_1.checkType)({
                value: params.authSig,
                allowedTypes: ['Object'],
                paramName: 'authSig',
                functionName: 'decryptZipFileWithMetadata'
            }))
            return false;
        // -- validate: sessionSigs and its type is correct
        if (params.sessionSigs &&
            !(0, misc_1.is)(params.sessionSigs, 'Object', 'sessionSigs', 'decryptZipFileWithMetadata'))
            return false;
        // -- validate: if sessionSig or authSig exists
        if (!params.sessionSigs && !params.authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass either authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate: if sessionSig and authSig exists
        if (params.sessionSigs && params.authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass only one authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate
        if (!(0, misc_1.checkType)({
            value: params.file,
            allowedTypes: ['Blob', 'File'],
            paramName: 'file',
            functionName: 'decryptZipFileWithMetadata'
        }))
            return false;
        // -- success case
        return true;
    },
    decryptZip: function (params) {
        var encryptedZipBlob = params.encryptedZipBlob, symmKey = params.symmKey;
        (0, misc_1.log)('encryptedZipBlob:', encryptedZipBlob);
        // -- validate
        if (!(0, misc_1.checkType)({
            value: encryptedZipBlob,
            allowedTypes: ['Blob', 'File'],
            paramName: 'encryptedZipBlob',
            functionName: 'decryptZip'
        }))
            return false;
        // -- validate
        if (!(0, misc_1.checkType)({
            value: symmKey,
            allowedTypes: ['Uint8Array'],
            paramName: 'symmKey',
            functionName: 'decryptZip'
        }))
            return false;
        return true;
    },
    encryptToIpfs: function (params) {
        // -- validate
        (0, misc_1.log)('params:', params);
        if (params.authSig &&
            !(0, misc_1.checkType)({
                value: params.authSig,
                allowedTypes: ['Object'],
                paramName: 'authSig',
                functionName: 'encryptToIpfs'
            }))
            return false;
        // -- validate
        if (params.accessControlConditions &&
            !(0, misc_1.checkType)({
                value: params.accessControlConditions,
                allowedTypes: ['Array'],
                paramName: 'accessControlConditions',
                functionName: 'encryptToIpfs'
            }))
            return false;
        // -- validate
        if (params.evmContractConditions &&
            !(0, misc_1.checkType)({
                value: params.evmContractConditions,
                allowedTypes: ['Array'],
                paramName: 'evmContractConditions',
                functionName: 'encryptToIpfs'
            }))
            return false;
        // -- validate
        if (params.solRpcConditions &&
            !(0, misc_1.checkType)({
                value: params.solRpcConditions,
                allowedTypes: ['Array'],
                paramName: 'solRpcConditions',
                functionName: 'encryptToIpfs'
            }))
            return false;
        // -- validate
        if (params.unifiedAccessControlConditions &&
            !(0, misc_1.checkType)({
                value: params.unifiedAccessControlConditions,
                allowedTypes: ['Array'],
                paramName: 'unifiedAccessControlConditions',
                functionName: 'encryptToIpfs'
            }))
            return false;
        // -- validate
        if (params.authSig &&
            !(0, misc_1.checkIfAuthSigRequiresChainParam)(params.authSig, params.chain, 'encryptToIpfs'))
            return false;
        // -- validate: sessionSigs and its type is correct
        if (params.sessionSigs &&
            !(0, misc_1.is)(params.sessionSigs, 'Object', 'sessionSigs', 'encryptToIpfs'))
            return false;
        // -- validate: if sessionSig or authSig exists
        if (!params.sessionSigs && !params.authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass either authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate: if sessionSig and authSig exists
        if (params.sessionSigs && params.authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass only one authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate
        if (params.string !== undefined &&
            !(0, misc_1.checkType)({
                value: params.string,
                allowedTypes: ['String'],
                paramName: 'string',
                functionName: 'encryptToIpfs'
            }))
            return false;
        // -- validate
        if (params.file !== undefined &&
            !(0, misc_1.checkType)({
                value: params.file,
                allowedTypes: ['Blob', 'File'],
                paramName: 'file',
                functionName: 'encryptToIpfs'
            }))
            return false;
        // -- success case
        return true;
    },
    decryptFromIpfs: function (params) {
        // -- validate
        (0, misc_1.log)('params:', params);
        if (params.authSig &&
            !(0, misc_1.checkType)({
                value: params.authSig,
                allowedTypes: ['Object'],
                paramName: 'authSig',
                functionName: 'decryptFromIpfs'
            }))
            return false;
        // -- validate: sessionSigs and its type is correct
        if (params.sessionSigs &&
            !(0, misc_1.is)(params.sessionSigs, 'Object', 'sessionSigs', 'decryptFromIpfs'))
            return false;
        // -- validate: if sessionSig or authSig exists
        if (!params.sessionSigs && !params.authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass either authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate: if sessionSig and authSig exists
        if (params.sessionSigs && params.authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass only one authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- success case
        return true;
    },
    encryptFileAndZipWithMetadata: function (params) {
        // -- validate
        (0, misc_1.log)('params:', params);
        if (params.authSig &&
            !(0, misc_1.checkType)({
                value: params.authSig,
                allowedTypes: ['Object'],
                paramName: 'authSig',
                functionName: 'encryptFileAndZipWithMetadata'
            }))
            return false;
        // -- validate
        if (params.accessControlConditions &&
            !(0, misc_1.checkType)({
                value: params.accessControlConditions,
                allowedTypes: ['Array'],
                paramName: 'accessControlConditions',
                functionName: 'encryptFileAndZipWithMetadata'
            }))
            return false;
        // -- validate
        if (params.evmContractConditions &&
            !(0, misc_1.checkType)({
                value: params.evmContractConditions,
                allowedTypes: ['Array'],
                paramName: 'evmContractConditions',
                functionName: 'encryptFileAndZipWithMetadata'
            }))
            return false;
        // -- validate
        if (params.solRpcConditions &&
            !(0, misc_1.checkType)({
                value: params.solRpcConditions,
                allowedTypes: ['Array'],
                paramName: 'solRpcConditions',
                functionName: 'encryptFileAndZipWithMetadata'
            }))
            return false;
        // -- validate
        if (params.unifiedAccessControlConditions &&
            !(0, misc_1.checkType)({
                value: params.unifiedAccessControlConditions,
                allowedTypes: ['Array'],
                paramName: 'unifiedAccessControlConditions',
                functionName: 'encryptFileAndZipWithMetadata'
            }))
            return false;
        // -- validate
        if (params.authSig &&
            !(0, misc_1.checkIfAuthSigRequiresChainParam)(params.authSig, params.chain, 'encryptFileAndZipWithMetadata'))
            return false;
        // -- validate: sessionSigs and its type is correct
        if (params.sessionSigs &&
            !(0, misc_1.is)(params.sessionSigs, 'Object', 'sessionSigs', 'encryptFileAndZipWithMetadata'))
            return false;
        // -- validate: if sessionSig or authSig exists
        if (!params.sessionSigs && !params.authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass either authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate: if sessionSig and authSig exists
        if (params.sessionSigs && params.authSig) {
            (0, misc_1.throwError)({
                message: 'You must pass only one authSig or sessionSigs',
                errorKind: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.kind,
                errorCode: constants_1.LIT_ERROR.INVALID_ARGUMENT_EXCEPTION.name
            });
            return false;
        }
        // -- validate
        if (!(0, misc_1.checkType)({
            value: params.file,
            allowedTypes: ['File'],
            paramName: 'file',
            functionName: 'encryptFileAndZipWithMetadata'
        }))
            return false;
        // -- validate
        if (params.readme &&
            !(0, misc_1.checkType)({
                value: params.readme,
                allowedTypes: ['String'],
                paramName: 'readme',
                functionName: 'encryptFileAndZipWithMetadata'
            }))
            return false;
        // -- success case
        return true;
    }
};
