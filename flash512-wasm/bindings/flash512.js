/**
 * Flash512 WASM Bindings
 */

let wasmModule = null;

export async function initFlash512() {
    if (wasmModule) return wasmModule;
    
    try {
        // Load the WASM module
        const wasm = await import('../build/flash512.js');
        wasmModule = await wasm.default();
        return wasmModule;
    } catch (error) {
        console.error('Failed to load Flash512 WASM:', error);
        throw error;
    }
}

export async function deriveUserId(masterSecret) {
    const module = await initFlash512();
    const secretPtr = module._malloc(masterSecret.length + 1);
    module.stringToUTF8(masterSecret, secretPtr, masterSecret.length + 1);
    
    const resultPtr = module._derive_user_id(secretPtr, masterSecret.length);
    const result = module.UTF8ToString(resultPtr);
    
    module._free(secretPtr);
    module._free_string(resultPtr);
    
    return result;
}

export async function decryptChallenge(token, masterSecret) {
    const module = await initFlash512();
    
    const tokenPtr = module._malloc(token.length + 1);
    module.stringToUTF8(token, tokenPtr, token.length + 1);
    
    const secretPtr = module._malloc(masterSecret.length + 1);
    module.stringToUTF8(masterSecret, secretPtr, masterSecret.length + 1);
    
    const resultPtr = module._decrypt_challenge(
        tokenPtr, token.length,
        secretPtr, masterSecret.length
    );
    const result = module.UTF8ToString(resultPtr);
    
    module._free(tokenPtr);
    module._free(secretPtr);
    module._free_string(resultPtr);
    
    return result;
}

export async function encryptData(data, masterSecret) {
    const module = await initFlash512();
    
    const dataPtr = module._malloc(data.length + 1);
    module.stringToUTF8(data, dataPtr, data.length + 1);
    
    const secretPtr = module._malloc(masterSecret.length + 1);
    module.stringToUTF8(masterSecret, secretPtr, masterSecret.length + 1);
    
    const resultPtr = module._encrypt_data(
        dataPtr, data.length,
        secretPtr, masterSecret.length
    );
    const result = module.UTF8ToString(resultPtr);
    
    module._free(dataPtr);
    module._free(secretPtr);
    module._free_string(resultPtr);
    
    return result;
}

export default {
    initFlash512,
    deriveUserId,
    decryptChallenge,
    encryptData
};
