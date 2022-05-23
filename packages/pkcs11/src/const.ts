// We have to use SHA-1 algorithm instead of SHA-2
// OS X security uses SHA-1 for SecKeyItem's ID generation (kSecAttrApplicationLabel | kSecAttrPublicKeyHash)
export const ID_DIGEST = "SHA-1";
