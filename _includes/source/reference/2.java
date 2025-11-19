// Compute a salted SHA-1 hash of an input string and compare it to a value of
// record stored as a base64-encoded string stored in "authoritativeHashString".
// The stored value is thus base64(A+B), where A is the salted SHA-1 hash bytes
// and B is the salt bytes. LDAP directories store password hashes this way.

// Create a SaltedHash object to store the value to compare against
SaltedHash authoritativeHash = new SaltedHash(
  CodecUtil.b64(authoritativeHashString), // String to bytes
  20, // SHA-1 hashes are 160 bits/20 bytes long,
  true); // Salt is appended to the end of the hash bytes

// Perform the hash comparison
boolean areEqual = HashUtil.compareHash(
  new org.bouncycastle.crypto.digests.SHA1Digest(),
  authoritativeHash,
  1, // One hashing round,
  true, // Salt is appended to the end of the hash bytes
  "Th3P@ssw0rd"); // Input string to hash and compare
