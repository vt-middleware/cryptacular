// Compute the SHA-1 hash of a string
byte[] sha1Bytes = HashUtil.sha1("Codito ergo sum");

// Compute the hex-encoded SHA-256 hash of a string
String sha256Hex = CodecUtil.hex(HashUtil.sha256("Ecce homo"));

// Note that HashUtil handles several input types directly:
// - CharSequence (converts to UTF-8 bytes)
// - InputStream (reads stream as bytes)
// - Resource (reads contents as bytes)
// Thus the usage for hashing a stream is the same as a string
byte[] sha256Bytes = HashUtil.sha256(new FileInputStream("/path/to/data"));
