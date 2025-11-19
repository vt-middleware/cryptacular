// Define the underlying AES cipher used for encryption/decryption
BlockCipher block = org.bouncycastle.crypto.engines.AESEngine.newInstance();

// Wrap the underlying AES block cipher in a GCM mode cipher
AEADBlockCipher cipher = org.bouncycastle.crypto.modes.GCMBlockCipher.newInstance(block);

// We generate a new 128-bit AES key here, but one could be loaded from a
// Keystore or other secure storage
SecretKey key = SecretKeyGenerator.generate(128, block);

// Take care to use a suitable Nonce class for the chosen cipher mode
// org.cryptacular.generator.sp80038d.RBGNonce - AEAD-mode ciphers
// org.cryptacular.generator.sp80038a.RBGNonce - block mode (e.g. CBC) ciphers
Nonce nonce = new org.cryptacular.generator.sp80038d.RBGNonce();

//============
// Encryption
//============
// Create input stream around the original plaintext input to encrypt
InputStream inPlain = new FileInputStream("/path/to/plain.txt");

// Create output stream to the file that will hold base64-encoded ciphertext
OutputStream outCipher = new EncodingOutputStream(
  new FileOutputStream("/path/to/cipher.b64"),
  new Base64Encoder(72)); // Line breaks at 72 chars per line

// Perform encryption
CipherUtil.encrypt(cipher, key, nonce, inPlain, outCipher);

//============
// Decryption
//============
// Create input stream around ciphertext input
// Note we have to handle base64 decoding
InputStream inCipher = new DecodingInputStream(
  new FileInputStream("/path/to/cipher.b64"),
  new Base64Decoder());

// Create output stream to hold decrypted plaintext
OutputStream outPlain = new FileOutputStream("/path/to/plain2.txt");

// Perform decryption
CipherUtil.decrypt(cipher, key, inCipher, outPlain);
