@org.springframework.stereotype.Service
public class EncryptionService() {
  @Inject
  private CipherBean cipherBean;

  private final Encoder encoder = new Base64Encoder(72);

  private final Decoder decoder = new Base64Decoder();

  public String encrypt(String plainText) {
    return CodecUtil.encode(encoder, cipherBean.encrypt(ByteUtil.toBytes(plainText)));
  }

  public String decrypt(String cipherText) {
    return ByteUtil.toString(cipherBean.decrypt(CodecUtil.decode(decoder, cipherText)));
  }
}
