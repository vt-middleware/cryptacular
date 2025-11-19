@org.springframework.stereotype.Service
public class PasswordHashService() {
  @Inject
  private HashBean<String> hashBean;

  public String hash(String password, byte[] salt) {
    // Hash beans handle conversion of objects to bytes for common input types
    // See HashUtil#hash() JavaDocs for more information
    return hashBean.hash(password, salt);
  }
}
