securityIgnoreProperties: getEnvArray("SECURITY_IGNORE_PROPERTIES") || [],
aesKeyBase64: getEnv("AES256_KEY_BASE64"),
aesIVBase64: getEnv("AES256_IV_BASE64"),


describe("getAlgorithmAES256CBC", () => {
  test("should return aes-128-cbc", () => {
    const key = Buffer.from("1234567890123456").toString("base64");

    expect(helper.getAlgorithmAES256CBC(key)).toBe("aes-128-cbc");
  });

  test("should return aes-256-cbc", () => {
    const key = Buffer.from("12345678901234567890123456789012").toString("base64");

    expect(helper.getAlgorithmAES256CBC(key)).toBe("aes-256-cbc");
  });
});



const key = Buffer.from(keyBase64, "base64");

switch (key.length) {
  case 16:
    return "aes-128-cbc";
  case 32:
    return "aes-256-cbc";
}
