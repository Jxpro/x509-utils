import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import java.util.Base64;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

/**
 * Java代码生成自颁发 cer证书、base64 cer证书文件
 *
 */
public class example1_genCer {

	private final String path = "./";

	private static final String CTFC_DOMAIN_NAME = "domainName";            //CN：用户姓名或域名
	private static final String CTFC_ORG_UNIT_NAME = "orgUnitName";       //OU：组织单位名称
	private static final String CTFC_ORG_NAME = "orgName";                //O：组织名称
	private static final String CTFC_COUNTRY_CODE = "countryCode";        //C：单位的两字母国家代码
	private static final String CTFC_CITY = "city";                       //L：城市或区域
	private static final String CTFC_PROVINCE = "province";               //ST：省份或州

	private static final String CTFC_VALID_START_TIME = "validStartTime"; //证书有效起始时间
	private static final String CTFC_VALID_END_TIME = "validEndTime";     //证书有效截止时间
	private static final String CTFC_SERIAL_NUMBER = "serialNumber";      //序列号域
	private static final String CTFC_SIG_AlG = "signatureAlgorithm";      //签名算法
	private static final String CTFC_ENCRYPT_TYPE = "encryptType";        //加密类型
	private static final String CTFC_ENCRYPT_NUM = "encryptNum";        //加密位数
	private static final String CTFC_PROVIDER = "provider";                //提供人

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 生成cer证书
	 *
	 * @param infoMap      证书信息
	 * @param keyPair_root 证书密钥对
	 * @param keyPair_user 用户密钥对
	 * @return 证书生成结果
	 */
	public X509Certificate generateCert(HashMap<String, Object> infoMap, KeyPair keyPair_root, KeyPair keyPair_user)
			throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X509Certificate cert;
		certGen.setSerialNumber((BigInteger) infoMap.get(CTFC_SERIAL_NUMBER));

		//证书颁发者，这里自颁发，颁发者和使用者一致，可以只是用户或域名，也可以是部分或完整的用户信息（OU：组织单位名称、O：组织单位、C：单位的两字母国家代码、L：城市或区域、ST：省份或州）
		certGen.setIssuerDN(new X509Name("CN=" + infoMap.get(CTFC_DOMAIN_NAME)));
		certGen.setNotBefore((Date) infoMap.get(CTFC_VALID_START_TIME));
		certGen.setNotAfter((Date) infoMap.get(CTFC_VALID_END_TIME));

		//证书使用者，这里自颁发，使用者和颁发者一致，可以只是用户或域名，也可以是完整的用户信息（组织单位名称、组织单位、国家代码、城市或区域、省份或州）
		certGen.setSubjectDN(new X509Name("CN=" + infoMap.get(CTFC_DOMAIN_NAME)));
		certGen.setPublicKey(keyPair_user.getPublic());
		certGen.setSignatureAlgorithm((String) infoMap.get(CTFC_SIG_AlG));
		cert = certGen.generateX509Certificate(keyPair_root.getPrivate(), (String) infoMap.get(CTFC_PROVIDER)); //BC：证书提供人
		return cert;
	}

	/**
	 * 生成密钥对
	 *
	 * @param infoMap 生成cer证书需要的参数
	 * @param seed    种子
	 * @return 密钥对
	 */
	public KeyPair generateKeyPair(HashMap<String, Object> infoMap, int seed) throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance((String) infoMap.get(CTFC_ENCRYPT_TYPE));
		kpg.initialize((int) infoMap.get(CTFC_ENCRYPT_NUM), new SecureRandom(new byte[seed]));
		return kpg.generateKeyPair();
	}

	/**
	 * 生成原格式 cer证书
	 *
	 * @param infoMap 生成cer证书需要的参数
	 * @return cer证书生成结果
	 */
	public boolean createCerFile(HashMap<String, Object> infoMap) {
		try {
			KeyPair keyPair_root = generateKeyPair(infoMap, 10);
			KeyPair keyPair_user = generateKeyPair(infoMap, 10);

			X509Certificate cert = generateCert(infoMap, keyPair_root, keyPair_user);
			System.out.println(cert.toString());
			String cerString = Base64.getEncoder().encodeToString(cert.getEncoded());
			System.out.println(cerString);

			//生成cer证书文件
			String certPath = path + infoMap.get(CTFC_DOMAIN_NAME) + ".cer";
			FileOutputStream fos = new FileOutputStream(certPath);
			fos.write(cert.getEncoded()); //证书可以二进制形式存入库表，存储字段类型为BLOB
			fos.close();
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("createPublicKey error：" + e.getMessage());
			return false;
		}
	}

	/**
	 * 生成base64格式 cer证书
	 *
	 * @param infoMap 生成cer证书需要的参数
	 * @return cer证书（base64）生成结果
	 */
	public boolean createBase64CerFileByDecode(HashMap<String, Object> infoMap) {
		try {
			KeyPair keyPair_root = generateKeyPair(infoMap, 10);
			KeyPair keyPair_user = generateKeyPair(infoMap, 10);
			X509Certificate cert = generateCert(infoMap, keyPair_root, keyPair_user);
			String certPath = path + infoMap.get(CTFC_DOMAIN_NAME) + "_base64.cer";

			String encode = Base64.getEncoder().encodeToString(cert.getEncoded());
			String base64EncodeCer = "-----BEGIN CERTIFICATE-----\r\n" + encode + "\r\n-----END CERTIFICATE-----\r\n";
			System.out.println(base64EncodeCer);

			//生成base64 cer证书文件
			FileWriter wr = new java.io.FileWriter(certPath);
			wr.write(base64EncodeCer);
			wr.flush();
			wr.close();
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("createPublicKeyByDecode error：" + e.getMessage());
			return false;
		}
	}

	public static void main(String[] args) {
		example1_genCer dataCertCreate = new example1_genCer();
		Date validStartTime = new Date();
		Date validEndTime = new Date(validStartTime.getTime() + 10 * 365L * 24L * 60L * 60L * 1000L);
		BigInteger serialNumber = new BigInteger(String.valueOf(validStartTime.getTime() / 1000L));

		//构建生成证书请求参数
		HashMap<String, Object> infoMap = new HashMap<String, Object>();
		infoMap.put(CTFC_DOMAIN_NAME, "www.justinqin.com");        //CN：用户姓名或域名
		infoMap.put(CTFC_ORG_UNIT_NAME, "orgUnitName");         //OU：组织单位名称
		infoMap.put(CTFC_ORG_NAME, "orgName");                //O：组织名称
		infoMap.put(CTFC_COUNTRY_CODE, "CN");                //C：单位的两字母国家代码
		infoMap.put(CTFC_CITY, "深圳市");                        //L：城市或区域
		infoMap.put(CTFC_PROVINCE, "广东省");                    //ST：省份或州

		infoMap.put(CTFC_VALID_START_TIME, validStartTime);    //证书有效起始时间
		infoMap.put(CTFC_VALID_END_TIME, validEndTime);        //证书有效截止时间
		infoMap.put(CTFC_SERIAL_NUMBER, serialNumber);        //序列号域
		infoMap.put(CTFC_SIG_AlG, "SHA256withRSA");            //签名算法
		infoMap.put(CTFC_ENCRYPT_TYPE, "RSA");                //加密类型
		infoMap.put(CTFC_ENCRYPT_NUM, 2048);                    //加密位数
		infoMap.put(CTFC_PROVIDER, "BC");                        //提供人

		// 生成公钥
		boolean createCerFileRs = dataCertCreate.createCerFile(infoMap);
		System.out.println("createCerFile, result==" + createCerFileRs);

		boolean createBase64CerFileByDecodeRs = dataCertCreate.createBase64CerFileByDecode(infoMap);
		System.out.println("createBase64CerFileByDecode, result==" + createBase64CerFileByDecodeRs);
	}
}