import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;

public class ObjectDN {
	// 姓名/域名/IP地址
	private String commonName;
	// 组织/公司
	private String organization;
	// 组织单位名称/部门名称
	private String organizationalUnit;
	// 国家
	private String countryName;
	// 省份
	private String provinceName;

	// 额外信息（邮箱，营业执照）
	private final ArrayList<GeneralName> subjectAlternativeNames = new ArrayList<>();

	public void setCommonName(String commonName) {
		this.commonName = commonName;
	}

	public void setOrganization(String organization) {
		this.organization = organization;
	}

	public void setOrganizationalUnit(String organizationalUnit) {
		this.organizationalUnit = organizationalUnit;
	}

	public void setCountryName(String countryName) {
		this.countryName = countryName;
	}

	public void setProvinceName(String provinceName) {
		this.provinceName = provinceName;
	}

	public void setEmail(String email) {
		subjectAlternativeNames.add(new GeneralName(GeneralName.rfc822Name, email));
	}

	public void setLicenseUrl(String licenseUrl) {
		subjectAlternativeNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, licenseUrl));
	}

	public GeneralNames getSubjectAlternativeNames() {
		return new GeneralNames(subjectAlternativeNames.toArray(new GeneralName[0]));
	}

	public X500Name getX500Name() {
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		if (commonName != null) {
			builder.addRDN(BCStyle.CN, commonName);
		}
		if (organization != null) {
			builder.addRDN(BCStyle.O, organization);
		}
		if (organizationalUnit != null) {
			builder.addRDN(BCStyle.OU, organizationalUnit);
		}
		if (countryName != null) {
			builder.addRDN(BCStyle.C, countryName);
		}
		if (provinceName != null) {
			builder.addRDN(BCStyle.ST, provinceName);
		}
		return builder.build();
	}

	public X500Principal getX500Principal() {
		return new X500Principal(getX500Name().toString());
	}
}