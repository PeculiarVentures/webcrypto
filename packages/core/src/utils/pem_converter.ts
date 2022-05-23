import { BufferSource, Convert } from "pvtsutils";

/**
 * PEM converter
 */
export class PemConverter {

  /**
   * Converts PEM to Array buffer
   * @param pem PEM string
   */
  public static toArrayBuffer(pem: string) {
    const base64 = pem
      .replace(/-{5}(BEGIN|END) .*-{5}/g, "")
      .replace("\r", "")
      .replace("\n", "");
    return Convert.FromBase64(base64);
  }

  /**
   * Converts PEM to Uint8Array
   * @param pem PEM string
   */
  public static toUint8Array(pem: string) {
    const bytes = this.toArrayBuffer(pem);
    return new Uint8Array(bytes);
  }

  /**
   * Converts buffer source to PEM
   * @param buffer Buffer source
   * @param tag PEM tag name
   */
  public static fromBufferSource(buffer: BufferSource, tag: string) {
    const base64 = Convert.ToBase64(buffer);
    let sliced: string;
    let offset = 0;
    const rows: string[] = [];
    while (true) {
      sliced = base64.slice(offset, offset = offset + 64);
      if (sliced.length) {
        rows.push(sliced);
        if (sliced.length < 64) {
          break;
        }
      } else {
        break;
      }
    }

    const upperCaseTag = tag.toUpperCase();
    return `-----BEGIN ${upperCaseTag}-----\n${rows.join("\n")}\n-----END ${upperCaseTag}-----`;
  }

  /**
   * Returns `true` if incoming data is PEM string, otherwise `false`
   * @param data Data
   */
  public static isPEM(data: string) {
    // tslint:disable-next-line:max-line-length
    return /-----BEGIN .+-----[A-Za-z0-9+\/\+\=\s\n]+-----END .+-----/i.test(data);
  }

  /**
   * Returns tag name from PEM string
   * @param pem PEM string
   */
  public static getTagName(pem: string) {
    if (!this.isPEM(pem)) {
      throw new Error("Bad parameter. Incoming data is not right PEM");
    }
    const res = /-----BEGIN (.+)-----/.exec(pem);
    if (!res) {
      throw new Error("Cannot get tag from PEM");
    }

    return res[1];
  }

  /**
   * Returns `true` if tag name from PEM matches to tagName parameter
   * @param pem PEM string
   * @param tagName Tag name for comparison
   */
  public static hasTagName(pem: string, tagName: string) {
    const tag = this.getTagName(pem);
    return tagName.toLowerCase() === tag.toLowerCase();
  }

  public static isCertificate(pem: string) {
    return this.hasTagName(pem, "certificate");
  }

  public static isCertificateRequest(pem: string) {
    return this.hasTagName(pem, "certificate request");
  }

  public static isCRL(pem: string) {
    return this.hasTagName(pem, "x509 crl");
  }

  public static isPublicKey(pem: string) {
    return this.hasTagName(pem, "public key");
  }

}
