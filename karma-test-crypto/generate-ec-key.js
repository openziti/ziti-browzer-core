
import {ZitiBrowzerCore} from "../dist/esm/index.js";



describe("generate-ec-key", function () {
  this.timeout(5000);

  beforeEach(async function () {
    this.zitiBrowzerCore = new ZitiBrowzerCore();
  });

  it("generates an EC keypair", async function () {
    let zitiContext = this.zitiBrowzerCore.createZitiContext({});
    expect(zitiContext).to.not.equal(undefined);
    await zitiContext.initialize(); // this instantiates the OpenSSL WASM

    let privateKeyPEM = zitiContext.generateECKey({});
    // console.log(privateKeyPEM);
    expect(privateKeyPEM).to.not.equal(undefined);
    expect(privateKeyPEM.startsWith('-----BEGIN PRIVATE KEY-----\n')).to.be.true;
    expect(privateKeyPEM.endsWith('-----END PRIVATE KEY-----\n')).to.be.true;

  });

});

