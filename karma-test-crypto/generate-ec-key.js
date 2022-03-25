
import {ZitiBrowzerCore} from "../dist/esm/index.js";



describe("generate-ec-key", function () {
  this.timeout(5000);

  beforeEach(async function () {
    this.zitiBrowzerCore = new ZitiBrowzerCore();
    this.logger = this.zitiBrowzerCore.createZitiLogger({
      logLevel: 'Debug',
    });

    this.logger.info(`beforeEach`);
  });

  it("generates an EC keypair", async function () {
    let zitiContext = this.zitiBrowzerCore.createZitiContext({
      logger: this.logger,
      controllerApi: 'bogus',
    });
    expect(zitiContext).to.not.equal(undefined);
    await zitiContext.initialize(); // this instantiates the OpenSSL WASM

    let privateKeyPEM = zitiContext.generateECKey({});
    this.logger.debug(privateKeyPEM);
    expect(privateKeyPEM).to.not.equal(undefined);
    expect(privateKeyPEM.startsWith('-----BEGIN PRIVATE KEY-----\n')).to.be.true;
    expect(privateKeyPEM.endsWith('-----END PRIVATE KEY-----\n')).to.be.true;

  });

});

